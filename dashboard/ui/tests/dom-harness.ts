// Test-only DOM harness: a real DOM (jsdom) plus a controlled clock, so the
// render/tick behaviour can be asserted without a browser and without waiting
// on wall-clock time. Not shipped: `tsconfig.json` excludes `ui/tests/**`, so
// nothing here reaches `ui/dist` or the packaged app.
import { JSDOM } from "jsdom";
import type { DOMWindow } from "jsdom";

/** One broker reply: a value to resolve with, or `fail({code,message})`. */
export type Responder = (cmd: string, args?: unknown) => unknown;

/** A rejected broker call, shaped exactly like `CmdError` across IPC. */
export function fail(code: string, message: string): never {
  const err = { code, message };
  throw err;
}

interface FakeTimer {
  id: number;
  fn: () => void;
  ms: number;
  next: number;
  interval: boolean;
}

export interface DomEnv {
  win: DOMWindow;
  doc: Document;
  /** Commands the app invoked, in order. */
  calls: string[];
  /** Run every timer due within `ms` of fake time, then move the clock. */
  advance(ms: number): void;
  /** Drain the app's promise chains. */
  settle(): Promise<void>;
  /** A pointer/keyboard-ish interaction: an `input` event carrying a value. */
  typeInput(el: HTMLInputElement, value: string): void;
  click(el: Element): void;
  teardown(): void;
}

const FINGERPRINT = "ab".repeat(32);

/** Monotonic cache-bust token: a fresh app module instance per test. */
let caseSeq = 0;

/** Posture payload the app reads first: trusted, pinned, vault unlocked. */
export const trustedUnlocked = {
  get_status: () => ({
    version: 1,
    created: "2026-01-01 00:00:00.000000000 +00:00:00",
    locked: false,
    online: true,
    trusted: true,
    initialized: true,
    fingerprint: FINGERPRINT,
  }),
  pin_status: () => ({ pinned: true, fingerprint: FINGERPRINT }),
  probe_fingerprint: () => ({ fingerprint: FINGERPRINT }),
  health: () => ({
    locked: false,
    idle_lock_secs: 900,
    idle_in: 800,
    audit_bytes: 1024,
    audit_soft_limit: 14680064,
    audit_hard_limit: 16777216,
    vault_bytes: 512,
    vault_max_bytes: 16777216,
    runs_active: 0,
    leases_active: 0,
    approvals_pending: 0,
  }),
  overview_refresh: () => ({
    online: true,
    trusted: true,
    locked: false,
    session_held: true,
    version: 1,
    created: "2026-01-01 00:00:00.000000000 +00:00:00",
    projects: 1,
    secrets_total: 1,
    secrets_total_exact: true,
    agents_active: 0,
    runs_active: 0,
    approvals_pending: 0,
    leases_active: 0,
    idle_lock_secs: 900,
    idle_in: 800,
    audit_bytes: 1024,
    audit_soft_limit: 14680064,
    audit_hard_limit: 16777216,
    vault_bytes: 512,
    vault_max_bytes: 16777216,
  }),
  projects_list: () => ({ projects: [{ name: "acme", paths: ["/tmp/work"] }] }),
  secrets_list: () => ({ secrets: [] }),
  agents_list: () => ({ agents: [] }),
  grants_list: () => ({ grants: [] }),
  approvals_pending: () => ({ approvals: [] }),
  leases_list: () => ({ leases: [] }),
  runs_list: () => ({ runs: [] }),
  audit_show: () => ({ entries: [], next_before_seq: null }),
  audit_verify: () => ({ entries: 0, macs_verified: 0, macs_null: 0 }),
} as const;

/**
 * Boot the real app module against a jsdom document and the given responder.
 * Every call imports a fresh copy of the module (cache-busted), so module-level
 * app state never leaks between tests.
 */
export async function makeEnv(
  respond: Responder,
  opts: { hash?: string; html?: string } = {},
): Promise<DomEnv> {
  const dom = new JSDOM(opts.html ?? '<!doctype html><html><body><div id="app"></div></body></html>', {
    url: `http://localhost/${opts.hash ?? ""}`,
    pretendToBeVisual: true,
  });
  const win = dom.window;
  const doc = win.document;
  const calls: string[] = [];

  // ---- controlled clock -----------------------------------------------------
  const timers = new Map<number, FakeTimer>();
  let nextId = 1;
  let fakeNow = 0;
  const epochBase = 1_700_000_000_000;
  win.setInterval = ((fn: () => void, ms?: number): number => {
    const id = nextId++;
    timers.set(id, { id, fn, ms: ms ?? 0, next: fakeNow + (ms ?? 0), interval: true });
    return id;
  }) as typeof win.setInterval;
  win.setTimeout = ((fn: () => void, ms?: number): number => {
    const id = nextId++;
    timers.set(id, { id, fn, ms: ms ?? 0, next: fakeNow + (ms ?? 0), interval: false });
    return id;
  }) as typeof win.setTimeout;
  win.clearInterval = ((id: number): void => {
    timers.delete(id);
  }) as typeof win.clearInterval;
  win.clearTimeout = win.clearInterval as typeof win.clearTimeout;
  const realDateNow = Date.now;
  Date.now = () => epochBase + fakeNow;

  // ---- bridge --------------------------------------------------------------
  Object.defineProperty(win, "__TAURI_INTERNALS__", {
    configurable: true,
    value: {
      invoke: (cmd: string, args?: unknown) => {
        calls.push(cmd);
        try {
          return Promise.resolve(respond(cmd, args));
        } catch (e) {
          return Promise.reject(e);
        }
      },
      transformCallback: (cb: unknown) => cb,
      unregisterCallback: () => undefined,
      convertFileSrc: (p: string) => p,
    },
  });

  const saved = {
    window: Object.getOwnPropertyDescriptor(globalThis, "window"),
    document: Object.getOwnPropertyDescriptor(globalThis, "document"),
  };
  Object.defineProperty(globalThis, "window", { configurable: true, writable: true, value: win });
  Object.defineProperty(globalThis, "document", { configurable: true, writable: true, value: doc });
  // The app branches on `instanceof HTMLElement` / `HTMLInputElement` / … and
  // jsdom's classes only exist on its own window, so publish the constructors
  // as globals for the duration of the test (removed in teardown).
  const domClasses = [
    "Node",
    "Element",
    "HTMLElement",
    "HTMLInputElement",
    "HTMLTextAreaElement",
    "HTMLSelectElement",
    "HTMLButtonElement",
    "HTMLAnchorElement",
    "HTMLFormElement",
    "HTMLOptionElement",
    "Event",
    "CustomEvent",
    "MouseEvent",
    "KeyboardEvent",
    "FocusEvent",
    "MutationObserver",
    "NodeList",
  ] as const;
  const savedClasses = new Map<string, PropertyDescriptor | undefined>();
  for (const name of domClasses) {
    const value = (win as unknown as Record<string, unknown>)[name];
    if (value === undefined) continue;
    savedClasses.set(name, Object.getOwnPropertyDescriptor(globalThis, name));
    Object.defineProperty(globalThis, name, { configurable: true, writable: true, value });
  }

  // A static import cannot work here: the app module boots on import and keeps
  // module-level state, so every test needs its own freshly evaluated instance.
  // The query string cache-busts Node's ESM registry (the documented exception
  // for tests that exercise module-loading boundaries).
  await import(`../app.js?case=${++caseSeq}`);

  const settle = async (): Promise<void> => {
    for (let i = 0; i < 12; i += 1) await Promise.resolve();
    await new Promise<void>((r) => setImmediate(r));
  };
  await settle();

  const advance = (ms: number): void => {
    const target = fakeNow + ms;
    for (;;) {
      let due: FakeTimer | null = null;
      for (const t of timers.values()) {
        if (t.next <= target && (due === null || t.next < due.next)) due = t;
      }
      if (due === null) break;
      fakeNow = due.next;
      if (due.interval) due.next = fakeNow + due.ms;
      else timers.delete(due.id);
      due.fn();
    }
    fakeNow = target;
  };

  return {
    win,
    doc,
    calls,
    advance,
    settle,
    typeInput(el, value) {
      el.focus();
      el.value = value;
      el.dispatchEvent(new win.Event("input", { bubbles: true }));
    },
    click(el) {
      el.dispatchEvent(new win.MouseEvent("click", { bubbles: true, cancelable: true }));
    },
    teardown() {
      Date.now = realDateNow;
      dom.window.close();
      for (const [name, descriptor] of savedClasses) {
        if (descriptor === undefined) delete (globalThis as Record<string, unknown>)[name];
        else Object.defineProperty(globalThis, name, descriptor);
      }
      if (saved.window === undefined) delete (globalThis as Record<string, unknown>).window;
      else Object.defineProperty(globalThis, "window", saved.window);
      if (saved.document === undefined) delete (globalThis as Record<string, unknown>).document;
      else Object.defineProperty(globalThis, "document", saved.document);
    },
  };
}

/** The button whose trimmed text matches `label`, or null. */
export function buttonByText(env: DomEnv, label: string): Element | null {
  return Array.from(env.doc.querySelectorAll("button")).find((b) => (b.textContent ?? "").trim() === label) ?? null;
}

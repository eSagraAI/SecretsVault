// Reveal: the ONE place a secret value is ever shown.
//
// Value discipline (security-critical):
// - The value lives ONLY in this module's `live` slot — never in
//   ShellState, never in any slice, never in storage, never in the URL/hash,
//   never logged, never in an error message. `takeRevealValue` is the pure,
//   testable twin (mirrors `takeSecretSubmit`/`takeOneTimeToken`).
// - Hidden by default: the modal shows project/key names only until the
//   human explicitly reveals it (the owner's direct reveal - no approval).
// - Auto-hides 15 000 ms after the reveal, with a visible countdown.
// - `Hide now` clears immediately; close/lock/route-change/expiry clear too.
// - Clearing drops the DOM node and the JS reference. Honestly: this does
//   NOT guarantee heap zeroization — the string may persist in memory until
//   GC, and a compromised renderer could have copied it. The broker is the
//   security boundary; this is a usability-minded minimization, not a
//   security guarantee.
//
// Clipboard policy:
// - Never copies automatically (no copy on reveal/focus/select).
// - An explicit `Copy` button only, with a visible warning: the clipboard
//   is a shared, persistent channel — other apps, clipboard managers and
//   the X11/Wayland clipboard can retain the value, and clearing is
//   best-effort only.
// - `navigator.clipboard.writeText` from JS (the value is already in JS by
//   necessity — it is being rendered). Unavailable API ⇒ plain failure text,
//   never a throw. Best-effort clear after 30 000 ms, and on hide/close/lock.
// - A Rust-only clipboard path was evaluated and rejected for D4: it would
//   not reduce exposure (the value must already be in JS to be displayed),
//   and would add an external binary dependency or a new Tauri plugin.

import { banner, button, el, fieldRow, iconTextButton, para, trapFocus } from "../components.js";
import type { RevealResult } from "../state.js";

/** Auto-hide delay after the human reveals the value. Pinned in tests. */
export const REVEAL_AUTO_HIDE_MS = 15_000;
/** Best-effort clipboard clear delay after an explicit copy. */
export const REVEAL_CLIPBOARD_CLEAR_MS = 30_000;

/**
 * Pure, DOM-free twin of the human reveal path, for tests: hand the `reveal`
 * result over for display (`shown`) and explicitly NOTHING to persist
 * (`persisted` is always null — there is no other output to stash in state).
 */
export function takeRevealValue(res: RevealResult): { shown: string; persisted: null } {
  if (!res || typeof res.value !== "string" || res.value.length === 0) {
    throw new Error("reveal result carries no value");
  }
  return { shown: res.value, persisted: null };
}

/**
 * Pure hide decision, for tests: just-revealed or inside the 15 s window ⇒
 * visible; past it, never-revealed, or dismissed ⇒ hidden. No timers, no DOM.
 */
export function revealVisible(shownAtMs: number | null, nowMs: number, dismissed: boolean): boolean {
  if (dismissed || shownAtMs === null) return false;
  return nowMs - shownAtMs < REVEAL_AUTO_HIDE_MS;
}

/** What may place the value on the clipboard. Only an explicit press. */
export type RevealCopyTrigger = "reveal" | "explicit";

/**
 * Pure clipboard policy, for tests: a fresh reveal never schedules an
 * automatic copy; only the explicit Copy button does.
 */
export function revealClipboardCopy(trigger: RevealCopyTrigger): boolean {
  return trigger === "explicit";
}

/** Wiring the app injects when opening the modal. The value never flows back through here. */
export interface RevealHooks {
  /** Ask the app to reveal the value for (project, key) via the owner's direct
   *  human reveal; the app answers via deliverRevealedValue / revealFailed.
   *  Never an agent approval claim. */
  onShow: (project: string, key: string) => void;
}

interface RevealLive {
  project: string;
  key: string;
  /** The only stored copy of the value; null while masked. */
  value: string | null;
  shownAtMs: number | null;
  busy: boolean;
  error: string | null;
  copied: boolean;
  copyNote: string | null;
}

let live: RevealLive | null = null;
let hooks: RevealHooks | null = null;
let overlay: HTMLElement | null = null;
let countdownEl: HTMLElement | null = null;
let hideTimer: number | null = null;
let tickTimer: number | null = null;
let clipboardTimer: number | null = null;
let untrap: (() => void) | null = null;
/** Whether the system clipboard may currently hold a copied value. */
let clipboardHoldsCopy = false;

/** Open the masked modal for one key. Drops any previous value first. Never auto-reveals. */
export function openRevealModal(project: string, key: string, h: RevealHooks): void {
  if (typeof document === "undefined") return;
  if (untrap !== null) {
    untrap();
    untrap = null;
  }
  teardownTimers();
  if (overlay !== null) overlay.remove();
  countdownEl = null;
  live = { project, key, value: null, shownAtMs: null, busy: false, error: null, copied: false, copyNote: null };
  hooks = h;
  const ov = el("div", { class: "reveal-overlay" });
  overlay = ov;
  document.body.append(ov);
  // Trap before the first paint so restore-on-close returns to the element
  // that opened the modal (paint moves focus inside, which would otherwise
  // become the "previous" element).
  untrap = trapFocus(ov, { onEscape: () => closeReveal() });
  paint();
}

/** Deliver a revealed value into the modal. Ignored unless the modal waits for exactly (project, key). */
export function deliverRevealedValue(project: string, key: string, value: string): void {
  const cur = live;
  if (cur === null || cur.project !== project || cur.key !== key) return;
  cur.value = value;
  cur.shownAtMs = Date.now();
  cur.busy = false;
  cur.error = null;
  armHideTimer();
  paint();
}

/** Report a failed reveal inside the modal. Never carries the value. */
export function revealFailed(project: string, key: string, message: string): void {
  const cur = live;
  if (cur === null || cur.project !== project || cur.key !== key) return;
  cur.busy = false;
  cur.error = message;
  paint();
}

/** Clear the value now but keep the masked modal open (Hide now / auto-hide). */
export function hideRevealValue(): void {
  const cur = live;
  if (cur === null) return;
  cur.value = null;
  cur.shownAtMs = null;
  cur.busy = false;
  cur.copied = false;
  cur.copyNote = null;
  teardownTimers();
  bestEffortClipboardClear();
  paint();
}

/** Full teardown: value, timers, overlay. Idempotent. */
export function closeReveal(): void {
  if (untrap !== null) {
    untrap();
    untrap = null;
  }
  teardownTimers();
  bestEffortClipboardClear();
  live = null;
  hooks = null;
  countdownEl = null;
  if (overlay !== null) {
    overlay.remove();
    overlay = null;
  }
}

/**
 * Lock/expiry/route-change wipe, called from the app's single choke point.
 * Same full teardown as closing — the value must not survive these.
 */
export function clearReveal(): void {
  closeReveal();
}

function countdownLabel(shownAtMs: number): string {
  const remaining = shownAtMs + REVEAL_AUTO_HIDE_MS - Date.now();
  if (remaining <= 0) return "Hiding…";
  return `Auto-hides in ${Math.ceil(remaining / 1000)}s.`;
}

function paint(): void {
  const cur = live;
  const host = overlay;
  if (cur === null || host === null || typeof document === "undefined") return;
  host.replaceChildren();
  const box = el("section", {
    class: "reveal-modal",
    role: "dialog",
    "aria-modal": "true",
    "aria-label": "Reveal secret",
  });
  box.append(el("h2", {}, "Reveal secret"));
  box.append(fieldRow("Project", cur.project));
  box.append(fieldRow("Key", cur.key));
  if (cur.error !== null) box.append(banner("warn", cur.error));
  if (cur.value !== null && cur.shownAtMs !== null) {
    box.append(banner("warn", "Sensitive value shown — it hides automatically and is not persisted by this app."));
    // A <pre>, never an <input>: the value must stay a clearly temporary
    // display, never a persistent normal text field.
    box.append(el("pre", { class: "reveal-value" }, cur.value));
    countdownEl = el("p", { class: "reveal-countdown" }, countdownLabel(cur.shownAtMs));
    box.append(countdownEl);
    const row = el("div", { class: "row" });
    row.append(
      button("Hide now", { variant: "primary", onClick: () => hideRevealValue() }),
      iconTextButton("copy", "Copy", { onClick: () => void copyLiveValue() }),
      button("Close (clears the value)", { onClick: () => closeReveal() }),
    );
    box.append(row);
    box.append(
      para(
        "Copy puts the value on the system clipboard — a shared, persistent channel. Other apps, clipboard managers and the X11/Wayland clipboard can retain it, and clearing is best-effort only. Nothing is ever copied automatically.",
        "muted",
      ),
    );
    if (cur.copyNote !== null) box.append(para(cur.copyNote, "muted"));
  } else {
    box.append(para("The value is hidden until you reveal it. Revealing shows it in this panel for 15 s. This is your own direct reveal through the dashboard session; no agent approval is involved.", "muted"));
    const row = el("div", { class: "row" });
    const claim = iconTextButton("eye", cur.busy ? "Revealing…" : "Reveal and show", {
      variant: "primary",
      disabled: cur.busy,
      onClick: () => {
        const c = live;
        const h = hooks;
        if (c === null || c.busy || h === null) return;
        c.busy = true;
        c.error = null;
        paint();
        h.onShow(c.project, c.key);
      },
    });
    row.append(claim, button("Close", { onClick: () => closeReveal() }));
    box.append(row);
  }
  host.append(box);
  // paint() replaces every child, which drops focus to the document body (or to
  // the overlay itself, which trapFocus focuses when it finds no control) and
  // would strand keyboard users outside the dialog. Pull focus onto the first
  // control INSIDE the dialog so containment, Escape and Tab-cycling all hold.
  if (!box.contains(document.activeElement)) {
    const first = box.querySelector("button:not([disabled]), a[href], input:not([disabled]), select:not([disabled])");
    if (first instanceof HTMLElement) first.focus();
    else {
      box.tabIndex = -1;
      box.focus();
    }
  }
}

/** Explicit Copy only — never called on reveal, focus, or select. */
async function copyLiveValue(): Promise<void> {
  const cur = live;
  if (cur === null || cur.value === null) return;
  if (!revealClipboardCopy("explicit")) return;
  const v = cur.value;
  try {
    if (typeof navigator === "undefined" || !navigator.clipboard || typeof navigator.clipboard.writeText !== "function") {
      throw new Error("unavailable");
    }
    await navigator.clipboard.writeText(v);
  } catch {
    const again = live;
    if (again !== null) {
      again.copyNote = "Copy failed — the clipboard API is unavailable. Select the value manually instead.";
      paint();
    }
    return;
  }
  clipboardHoldsCopy = true;
  const again = live;
  if (again !== null) {
    again.copied = true;
    again.copyNote = "Copied. The clipboard will be cleared best-effort in 30 s — clipboard managers may still retain it.";
    paint();
  }
  armClipboardTimer();
}

/**
 * Best-effort clipboard clear. Only ever runs when THIS app put the value
 * there (`clipboardHoldsCopy`): once the operator copies anything else, the
 * clipboard is theirs and we must not overwrite it. Does not guarantee the
 * value is gone from clipboard managers or the X11 selection; if the clear is
 * rejected the modal says so instead of promising a clear that did not happen.
 */
function bestEffortClipboardClear(): void {
  if (!clipboardHoldsCopy) return;
  clipboardHoldsCopy = false;
  try {
    if (typeof navigator === "undefined" || !navigator.clipboard) return;
    void Promise.resolve(navigator.clipboard.writeText(""))
      .then(() => undefined)
      .catch(() => {
        const cur = live;
        if (cur === null) return;
        cur.copyNote = "The clipboard could not be cleared — it may still hold the value.";
        paint();
      });
  } catch {
    // Best-effort only: a late clear must never throw into hide/close/lock paths.
  }
}

function armHideTimer(): void {
  teardownTimers();
  if (typeof window === "undefined") return;
  hideTimer = window.setTimeout(() => {
    hideTimer = null;
    hideRevealValue();
  }, REVEAL_AUTO_HIDE_MS);
  tickTimer = window.setInterval(() => {
    const cur = live;
    if (cur === null || cur.shownAtMs === null) return;
    const remaining = cur.shownAtMs + REVEAL_AUTO_HIDE_MS - Date.now();
    if (remaining <= 0) {
      hideRevealValue();
      return;
    }
    if (countdownEl !== null && countdownEl.isConnected) {
      countdownEl.textContent = `Auto-hides in ${Math.ceil(remaining / 1000)}s.`;
    }
  }, 500);
}

function armClipboardTimer(): void {
  if (typeof window === "undefined") return;
  if (clipboardTimer !== null) {
    window.clearTimeout(clipboardTimer);
    clipboardTimer = null;
  }
  // Best-effort clear after 30 000 ms: this does not guarantee the value is
  // gone from clipboard managers or from the X11 selection.
  clipboardTimer = window.setTimeout(() => {
    clipboardTimer = null;
    bestEffortClipboardClear();
  }, REVEAL_CLIPBOARD_CLEAR_MS);
}

function teardownTimers(): void {
  if (typeof window === "undefined") {
    hideTimer = null;
    tickTimer = null;
    clipboardTimer = null;
    return;
  }
  if (hideTimer !== null) {
    window.clearTimeout(hideTimer);
    hideTimer = null;
  }
  if (tickTimer !== null) {
    window.clearInterval(tickTimer);
    tickTimer = null;
  }
  if (clipboardTimer !== null) {
    window.clearTimeout(clipboardTimer);
    clipboardTimer = null;
  }
}

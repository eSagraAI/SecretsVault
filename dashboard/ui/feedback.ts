// Toast notifications plus the broker-message sanitiser. Module-local overlay
// state (single-instance chrome, allowed by the contract). Every string
// reaches the DOM via textContent — never innerHTML.

import { el } from "./components.js";

export type ToastKind = "success" | "error" | "info" | "warn";

const MAX_TOASTS = 5;
const DEFAULT_TIMEOUT_MS = 5000;
const timers = new Map<HTMLElement, number>();
let hostRef: HTMLElement | null = null;
let container: HTMLElement | null = null;

function liveContainer(): HTMLElement {
  if (!container) container = el("div", { class: "toasts" });
  // Re-home when never mounted or when a host re-render wiped the old tree.
  if (!container.isConnected) (hostRef ?? document.body).append(container);
  return container;
}

function removeToast(node: HTMLElement): void {
  const t = timers.get(node);
  if (t !== undefined) {
    clearTimeout(t);
    timers.delete(node);
  }
  node.remove();
}

export function mountToasts(host: HTMLElement): void {
  hostRef = host;
  const direct = host.querySelector(":scope > .toasts");
  if (direct instanceof HTMLElement) {
    container = direct;
    return;
  }
  if (!container) container = el("div", { class: "toasts" });
  // append() moves the node when it already lives under an older host.
  if (container.parentElement !== host) host.append(container);
}

export function toast(kind: ToastKind, message: string, o?: { detail?: string; timeoutMs?: number }): void {
  const box = liveContainer();
  const isError = kind === "error";
  const node = el("div", {
    class: `toast toast-${kind}`,
    role: isError ? "alert" : "status",
    "aria-live": isError ? "assertive" : "polite",
  });
  node.append(el("div", { class: "toast-title" }, message));
  if (o?.detail !== undefined) node.append(el("div", { class: "toast-detail" }, o.detail));
  const close = el("button", {
    class: "toast-close",
    type: "button",
    "aria-label": "Dismiss notification",
  }, "×");
  close.addEventListener("click", () => removeToast(node));
  node.append(close);
  // Bounded stack: evict the oldest first so the newest is always visible.
  while (box.childElementCount >= MAX_TOASTS) {
    const first = box.firstElementChild;
    if (!(first instanceof HTMLElement)) break;
    removeToast(first);
  }
  box.append(node);
  const timeoutMs = o?.timeoutMs ?? (isError ? 0 : DEFAULT_TIMEOUT_MS);
  // window.setTimeout (not the bare global): the global resolves to Node's
  // Timeout under @types/node while the map is typed as the DOM timer handle.
  if (timeoutMs > 0) timers.set(node, window.setTimeout(() => removeToast(node), timeoutMs));
}

export function dismissToasts(): void {
  for (const t of timers.values()) clearTimeout(t);
  timers.clear();
  container?.replaceChildren();
}

export function toastCount(): number {
  return container?.childElementCount ?? 0;
}

/**
 * Make a broker-supplied message safe for UI display. Pure, no DOM:
 * C0/C1 controls and newlines become a single space, whitespace runs
 * collapse, output trims, caps at 300 chars with a trailing … and masks
 * credential-shaped runs — while short identity material (8-hex prefixes,
 * colon-separated 64-hex fingerprints) stays readable.
 */
export function sanitizeBrokerMessage(message: string): string {
  const spaced = message.replace(/[\x00-\x1F\x7F-\x9F]/g, " ");
  const collapsed = spaced.replace(/\s+/g, " ").trim();
  // Same carve-out as state's redactForLog: a bare 8-hex prefix never reaches
  // the 32+ mask anyway; a 64-hex fingerprint would, so it stays readable.
  const masked = collapsed.replace(/[A-Za-z0-9_\-+/=]{32,}/g, (m) =>
    /^[0-9a-fA-F]{8}$/.test(m) || /^[0-9a-fA-F]{64}$/.test(m) ? m : "[credential]",
  );
  return masked.length > 300 ? `${masked.slice(0, 300)}…` : masked;
}

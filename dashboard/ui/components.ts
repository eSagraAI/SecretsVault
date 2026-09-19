import { icon, type IconName } from "./icons.js";
import type { Tone } from "./state.js";

// Small render helpers. All DOM via createElement/textContent — never
// innerHTML with interpolated data. No remote assets, no inline handlers.
//
// Frozen helpers (behaviour preserved byte-for-byte): el, banner, pill,
// fieldRow, panel, para, codeBlock. Everything below them is the D5 primitive
// set consumed by the shell and all screens. Class names come from the frozen
// §3 vocabulary only.

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string> = {},
  text = "",
): HTMLElementTagNameMap[K] {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  if (text) n.textContent = text;
  return n;
}

export type BannerKind = "info" | "warn" | "alarm";

export function banner(kind: BannerKind, text: string): HTMLElement {
  const d = el("div", { class: `banner banner-${kind}`, role: kind === "alarm" ? "alert" : "status" }, text);
  return d;
}

export function pill(label: string, tone: "ok" | "bad" | "warn" | "mute"): HTMLElement {
  return el("span", { class: `pill pill-${tone}` }, label);
}

export function fieldRow(label: string, value: string): HTMLElement {
  const row = el("div", { class: "field" });
  row.append(el("span", { class: "field-label" }, label), el("span", { class: "field-value" }, value));
  return row;
}

export function panel(title: string, body: Node[]): HTMLElement {
  const s = el("section", { class: "panel" });
  s.append(el("h2", {}, title));
  for (const n of body) s.append(n);
  return s;
}

export function para(text: string, cls = ""): HTMLElement {
  return el("p", cls ? { class: cls } : {}, text);
}

/** Monospace block for fingerprints / codes. textContent keeps it inert. */
export function codeBlock(text: string): HTMLElement {
  return el("pre", { class: "mono" }, text);
}

export function badge(label: string, tone: Tone, opts?: { title?: string }): HTMLElement {
  const attrs: Record<string, string> = { class: `badge badge-tone-${tone}` };
  if (opts?.title !== undefined) attrs["title"] = opts.title;
  return el("span", attrs, label);
}

export function statusDot(tone: Tone, label: string): HTMLElement {
  const root = el("span", { "aria-label": label });
  const dot = el("span", { class: `status-dot status-dot-${tone}`, "aria-hidden": "true" });
  root.append(dot, document.createTextNode(label));
  return root;
}

export function button(label: string, o?: {
  variant?: "primary" | "default" | "danger" | "ghost" | "warn"; disabled?: boolean;
  onClick?: () => void; title?: string; type?: "button" | "submit"; size?: "sm" | "md" | "lg";
}): HTMLButtonElement {
  const cls = ["btn"];
  if (o?.variant === "primary") cls.push("btn-primary");
  else if (o?.variant === "danger") cls.push("btn-danger");
  else if (o?.variant === "ghost") cls.push("btn-ghost");
  else if (o?.variant === "warn") cls.push("btn-warn");
  if (o?.size === "sm") cls.push("btn-sm");
  else if (o?.size === "lg") cls.push("btn-lg");
  const b = el("button", { class: cls.join(" "), type: o?.type ?? "button" }, label);
  if (o?.title !== undefined) b.setAttribute("title", o.title);
  if (o?.disabled === true) b.disabled = true;
  if (o?.onClick) b.addEventListener("click", o.onClick);
  return b;
}

export function iconButton(n: IconName, label: string, o?: {
  variant?: "default" | "ghost" | "danger" | "warn"; disabled?: boolean; onClick?: () => void; title?: string;
}): HTMLButtonElement {
  const cls = ["btn", "btn-icon"];
  if (o?.variant === "ghost") cls.push("btn-ghost");
  else if (o?.variant === "danger") cls.push("btn-danger");
  else if (o?.variant === "warn") cls.push("btn-warn");
  const b = el("button", {
    class: cls.join(" "),
    type: "button",
    "aria-label": label,
    title: o?.title ?? label,
  });
  b.append(icon(n));
  if (o?.disabled === true) b.disabled = true;
  if (o?.onClick) b.addEventListener("click", o.onClick);
  return b;
}

export function iconTextButton(n: IconName, label: string, o?: {
  variant?: "primary" | "default" | "danger" | "ghost" | "warn"; disabled?: boolean;
  onClick?: () => void; title?: string; type?: "button" | "submit"; size?: "sm" | "md" | "lg";
}): HTMLButtonElement {
  const cls = ["btn"];
  if (o?.variant === "primary") cls.push("btn-primary");
  else if (o?.variant === "danger") cls.push("btn-danger");
  else if (o?.variant === "ghost") cls.push("btn-ghost");
  else if (o?.variant === "warn") cls.push("btn-warn");
  if (o?.size === "sm") cls.push("btn-sm");
  else if (o?.size === "lg") cls.push("btn-lg");
  const b = el("button", { class: cls.join(" "), type: o?.type ?? "button" });
  b.append(icon(n), document.createTextNode(label));
  if (o?.title !== undefined) b.setAttribute("title", o.title);
  if (o?.disabled === true) b.disabled = true;
  if (o?.onClick) b.addEventListener("click", o.onClick);
  return b;
}

export function card(title: string, o?: {
  subtitle?: string; actions?: Node[]; tone?: Tone; id?: string;
}): { root: HTMLElement; header: HTMLElement; body: HTMLElement; footer: HTMLElement } {
  // No card-tone-mute class exists in the frozen vocabulary: mute renders untoned.
  const toneCls = o?.tone !== undefined && o.tone !== "mute" ? ` card-tone-${o.tone}` : "";
  const root = el("section", { class: `card${toneCls}` });
  if (o?.id !== undefined) root.id = o.id;
  const header = el("div", { class: "card-header" });
  header.append(el("h2", { class: "card-title" }, title));
  if (o?.subtitle !== undefined) header.append(el("p", { class: "card-sub" }, o.subtitle));
  if (o?.actions !== undefined && o.actions.length > 0) {
    const actions = el("div", { class: "card-actions" });
    for (const n of o.actions) actions.append(n);
    header.append(actions);
  }
  const body = el("div", { class: "card-body" });
  const footer = el("div", { class: "card-footer" });
  root.append(header, body, footer);
  return { root, header, body, footer };
}

export function section(title: string, o?: { subtitle?: string; actions?: Node[] }): { root: HTMLElement; body: HTMLElement } {
  // No section-body class in the vocabulary: the body is a plain div.
  const root = el("section", { class: "section" });
  const header = el("div", { class: "section-header" });
  header.append(el("h2", { class: "section-title" }, title));
  if (o?.subtitle !== undefined) header.append(el("p", { class: "muted" }, o.subtitle));
  if (o?.actions !== undefined && o.actions.length > 0) {
    const actions = el("div", { class: "section-actions" });
    for (const n of o.actions) actions.append(n);
    header.append(actions);
  }
  const secBody = el("div", {});
  root.append(header, secBody);
  return { root, body: secBody };
}

export function breadcrumb(parts: string[]): HTMLElement {
  const nav = el("nav", { class: "breadcrumb", "aria-label": "Breadcrumb" });
  parts.forEach((part, i) => {
    if (i > 0) nav.append(el("span", { class: "breadcrumb-sep", "aria-hidden": "true" }, "/"));
    const attrs: Record<string, string> = {};
    if (i === parts.length - 1) attrs["aria-current"] = "page";
    nav.append(el("span", attrs, part));
  });
  return nav;
}

export function pageHeader(title: string, o?: {
  subtitle?: string; actions?: Node[]; breadcrumb?: string[];
}): HTMLElement {
  const root = el("div", { class: "page-header" });
  if (o?.breadcrumb !== undefined && o.breadcrumb.length > 0) root.append(breadcrumb(o.breadcrumb));
  root.append(el("h1", { class: "page-title" }, title));
  if (o?.subtitle !== undefined) root.append(el("p", { class: "page-sub" }, o.subtitle));
  if (o?.actions !== undefined && o.actions.length > 0) {
    const actions = el("div", { class: "page-actions" });
    for (const n of o.actions) actions.append(n);
    root.append(actions);
  }
  return root;
}

export function stat(label: string, value: string, o?: {
  tone?: Tone; hint?: string; route?: string;
}): HTMLElement {
  const root = o?.route !== undefined
    ? el("a", { class: "stat", href: o.route })
    : el("div", { class: "stat" });
  root.append(el("div", { class: "stat-label" }, label));
  const valueEl = el("div", { class: "stat-value" });
  if (o?.tone !== undefined) {
    valueEl.append(el("span", { class: `status-dot status-dot-${o.tone}`, "aria-hidden": "true" }));
  }
  valueEl.append(document.createTextNode(value));
  root.append(valueEl);
  if (o?.hint !== undefined) root.append(el("div", { class: "stat-hint" }, o.hint));
  return root;
}

export function stats(items: HTMLElement[]): HTMLElement {
  const root = el("div", { class: "stats" });
  for (const n of items) root.append(n);
  return root;
}

export function table(columns: Array<string | { label: string; numeric?: boolean }>,
  rows: HTMLElement[][], o?: {
    dense?: boolean; zebra?: boolean; empty?: string; label?: string;
  }): HTMLElement {
  const wrap = el("div", { class: "table-wrap" });
  const cls = ["table"];
  if (o?.dense === true) cls.push("table-dense");
  if (o?.zebra === true) cls.push("table-zebra");
  const t = el("table", { class: cls.join(" ") });
  if (o?.label !== undefined) t.setAttribute("aria-label", o.label);
  const headRow = el("tr", {});
  for (const col of columns) {
    const label = typeof col === "string" ? col : col.label;
    const th = el("th", { scope: "col" }, label);
    // No numeric-alignment class in the vocabulary: expose it as data instead.
    if (typeof col !== "string" && col.numeric === true) th.setAttribute("data-numeric", "true");
    headRow.append(th);
  }
  const headEl = el("thead", {});
  headEl.append(headRow);
  const bodyEl = el("tbody", {});
  for (const row of rows) {
    const tr = el("tr", {});
    row.forEach((cell, i) => {
      const td = el("td", {});
      const col = columns[i];
      if (typeof col !== "string" && col?.numeric === true) td.setAttribute("data-numeric", "true");
      td.append(cell);
      tr.append(td);
    });
    bodyEl.append(tr);
  }
  if (rows.length === 0 && o?.empty !== undefined) {
    const tr = el("tr", {});
    tr.append(el("td", { class: "table-empty", colspan: String(columns.length) }, o.empty));
    bodyEl.append(tr);
  }
  t.append(headEl, bodyEl);
  wrap.append(t);
  return wrap;
}

export function fieldGrid(pairs: Array<[string, Node | string]>): HTMLElement {
  const root = el("div", { class: "field-grid" });
  for (const [label, value] of pairs) {
    const row = el("div", { class: "field" });
    row.append(el("span", { class: "field-label" }, label));
    const v = el("span", { class: "field-value" });
    if (typeof value === "string") v.textContent = value;
    else v.append(value);
    row.append(v);
    root.append(row);
  }
  return root;
}

export function emptyState(title: string, body: string, o?: { icon?: IconName; actions?: Node[] }): HTMLElement {
  const root = el("div", { class: "empty-state" });
  if (o?.icon !== undefined) {
    const holder = el("div", { class: "empty-state-icon", "aria-hidden": "true" });
    holder.append(icon(o.icon, 24));
    root.append(holder);
  }
  root.append(el("h2", { class: "empty-state-title" }, title));
  root.append(el("p", { class: "empty-state-body" }, body));
  if (o?.actions !== undefined && o.actions.length > 0) {
    const actions = el("div", { class: "empty-state-actions" });
    for (const n of o.actions) actions.append(n);
    root.append(actions);
  }
  return root;
}

export function errorState(title: string, body: string, o?: { code?: string; retry?: Node[] }): HTMLElement {
  const root = el("div", { class: "error-state", role: "alert" });
  root.append(el("h2", {}, title));
  root.append(el("p", {}, body));
  if (o?.code !== undefined) root.append(codeBlock(o.code));
  if (o?.retry !== undefined && o.retry.length > 0) {
    const row = el("div", { class: "row" });
    for (const n of o.retry) row.append(n);
    root.append(row);
  }
  return root;
}

export function loadingState(label: string, o?: { rows?: number; cols?: number }): HTMLElement {
  const root = el("div", { class: "loading-state", role: "status" });
  root.append(el("span", { class: "muted" }, label));
  root.append(skeletonRows(o?.rows ?? 3, o?.cols ?? 3));
  return root;
}

export function skeletonRows(rows: number, cols: number): HTMLElement {
  const root = el("div", { class: "skeleton", "aria-hidden": "true" });
  for (let r = 0; r < rows; r++) {
    const row = el("div", { class: "skeleton-row" });
    for (let c = 0; c < cols; c++) row.append(el("div", { class: "skeleton-cell" }));
    root.append(row);
  }
  return root;
}

export function chip(text: string, o?: { tone?: Tone; title?: string }): HTMLElement {
  const attrs: Record<string, string> = { class: `chip chip-tone-${o?.tone ?? "mute"}` };
  if (o?.title !== undefined) attrs["title"] = o.title;
  return el("span", attrs, text);
}

export function chipList(items: Array<{ text: string; tone?: Tone; title?: string }>, o?: { empty?: string }): HTMLElement {
  const root = el("div", { class: "chiplist" });
  for (const item of items) root.append(chip(item.text, { tone: item.tone, title: item.title }));
  if (items.length === 0 && o?.empty !== undefined) root.append(el("span", { class: "muted" }, o.empty));
  return root;
}

export function kbd(keys: string): HTMLElement {
  const root = el("span", {});
  const parts = keys.split(/\s+/).filter((p) => p.length > 0);
  parts.forEach((part, i) => {
    if (i > 0) root.append(document.createTextNode(" "));
    root.append(el("kbd", { class: "kbd" }, part));
  });
  return root;
}

export function toolbar(nodes: Node[]): HTMLElement {
  const root = el("div", { class: "toolbar" });
  for (const n of nodes) root.append(n);
  return root;
}

export function meter(label: string, value: number | null, max: number | null): HTMLElement {
  const known = value !== null && max !== null && max > 0;
  const ratio = known ? Math.max(0, Math.min(1, (value as number) / (max as number))) : 0;
  const text = known ? `${String(value)} / ${String(max)}` : "—";
  const root = el("div", { class: "meter", "aria-label": `${label}: ${text}` });
  root.append(el("span", {}, label));
  const bar = el("div", { class: "meter-bar", "aria-hidden": "true" });
  // No meter-mute class exists: unknown renders an untoned, empty fill.
  const toneCls = !known ? "" : ratio >= 0.8 ? " meter-bad" : ratio >= 0.5 ? " meter-warn" : " meter-ok";
  const fill = el("div", { class: `meter-fill${toneCls}` });
  // Fill proportion has no vocabulary class: CSSOM width is the last resort.
  fill.style.width = `${String(Math.round(ratio * 100))}%`;
  bar.append(fill);
  root.append(bar);
  root.append(el("span", {}, text));
  return root;
}

export function confirmBar(message: string, o: {
  onConfirm: () => void; onCancel: () => void; busy?: boolean;
  confirmLabel?: string; cancelLabel?: string; danger?: boolean;
}): HTMLElement {
  const root = el("div", { class: "confirm-bar" });
  root.append(el("span", { class: "confirm-bar-text" }, message));
  const busy = o.busy === true;
  root.append(button(o.cancelLabel ?? "Cancel", { variant: "ghost", disabled: busy, onClick: o.onCancel }));
  root.append(button(o.confirmLabel ?? "Confirm", {
    variant: o.danger === true ? "danger" : "primary",
    disabled: busy,
    onClick: o.onConfirm,
  }));
  return root;
}

export function modalShell(title: string, o?: { label?: string; tone?: Tone }): {
  root: HTMLElement;
  box: HTMLElement; body: HTMLElement; footer: HTMLElement;
} {
  // The overlay is returned DETACHED: the caller appends it to document.body.
  const root = el("div", { class: "modal-overlay" });
  const box = el("div", {
    class: "modal",
    role: "dialog",
    "aria-modal": "true",
    "aria-label": o?.label ?? title,
  });
  const header = el("div", { class: "modal-header" });
  if (o?.tone !== undefined && o.tone !== "mute") {
    header.append(el("span", { class: `status-dot status-dot-${o.tone}`, "aria-hidden": "true" }));
  }
  header.append(el("h2", {}, title));
  const body = el("div", { class: "modal-body" });
  const footer = el("div", { class: "modal-footer" });
  box.append(header, body, footer);
  root.append(box);
  return { root, box, body, footer };
}

const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/** Focus trap + Escape + restore-focus helper for overlays. Returns a disposer. */
export function trapFocus(overlay: HTMLElement, o: { onEscape: () => void }): () => void {
  const prev = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  // Array.from (not spread): the tsconfig lib set has DOM but not DOM.Iterable,
  // so NodeListOf is not iterable at the type level.
  const focusables = (): HTMLElement[] =>
    Array.from(overlay.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter((n) => !n.hasAttribute("disabled"));
  const onKey = (e: KeyboardEvent): void => {
    if (e.key === "Escape") {
      e.stopPropagation();
      o.onEscape();
      return;
    }
    if (e.key !== "Tab") return;
    const items = focusables();
    if (items.length === 0) {
      e.preventDefault();
      return;
    }
    const first = items[0] as HTMLElement;
    const last = items[items.length - 1] as HTMLElement;
    const active = document.activeElement;
    if (!overlay.contains(active)) {
      e.preventDefault();
      (e.shiftKey ? last : first).focus();
    } else if (e.shiftKey && active === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && active === last) {
      e.preventDefault();
      first.focus();
    }
  };
  overlay.addEventListener("keydown", onKey);
  const first = focusables()[0];
  if (first) first.focus();
  else {
    overlay.tabIndex = -1;
    overlay.focus();
  }
  return () => {
    overlay.removeEventListener("keydown", onKey);
    if (prev && prev.isConnected) prev.focus();
  };
}

export function copyButton(value: string, label: string, o?: { onCopied?: (ok: boolean) => void }): HTMLButtonElement {
  // Copies only inside the click handler — never on its own — and never throws.
  const btn = iconTextButton("copy", label);
  btn.addEventListener("click", () => {
    try {
      const clip = typeof navigator !== "undefined" ? navigator.clipboard : undefined;
      if (!clip || typeof clip.writeText !== "function") {
        o?.onCopied?.(false);
        return;
      }
      clip.writeText(value).then(
        () => o?.onCopied?.(true),
        () => o?.onCopied?.(false),
      );
    } catch {
      o?.onCopied?.(false);
    }
  });
  return btn;
}

export function confirmDialog(title: string, body: string, o: {
  onConfirm: () => void; confirmLabel?: string; cancelLabel?: string; danger?: boolean;
}): void {
  const shell = modalShell(title);
  shell.body.append(el("p", {}, body));
  const close = (): void => {
    dispose();
    shell.root.remove();
  };
  shell.footer.append(
    button(o.cancelLabel ?? "Cancel", { variant: "ghost", onClick: close }),
    button(o.confirmLabel ?? "Confirm", {
      variant: o.danger === true ? "danger" : "primary",
      onClick: () => {
        close();
        o.onConfirm();
      },
    }),
  );
  document.body.append(shell.root);
  const dispose = trapFocus(shell.root, { onEscape: close });
}

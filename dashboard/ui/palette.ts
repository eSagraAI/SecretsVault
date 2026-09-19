// Command palette overlay. Module-local state (single-instance chrome,
// allowed by the contract). The command list is read through the `commands`
// getter on every open/render so it stays fresh. All text via textContent.

import { el, kbd, trapFocus } from "./components.js";

export interface PaletteCommand { id: string; label: string; hint?: string; keys?: string; run: () => void; }

const LIST_ID = "palette-list";
const EMPTY_TEXT = "No matching commands";

let hostRef: HTMLElement | null = null;
let getCommands: () => PaletteCommand[] = () => [];
let overlay: HTMLElement | null = null;
let inputEl: HTMLInputElement | null = null;
let listEl: HTMLElement | null = null;
let visible: PaletteCommand[] = [];
let active = -1;
let opened = false;
let disposeTrap: (() => void) | null = null;

function currentCommands(): PaletteCommand[] {
  try {
    const cmds = getCommands();
    return Array.isArray(cmds) ? cmds : [];
  } catch {
    return [];
  }
}

export function filterCommands(commands: PaletteCommand[], query: string): PaletteCommand[] {
  try {
    const list = Array.isArray(commands) ? commands : [];
    const q = (typeof query === "string" ? query : "").trim().toLowerCase();
    if (q === "") return list.slice();
    return list.filter((c) => {
      if (!c || typeof c.label !== "string") return false;
      const hint = typeof c.hint === "string" ? c.hint : "";
      return `${c.label} ${hint}`.toLowerCase().includes(q);
    });
  } catch {
    return [];
  }
}

function renderItem(cmd: PaletteCommand, index: number): HTMLElement {
  const item = el("div", {
    class: "palette-item",
    role: "option",
    id: `${LIST_ID}-${String(index)}`,
    "aria-selected": "false",
  });
  item.append(document.createTextNode(cmd.label));
  if (cmd.hint !== undefined && cmd.hint !== "") {
    item.append(el("span", { class: "palette-hint" }, cmd.hint));
  }
  if (cmd.keys !== undefined && cmd.keys !== "") item.append(kbd(cmd.keys));
  item.addEventListener("click", () => {
    try {
      cmd.run();
    } finally {
      closePalette();
    }
  });
  return item;
}

function paintActive(): void {
  const input = inputEl;
  const list = listEl;
  if (!input || !list) return;
  let activeId = "";
  for (let i = 0; i < list.childElementCount; i++) {
    const kid = list.children[i];
    if (!(kid instanceof HTMLElement)) continue;
    const on = i === active && active >= 0;
    kid.classList.toggle("palette-item-active", on);
    kid.setAttribute("aria-selected", on ? "true" : "false");
    if (on && kid.id) activeId = kid.id;
  }
  input.setAttribute("aria-expanded", visible.length > 0 ? "true" : "false");
  if (activeId) input.setAttribute("aria-activedescendant", activeId);
  else input.removeAttribute("aria-activedescendant");
}

function renderList(query: string): void {
  const list = listEl;
  if (!list) return;
  visible = filterCommands(currentCommands(), query);
  list.replaceChildren();
  if (visible.length === 0) {
    list.append(el("div", { class: "palette-empty" }, EMPTY_TEXT));
    active = -1;
  } else {
    visible.forEach((cmd, i) => list.append(renderItem(cmd, i)));
    active = 0;
  }
  paintActive();
}

function moveActive(delta: 1 | -1): void {
  if (visible.length === 0) return;
  active = (active + delta + visible.length) % visible.length;
  paintActive();
  const node = listEl?.children[active];
  if (node instanceof HTMLElement) node.scrollIntoView({ block: "nearest" });
}

export function mountPalette(host: HTMLElement, commands: () => PaletteCommand[]): void {
  hostRef = host;
  getCommands = commands;
  if (overlay && inputEl && listEl) return;
  const root = el("div", { class: "palette-overlay" });
  const box = el("div", { class: "palette", role: "dialog", "aria-label": "Command palette" });
  const input = document.createElement("input");
  input.setAttribute("class", "palette-input");
  input.setAttribute("type", "text");
  input.setAttribute("role", "combobox");
  input.setAttribute("aria-expanded", "false");
  input.setAttribute("aria-controls", LIST_ID);
  input.setAttribute("aria-autocomplete", "list");
  input.setAttribute("aria-label", "Filter commands");
  input.setAttribute("placeholder", "Type a command…");
  input.setAttribute("autocomplete", "off");
  input.setAttribute("spellcheck", "false");
  const list = el("div", { class: "palette-list", role: "listbox", id: LIST_ID, "aria-label": "Commands" });
  input.addEventListener("input", () => renderList(input.value));
  input.addEventListener("keydown", (e: KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      moveActive(1);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      moveActive(-1);
    } else if (e.key === "Enter") {
      e.preventDefault();
      const cmd = visible[active];
      if (cmd) {
        try {
          cmd.run();
        } finally {
          closePalette();
        }
      }
    }
    // Escape is handled by the trapFocus onEscape below.
  });
  box.append(input, list);
  root.append(box);
  overlay = root;
  inputEl = input;
  listEl = list;
}

export function openPalette(): void {
  const root = overlay;
  const input = inputEl;
  const host = hostRef;
  if (!root || !input || !host) return;
  if (!opened) {
    opened = true;
    host.append(root);
    disposeTrap = trapFocus(root, { onEscape: () => closePalette() });
  }
  input.value = "";
  renderList("");
  input.focus();
}

export function closePalette(): void {
  if (!opened) return;
  opened = false;
  if (disposeTrap) {
    disposeTrap();
    disposeTrap = null;
  }
  overlay?.remove();
}

export function paletteOpen(): boolean {
  return opened;
}

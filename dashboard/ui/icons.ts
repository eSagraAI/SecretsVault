// Inline SVG icon set. Stroke-only (1.5 px, round caps/joins), currentColor,
// no text glyphs, no <use>/external refs. Built with createElementNS —
// never innerHTML. 16 px default.

export type IconName =
  | "overview" | "projects" | "secrets" | "agents" | "grants" | "leases" | "approvals"
  | "runs" | "audit" | "settings" | "lock" | "unlock" | "refresh" | "command" | "search"
  | "chevron-right" | "chevron-down" | "copy" | "eye" | "eye-off" | "alert" | "warning"
  | "check" | "x" | "shield" | "key" | "clock" | "folder" | "play" | "plus" | "trash";

const SVG_NS = "http://www.w3.org/2000/svg";

type Child = [string, Record<string, string>];

const R = (x: string, y: string, w: string, h: string, rx: string): Child =>
  ["rect", { x, y, width: w, height: h, rx }];
const C = (cx: string, cy: string, r: string): Child =>
  ["circle", { cx, cy, r }];
const P = (d: string): Child => ["path", { d }];

const ICONS: Record<IconName, Child[]> = {
  overview: [R("1.5", "1.5", "5", "5", "1"), R("9.5", "1.5", "5", "5", "1"), R("1.5", "9.5", "5", "5", "1"), R("9.5", "9.5", "5", "5", "1")],
  projects: [P("M8 1.8 14.5 5 8 8.2 1.5 5Z"), P("M2.5 8.2 8 11l5.5-2.8"), P("M2.5 11.2 8 14l5.5-2.8")],
  secrets: [R("2.5", "2.5", "11", "11", "1.5"), C("8", "8", "2.8"), P("M8 8l1.6-1.2")],
  agents: [C("8", "5", "2.6"), P("M2.8 14c.6-2.8 2.7-4.2 5.2-4.2s4.6 1.4 5.2 4.2")],
  grants: [C("6", "8", "3.4"), C("10", "8", "3.4")],
  leases: [P("M4 1.8h8M4 14.2h8M5 1.8v2.6l3 3.2 3-3.2V1.8M5 14.2v-2.6l3-3.2 3 3.2v2.6")],
  approvals: [C("8", "8", "6.3"), P("M5.4 8.3 7.3 10.2 10.8 6")],
  runs: [R("1.5", "3", "13", "10", "1.5"), P("M4.5 6l2 2-2 2M8 10.5h3.5")],
  audit: [P("M4 1.5h4.5L12 5v9.5H4Z"), P("M8.5 1.5V5H12"), P("M6 8h4M6 10.5h4")],
  settings: [C("8", "8", "2.1"), P("M8 1.5v2.2M8 12.3v2.2M1.5 8h2.2M12.3 8h2.2M3.4 3.4l1.5 1.5M11.1 11.1l1.5 1.5M12.6 3.4l-1.5 1.5M4.9 11.1l-1.5 1.5")],
  lock: [R("3.5", "7", "9", "7", "1.2"), P("M5.8 7V5.2a2.2 2.2 0 0 1 4.4 0V7")],
  unlock: [R("3.5", "7", "9", "7", "1.2"), P("M5.8 7V5.2a2.2 2.2 0 0 1 4.3-.7")],
  refresh: [P("M13.8 8a5.8 5.8 0 1 1-1.7-4.1"), P("M13.8 1.5v3h-3")],
  command: [P("M12 2a2 2 0 0 0-2 2v8a2 2 0 0 0 2-2 2 2 0 0 0-2-2H4a2 2 0 0 0-2 2 2 2 0 0 0 2 2V4a2 2 0 0 0-2-2 2 2 0 0 0 2 2h8a2 2 0 0 0 2-2Z")],
  search: [C("7", "7", "4.3"), P("M10.2 10.2 14.5 14.5")],
  "chevron-right": [P("M6 3.5 10.5 8 6 12.5")],
  "chevron-down": [P("M3.5 6 8 10.5 12.5 6")],
  copy: [R("5.5", "5.5", "8.5", "8.5", "1.2"), P("M11 5.5V3.5a1 1 0 0 0-1-1H3.5a1 1 0 0 0-1 1V10a1 1 0 0 0 1 1H4.5")],
  eye: [P("M1.8 8S4.5 4.5 8 4.5 14.2 8 14.2 8 11.5 11.5 8 11.5 1.8 8 1.8 8Z"), C("8", "8", "1.8")],
  "eye-off": [P("M2.5 2.5l11 11"), P("M6.2 4.8c.6-.2 1.2-.3 1.8-.3 3.5 0 6 3.5 6 3.5a11.6 11.6 0 0 1-2.3 2.2M3.2 5.6A11.3 11.3 0 0 1 2 8s2.5 3.5 6 3.5c.6 0 1.2-.1 1.8-.3")],
  alert: [P("M8 2.2 14.8 13.5H1.2Z"), P("M8 6.5v3"), P("M8 11.6v.2")],
  warning: [C("8", "8", "6.3"), P("M8 5v3.6"), P("M8 11v.2")],
  check: [P("M2.8 8.5 6.5 12.2 13.2 4.3")],
  x: [P("M4 4l8 8M12 4l-8 8")],
  shield: [P("M8 1.5 13.5 3.5v3.8c0 3.8-2.4 5.9-5.5 7.2-3.1-1.3-5.5-3.4-5.5-7.2V3.5Z")],
  key: [C("4.8", "8", "2.8"), P("M7.3 8H14M12 8v2.6M9.8 8v1.6")],
  clock: [C("8", "8", "6.3"), P("M8 4.8V8l2.4 1.5")],
  folder: [P("M1.8 4.2a1 1 0 0 1 1-1h3.6L8 5h5.2a1 1 0 0 1 1 1v6a1 1 0 0 1-1 1H2.8a1 1 0 0 1-1-1Z")],
  play: [P("M5 3.2 12.5 8 5 12.8Z")],
  plus: [P("M8 3v10M3 8h10")],
  trash: [P("M2.5 4h11M6.5 4V2.5h3V4M4 4l.7 9.3a1 1 0 0 0 1 1h4.6a1 1 0 0 0 1-1L12 4"), P("M6.6 7v4M9.4 7v4")],
};

export function icon(name: IconName, size = 16): SVGSVGElement {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("width", String(size));
  svg.setAttribute("height", String(size));
  svg.setAttribute("viewBox", "0 0 16 16");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.5");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  for (const [tag, attrs] of ICONS[name]) {
    const n = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    svg.append(n);
  }
  return svg;
}

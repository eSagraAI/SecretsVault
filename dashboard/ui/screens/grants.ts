// Grants: the Agent → Project → Capabilities view over `grants_list` /
// `grant_set` / `grant_revoke`. No optimistic UI: after any mutation the
// list is re-read before render. Selectors are sourced from the real
// `agents`/`projects` slices — never a hardcoded list.

import {
  badge,
  banner,
  button,
  card,
  chip,
  chipList,
  confirmBar,
  el,
  emptyState,
  errorState,
  loadingState,
  pageHeader,
  para,
  section,
  statusDot,
} from "../components.js";
import {
  activeGrantOps,
  activeGrantsFor,
  CAPABILITIES,
  capabilityMatrix,
  capabilityTone,
  errorAdvice,
  grantRunRemoved,
  grantWidens,
  RESERVED_CAPABILITIES,
  type GrantDraft,
  type GrantPair,
  type MappedError,
  type PendingConfirm,
  type ShellState,
} from "../state.js";
export interface GrantsActions {
  busyAction: string | null;
  pendingConfirm: PendingConfirm | null;
  draft: GrantDraft | null;
  /** The pair the editor is pointed at; null before the operator ever picked one. */
  pair: GrantPair | null;
  onSave: (agent: string, project: string, ops: string[]) => void;
  onPairChange: (agent: string, project: string) => void;
  onConfirmSave: () => void;
  onRevoke: (agent: string, project: string) => void;
  onCancelConfirm: () => void;
  onReload: () => void;
  inlineError: MappedError | null;
}

export function renderGrants(root: HTMLElement, s: ShellState, a: GrantsActions): void {
  root.replaceChildren();
  const busyReload = a.busyAction === "grants_list";
  const wrap = el("div", { class: "page" });
  wrap.append(
    pageHeader("Grants", {
      subtitle: "Agent × project × capability. Cells route through the existing save semantics.",
      actions: [
        button(busyReload ? "Loading…" : "Reload", {
          disabled: a.busyAction !== null,
          onClick: () => a.onReload(),
        }),
      ],
    }),
  );

  if (s.sessionExpired) {
    wrap.append(banner("warn", "Your session expired — unlock again before managing grants."));
  }
  if (a.inlineError) {
    wrap.append(
      errorState(a.inlineError.message, errorAdvice(a.inlineError.code) ?? "", {
        code: a.inlineError.code,
        retry: [button("Reload", { disabled: a.busyAction !== null, onClick: () => a.onReload() })],
      }),
    );
  }

  wrap.append(matrixSection(s, a));
  wrap.append(grantsListSection(s, a));
  wrap.append(editorPanel(s, a));
  if (a.draft) wrap.append(draftConfirm(s, a));
  root.append(wrap);
}

type CellTarget = { agent: string; project: string; ops: string[] } | null;

/** Resolve the onSave target for a project × capability cell: the first live grant holding it. */
function cellTarget(s: ShellState, project: string, cap: string): { first: CellTarget; others: string[] } {
  const holders = activeGrantsFor(s, project).filter((g) => g.ops.indexOf(cap) >= 0);
  if (holders.length === 0) return { first: null, others: [] };
  const first = holders[0];
  return {
    first: { agent: first.agent, project, ops: [...first.ops] },
    others: holders.slice(1).map((g) => g.agent),
  };
}

function matrixSection(s: ShellState, a: GrantsActions): HTMLElement {
  const sec = section("Capability matrix", {
    subtitle: "Rows are projects, columns are capabilities. A cell is on when any live grant on that project holds the capability.",
  });
  const { projects } = capabilityMatrix(s);
  const box = el("div", { class: "matrix", role: "grid", "aria-label": "Capability matrix" });
  const cols = 1 + CAPABILITIES.length;
  const head = el("div", { class: "matrix-head" });
  // No vocabulary class for a dynamic column count: CSSOM width is the last resort.
  head.style.gridTemplateColumns = `repeat(${String(cols)}, minmax(0, 1fr))`;
  head.append(el("span", { class: "matrix-cell" }, "Project"));
  for (const cap of CAPABILITIES) {
    const h = el("span", { class: "matrix-cell" }, cap);
    if (RESERVED_CAPABILITIES[cap]) {
      h.append(el("span", { class: "cap-reserved", title: "The broker models and grants this, but no agent operation consumes it yet — management stays human-only." }, " reserved"));
    }
    head.append(h);
  }
  box.append(head);
  if (s.grants === null) {
    if (a.busyAction === "grants_list") {
      box.append(loadingState("Loading grants…"));
    } else {
      box.append(emptyState("Grants not loaded", "Grants are not loaded yet — press Reload.", { icon: "grants" }));
    }
    sec.body.append(box);
    return sec.root;
  }
  if (projects.length === 0) {
    box.append(emptyState("No grants yet.", "Use the editor below to grant an agent capabilities on a project.", { icon: "grants" }));
    sec.body.append(box);
    return sec.root;
  }
  for (const project of projects) {
    const row = el("div", { class: "matrix-row" });
    row.style.gridTemplateColumns = `repeat(${String(cols)}, minmax(0, 1fr))`;
    row.append(el("span", { class: "matrix-cell mono" }, project));
    for (const cap of CAPABILITIES) {
      row.append(matrixCell(s, a, project, cap));
    }
    box.append(row);
  }
  sec.body.append(box);
  return sec.root;
}

function matrixCell(s: ShellState, a: GrantsActions, project: string, cap: string): HTMLElement {
  const { first, others } = cellTarget(s, project, cap);
  const saved = first !== null ? first.ops : [];
  if (first === null) {
    // Inert by design: with no live holder there is no (agent, project, ops)
    // triple for the existing onSave(agent, project, ops) semantics, and no
    // new action member is allowed — so an -off cell never calls onSave.
    // The glyph is paired with a text label so the state never rests on colour.
    const off = el("span", { class: "matrix-cell matrix-cell-off", title: `No live grant holds ${cap} on ${project}. Grant it from the editor below.` }, "○ off");
    off.setAttribute("aria-label", `${project} ${cap}: off`);
    return off;
  }
  const cell = el("button", { type: "button", class: "matrix-cell matrix-cell-on", title: titleFor(first.agent, project, cap, saved, others) }, "● on");
  cell.setAttribute("aria-label", `${project} ${cap}: on via ${first.agent}`);
  cell.addEventListener("click", () => {
    // An -on cell removal can only narrow that grant, so it saves directly
    // through the existing onSave path (app.ts stages a draft only when the
    // proposed set widens authority).
    const next = saved.filter((c) => c !== cap);
    a.onSave(first.agent, project, next);
  });
  return cell;
}

function titleFor(agent: string, project: string, cap: string, saved: string[], others: string[]): string {
  const base = `${agent} holds ${cap} on ${project} (${saved.join(", ")}). Press to narrow to (${saved.filter((c) => c !== cap).join(", ") || "no capabilities"}).`;
  const sensitive = cap === "reveal" || cap === "manage" ? " Sensitive capability." : "";
  const alt = others.length > 0 ? ` Also held by: ${others.join(", ")}.` : "";
  return `${base}${sensitive}${alt}`;
}

function grantsListSection(s: ShellState, a: GrantsActions): HTMLElement {
  const sec = section("Grants by agent", {
    subtitle: "Every live and revoked grant the broker lists.",
  });
  const list = s.grants;
  if (list === null) {
    if (a.busyAction === "grants_list") {
      sec.body.append(loadingState("Loading grants…"));
    } else {
      sec.body.append(emptyState("Grants not loaded", "Grants are not loaded yet — press Reload.", { icon: "grants" }));
    }
    return sec.root;
  }
  if (list.length === 0) {
    sec.body.append(emptyState("No grants yet.", "Use the editor below to grant an agent capabilities on a project.", { icon: "grants" }));
    return sec.root;
  }
  for (const g of list) sec.body.append(grantCard(g.agent, g.project, g.ops, g.revoked, a));
  return sec.root;
}

function editorPanel(s: ShellState, a: GrantsActions): HTMLElement {
  const busy = a.busyAction === "grant_set";
  const c = card("Grant capabilities", {
    subtitle: "An agent's reveal never bypasses human approval: even with the grant, each agent reveal raises a pending approval a human must decide. Your own direct reveal needs no approval.",
  });
  const form = el("form", { autocomplete: "off" });

  const agents = s.agents ?? [];
  const projects = s.projects ?? [];
  const agentSel = el("select", { class: "select", "aria-label": "Agent" }) as HTMLSelectElement;
  for (const ag of agents) agentSel.append(el("option", { value: ag.name }, ag.name) as HTMLOptionElement);
  const projSel = el("select", { class: "select", "aria-label": "Project" }) as HTMLSelectElement;
  for (const p of projects) projSel.append(el("option", { value: p.name }, p.name) as HTMLOptionElement);
  if (agents.length === 0 || projects.length === 0) {
    agentSel.disabled = true;
    projSel.disabled = true;
  }
  const selRow = el("div", { class: "form-row" });
  selRow.append(el("span", { class: "lbl" }, "Agent"), agentSel, el("span", { class: "lbl" }, "Project"), projSel);
  // The pair IS the editor's target, so it is rendered before the capability
  // row and resolved from `a.pair`, not read back from the selectors: the
  // baseline must not depend on how the node answers before it is attached.
  // It stays in the app's form state for the same reason — a repaint would
  // otherwise revert the target to the first option of each list.
  const stored = a.pair;
  let agent = stored !== null && agents.some((ag) => ag.name === stored.agent) ? stored.agent : (agents[0]?.name ?? "");
  let project = stored !== null && projects.some((p) => p.name === stored.project) ? stored.project : (projects[0]?.name ?? "");
  agentSel.value = agent;
  projSel.value = project;
  form.append(selRow);

  const checks = el("div", { class: "checkrow" });
  const boxes: HTMLInputElement[] = [];
  for (const cap of CAPABILITIES) {
    const label = el("label", { class: "check" });
    const box = el("input", { type: "checkbox", class: "checkbox", value: cap }) as HTMLInputElement;
    boxes.push(box);
    label.append(box, el("span", {}, cap));
    if (RESERVED_CAPABILITIES[cap]) {
      label.append(el("span", { class: "cap-reserved", title: "The broker models and grants this, but no agent operation consumes it yet — management stays human-only." }, "reserved"));
    }
    checks.append(label);
  }
  // The capability names come from `CAPABILITIES`, indexed in step with the
  // boxes built from it: an editor whose baseline depended on reading an
  // `input.value` back out of the DOM during construction would be reading a
  // node that is not attached yet.
  const proposedOps = (): string[] => CAPABILITIES.filter((_, i) => boxes[i].checked);
  // Pre-check from the saved grant for the selected pair, when known.
  const syncFromSaved = (): void => {
    const saved = activeGrantOps(s, agent, project);
    boxes.forEach((box, i) => {
      box.checked = saved !== null && saved.indexOf(CAPABILITIES[i]) >= 0;
    });
    renderRunNote();
  };
  form.append(checks);

  const runNote = para("", "muted");
  runNote.setAttribute("data-run-note", "");
  const renderRunNote = (): void => {
    const saved = activeGrantOps(s, agent, project);
    runNote.textContent =
      saved !== null && grantRunRemoved(saved, proposedOps())
        ? "Removing `run` terminates this agent's active runs on this project."
        : "";
  };
  // A change re-syncs this screen at once and hands the pair to the app, which
  // owns it from then on: the baseline, the notes and any staged draft are
  // rebuilt from the new pair instead of being carried over from the old one.
  const choosePair = (): void => {
    agent = agentSel.value !== "" ? agentSel.value : agent;
    project = projSel.value !== "" ? projSel.value : project;
    syncFromSaved();
    a.onPairChange(agent, project);
  };
  agentSel.addEventListener("change", choosePair);
  projSel.addEventListener("change", choosePair);
  for (const box of boxes) box.addEventListener("change", renderRunNote);
  syncFromSaved();
  form.append(runNote);

  const btn = button(busy ? "Saving…" : "Save grant", {
    variant: "primary",
    type: "submit",
    disabled: busy || agents.length === 0 || projects.length === 0,
  });
  if (agents.length === 0 || projects.length === 0) {
    form.append(para("Agents or projects are not loaded yet — press Reload first. Selectors always come from the broker, never a built-in list.", "muted"));
  }
  form.append(btn);
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    if (!agent || !project) return;
    a.onSave(agent, project, proposedOps());
  });
  c.body.append(form);
  return c.root;
}

function draftConfirm(s: ShellState, a: GrantsActions): HTMLElement {
  const d = a.draft as GrantDraft;
  const saved = activeGrantOps(s, d.agent, d.project) ?? [];
  const added = d.ops.filter((c) => saved.indexOf(c) < 0);
  const widening = grantWidens(saved, d.ops);
  const sensitive = added.filter((c) => c === "manage" || c === "reveal");
  const c = card(`Confirm grant: ${d.agent} → ${d.project}`, {
    subtitle: `Capabilities after save: ${d.ops.length > 0 ? d.ops.join(", ") : "(none — grant holds no capabilities)"}.`,
    tone: widening ? (sensitive.length > 0 ? "warn" : "info") : undefined,
  });
  c.body.append(
    chipList(
      d.ops.map((cap) => ({ text: cap, tone: capabilityTone(cap) })),
      { empty: "No capabilities held." },
    ),
  );
  if (widening) {
    c.body.append(
      banner(
        "warn",
        sensitive.length > 0
          ? `This ADDS authority (${added.join(", ")}), including ${sensitive.join(", ")} — confirm this is intended.`
          : `This ADDS authority (${added.join(", ")}) — confirm this is intended.`,
      ),
    );
  } else {
    c.body.append(para("This only removes authority — no new capability is added.", "muted"));
  }
  if (grantRunRemoved(saved, d.ops)) {
    c.body.append(para("Removing `run` terminates this agent's active runs on this project.", "muted"));
  }
  const busy = a.busyAction === "grant_set";
  c.body.append(
    confirmBar(widening ? `Save widened grant for ${d.agent} → ${d.project}?` : `Save narrowed grant for ${d.agent} → ${d.project}?`, {
      busy,
      danger: widening,
      confirmLabel: busy ? "Saving…" : "Confirm save",
      onConfirm: () => a.onConfirmSave(),
      onCancel: () => a.onCancelConfirm(),
    }),
  );
  return c.root;
}

function grantCard(agent: string, project: string, ops: string[], revoked: boolean, a: GrantsActions): HTMLElement {
  const c = card(`${agent} → ${project}`, {
    tone: revoked ? undefined : ops.some((cap) => cap === "reveal" || cap === "manage") ? "warn" : undefined,
    actions: [revoked ? badge("revoked", "mute") : badge("active", "ok")],
  });
  if (ops.length === 0) {
    c.body.append(para("No capabilities held.", "muted"));
  } else {
    c.body.append(
      chipList(
        ops.map((cap) => ({
          text: cap,
          tone: capabilityTone(cap),
          title: RESERVED_CAPABILITIES[cap]
            ? "The broker models and grants this, but no agent operation consumes it yet — management stays human-only."
            : undefined,
        })),
        { empty: "No capabilities held." },
      ),
    );
    if (ops.some((cap) => RESERVED_CAPABILITIES[cap])) {
      const note = el("span", { class: "muted" }, "Includes ");
      note.append(chip("reserved", { tone: "warn", title: "The broker models and grants this, but no agent operation consumes it yet — management stays human-only." }));
      c.body.append(note);
    }
  }
  if (revoked) c.body.append(statusDot("bad", "revoked"));
  else c.body.append(statusDot("ok", "active"));
  const confirm = a.pendingConfirm;
  if (confirm && confirm.kind === "grant" && confirm.project === agent && confirm.extra === project) {
    const busy = a.busyAction === "grant_revoke";
    c.body.append(
      confirmBar("Revoking drops every capability this agent holds on this project. This cannot be undone — re-grant to restore.", {
        busy,
        danger: true,
        confirmLabel: busy ? "Revoking…" : "Confirm revoke",
        onConfirm: () => a.onRevoke(agent, project),
        onCancel: () => a.onCancelConfirm(),
      }),
    );
  } else {
    c.footer.append(
      button("Revoke…", { disabled: a.busyAction !== null, onClick: () => a.onRevoke(agent, project) }),
    );
  }
  return c.root;
}

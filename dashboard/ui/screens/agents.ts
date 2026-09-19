// Agents: broker-backed enroll / list / revoke over `agents_list` /
// `agent_add` / `agent_revoke`. No optimistic UI: after any mutation the
// list is re-read before render. The broker sends no created_at/last_seen,
// so none is shown.
//
// ONE-TIME TOKEN DISCIPLINE (security-critical):
// - The token lives ONLY in the submit handler's function-local scope (see
//   app.ts `onAgentEnroll`) and in the one node built by
//   `renderOneTimeToken` below.
// - It is NEVER stored in ShellState, any slice of it, module-level
//   variables, localStorage/sessionStorage, the URL/hash, logs, nor put on
//   the clipboard automatically.
// - Dismiss removes the node; any later full render drops it. Copy it now.

import {
  banner,
  button,
  card,
  chipList,
  codeBlock,
  confirmBar,
  el,
  emptyState,
  errorState,
  fieldGrid,
  loadingState,
  pageHeader,
  para,
  section,
  statusDot,
} from "../components.js";
import {
  agentStatusTone,
  capabilityTone,
  errorAdvice,
  projectsForAgent,
  type AgentAddResult,
  type MappedError,
  type PendingConfirm,
  type ShellState,
} from "../state.js";

export interface AgentsActions {
  busyAction: string | null;
  pendingConfirm: PendingConfirm | null;
  selected: string | null;
  onSelect: (name: string | null) => void;
  onEnroll: (name: string, tokenPath?: string) => void;
  onRevoke: (name: string) => void;
  onCancelConfirm: () => void;
  onReload: () => void;
  inlineError: MappedError | null;
}

/**
 * Pure, DOM-free twin of the enroll submit path, for tests: take the
 * one-time token out of an `agent_add` result for display. Returns it for
 * display (`shown`) and explicitly NOTHING to persist (`persisted` is always
 * null — there is no other output for a caller to stash in state).
 */
export function takeOneTimeToken(res: AgentAddResult): { shown: string; persisted: null } {
  if (!res || typeof res.token !== "string" || res.token.length === 0) {
    throw new Error("agent_add result carries no token");
  }
  return { shown: res.token, persisted: null };
}

/**
 * The single render of a one-time token. The caller holds `token` in a
 * function-local and drops it after this call; the node holds the only
 * other copy. No state, storage, URL, log, or clipboard write happens here.
 */
export function renderOneTimeToken(token: string, savedPath: string | null, onDismiss: () => void): HTMLElement {
  const box = el("section", { class: "card token-box" });
  box.setAttribute("data-onetime-token", "");
  box.append(el("h2", { class: "card-title" }, "Agent token — shown once"));
  box.append(banner("warn", "This token is shown once and cannot be recovered. Copy it now — dismissing or refreshing loses it forever."));
  box.append(codeBlock(token));
  if (savedPath) box.append(para("The broker also saved it to the file path you gave.", "muted"));
  box.append(button("Dismiss (drops the token)", { variant: "primary", onClick: () => onDismiss() }));
  return box;
}
export function renderAgents(root: HTMLElement, s: ShellState, a: AgentsActions): void {
  root.replaceChildren();
  const busyReload = a.busyAction === "agents_list";
  const reload = button(busyReload ? "Loading…" : "Reload", {
    disabled: a.busyAction !== null,
    onClick: () => a.onReload(),
  });
  const wrap = el("div", { class: "page" });
  wrap.append(
    pageHeader("Agents", {
      subtitle: "Enroll identities, inspect access, revoke.",
      actions: [reload],
    }),
  );

  if (s.sessionExpired) {
    wrap.append(banner("warn", "Your session expired — unlock again before managing agents."));
  }
  if (a.inlineError) {
    wrap.append(
      errorState(a.inlineError.message, errorAdvice(a.inlineError.code) ?? "", {
        code: a.inlineError.code,
        retry: [button("Reload", { disabled: a.busyAction !== null, onClick: () => a.onReload() })],
      }),
    );
  }

  wrap.append(enrollPanel(a));

  const list = s.agents;
  if (list === null) {
    if (busyReload) {
      wrap.append(loadingState("Loading agents…"));
    } else {
      wrap.append(
        emptyState("Agents not loaded", "Agent identities are not loaded yet — press Reload.", {
          icon: "agents",
          actions: [button("Reload", { disabled: a.busyAction !== null, onClick: () => a.onReload() })],
        }),
      );
    }
    root.append(wrap);
    return;
  }
  if (list.length === 0) {
    wrap.append(
      emptyState("No agents enrolled yet.", "Enroll the first agent above; its one-time token is shown once.", {
        icon: "agents",
      }),
    );
    root.append(wrap);
    return;
  }
  const split = el("div", { class: "master-detail" });
  split.append(agentMasterList(list.map((x) => ({ name: x.name, status: x.status })), a));
  split.append(agentDetail(s, a));
  wrap.append(split);
  root.append(wrap);
}

function agentMasterList(rows: Array<{ name: string; status: string }>, a: AgentsActions): HTMLElement {
  const list = el("div", { class: "master-list", role: "listbox", "aria-label": "Agents" });
  for (const row of rows) {
    const item = el("button", {
      type: "button",
      class: a.selected === row.name ? "master-item master-item-active" : "master-item",
      role: "option",
    });
    if (a.selected === row.name) item.setAttribute("aria-selected", "true");
    item.append(el("span", { class: "truncate" }, row.name));
    item.append(statusDot(agentStatusTone(row.status), row.status || "unknown"));
    item.addEventListener("click", () => a.onSelect(a.selected === row.name ? null : row.name));
    list.append(item);
  }
  return list;
}

function enrollPanel(a: AgentsActions): HTMLElement {
  const busy = a.busyAction === "agent_add";
  const c = card("Enroll agent", {
    subtitle: "The token is shown once after enrollment and cannot be recovered. Optionally give a file path and the broker will save it there — the dashboard itself never writes files.",
  });
  const form = el("form", { autocomplete: "off" });
  const nameInput = el("input", { type: "text", class: "input", placeholder: "Agent name", "aria-label": "Agent name" }) as HTMLInputElement;
  const pathInput = el("input", {
    type: "text",
    class: "input",
    placeholder: "Token file path (optional)",
    "aria-label": "Token file path (optional)",
  }) as HTMLInputElement;
  const btn = button(busy ? "Enrolling…" : "Enroll", { variant: "primary", type: "submit", disabled: busy });
  if (busy) {
    nameInput.disabled = true;
    pathInput.disabled = true;
  }
  const row = el("div", { class: "form-row" });
  row.append(nameInput, pathInput, btn);
  form.append(row);
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const name = nameInput.value.trim();
    const tokenPath = pathInput.value.trim();
    if (!name) {
      a.onEnroll("", undefined);
      return;
    }
    a.onEnroll(name, tokenPath ? tokenPath : undefined);
  });
  c.body.append(form);
  return c.root;
}

function agentDetail(s: ShellState, a: AgentsActions): HTMLElement {
  const wrap = el("div", { class: "detail" });
  const name = a.selected;
  const entry = name === null ? null : (s.agents ?? []).find((x) => x.name === name) ?? null;
  if (name === null || entry === null) {
    wrap.append(emptyState("Select an agent.", "Pick an agent on the left to inspect its identity, access, and revoke action.", { icon: "agents" }));
    return wrap;
  }
  const c = card(entry.name, {
    subtitle: "Agent identity",
    actions: [statusDot(agentStatusTone(entry.status), entry.status || "unknown")],
  });
  c.body.append(
    fieldGrid([
      ["Status", statusDot(agentStatusTone(entry.status), entry.status || "unknown")],
      ["Token prefix", codeBlock(entry.token_prefix || "—")],
    ]),
  );
  const projects = projectsForAgent(s, entry.name);
  // Honesty: `grants === null` means the grants list was never read, which is
  // NOT the same as "this agent holds nothing". Never render unknown as empty.
  const grantsKnown = s.grants !== null;
  const access = section("Projects with access", {
    subtitle: !grantsKnown
      ? "The grants list has not been read yet — this agent's access is unknown."
      : projects.length === 0
        ? "No live grant for this agent."
        : `${projects.length} project${projects.length === 1 ? "" : "s"} with live grants.`,
  });
  for (const p of projects) {
    const chips = p.ops.map((cap) => ({ text: cap, tone: capabilityTone(cap) }));
    const row = el("div", { class: "row" });
    row.append(el("span", { class: "truncate" }, p.project));
    row.append(chipList(chips, { empty: "No capabilities held." }));
    access.body.append(row);
  }
  if (!grantsKnown) {
    access.body.append(el("a", { class: "btn", href: "#/grants" }, "Load grants"));
  } else if (projects.length === 0) {
    access.body.append(para("No live grant for this agent.", "muted"));
  }
  c.body.append(access.root);
  const summary = section("Grants summary", {
    subtitle: !grantsKnown
      ? "Not loaded yet."
      : projects.length === 0
        ? "Nothing granted."
        : projects.map((p) => `${p.project} (${p.ops.length > 0 ? p.ops.join(", ") : "no capabilities"})`).join("; "),
  });
  c.body.append(summary.root);
  const confirm = a.pendingConfirm;
  if (confirm && confirm.kind === "agent" && confirm.project === entry.name) {
    const busy = a.busyAction === "agent_revoke";
    c.body.append(
      confirmBar("Revoking invalidates the agent's token, its leases, and terminates its active runs. This cannot be undone — the agent must be re-enrolled.", {
        busy,
        danger: true,
        confirmLabel: busy ? "Revoking…" : "Confirm revoke",
        onConfirm: () => a.onRevoke(entry.name),
        onCancel: () => a.onCancelConfirm(),
      }),
    );
  } else {
    c.footer.append(
      button("Revoke…", { variant: "danger", disabled: a.busyAction !== null, onClick: () => a.onRevoke(entry.name) }),
    );
  }
  wrap.append(c.root);
  return wrap;
}

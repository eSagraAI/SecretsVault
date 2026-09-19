// Overview: the control centre. Everything here comes from real broker data
// (`overview_refresh`) or a real slice — never a fabricated metric, never a
// verdict the broker did not send. Every counter the broker leaves null renders
// as "—" with a muted note, never 0; an unloaded slice says so instead of
// rendering an empty list as if it were the truth.
//
// Reading order is deliberate: what needs attention, then posture/health, then
// the live operational lists, then shortcuts. Actions are navigation (hash
// links) only — this screen performs no broker mutation of its own.

import {
  banner,
  card,
  chip,
  codeBlock,
  el,
  emptyState,
  fieldGrid,
  iconTextButton,
  loadingState,
  meter,
  pageHeader,
  para,
  section,
  stat,
  stats,
} from "../components.js";
import {
  agentStatusTone,
  approvalCountdown,
  attentionItems,
  fmtAuditUsage,
  fmtBytes,
  fmtCount,
  fmtRelative,
  fmtSecretsTotal,
  isPostureOnly,
  overviewHint,
  runStatusTone,
  sessionHeld,
  sessionText,
  showSessionCard,
  type OverviewData,
  type ShellState,
} from "../state.js";

export interface OverviewActions {
  onRefresh: () => void;
  busy: boolean;
}

function usageNote(known: boolean): string {
  return known ? "" : " (not reported — vault locked or broker silent)";
}

/**
 * Re-export of the single byte formatter in `state.ts`. Kept as a named
 * export because the D5 overview tests import it from this module.
 */
export { fmtBytes };

/** One honest posture/counter tile. Null counters render "—", never 0. */
function counter(label: string, value: string, known: boolean, route?: string): HTMLElement {
  return stat(label, known ? value : "—", route === undefined ? {} : { route });
}

/**
 * Posture + counters, all from the real payload. No "healthy"/"OK" verdicts:
 * the broker reports counts, not judgements.
 */
function posturePanel(o: OverviewData): { root: HTMLElement; body: HTMLElement } {
  const c = section("Vault activity", {
    subtitle: "Reported by the broker; counters the broker stayed silent on are unknown, not zero.",
  });
  const secretsLine =
    o.secrets_total === null ? "—" : fmtSecretsTotal(o.secrets_total, o.secrets_total_exact);

  const tiles = stats([
    counter("Broker", o.online ? (o.trusted ? "online, pinned" : "online, untrusted") : "offline", true),
    counter("Vault", o.locked ? "locked" : "unlocked", true),
    counter("Broker version", String(o.version), true),
    counter("Vault created", o.created || "—", o.created !== ""),
    counter("Projects", fmtCount(o.projects), o.projects !== null, "#/projects"),
    counter(
      "Secrets total",
      secretsLine + (o.secrets_total_exact ? "" : " (capped)"),
      o.secrets_total !== null,
      "#/secrets",
    ),
    counter("Active agents", fmtCount(o.agents_active), o.agents_active !== null, "#/agents"),
    counter("Pending approvals", fmtCount(o.approvals_pending), o.approvals_pending !== null, "#/approvals"),
    counter("Active runs", fmtCount(o.runs_active), o.runs_active !== null, "#/runs"),
    counter("Active leases", fmtCount(o.leases_active), o.leases_active !== null, "#/leases"),
    counter(
      "Idle-lock window",
      o.idle_lock_secs === null ? "—" : `${o.idle_lock_secs}s`,
      o.idle_lock_secs !== null,
    ),
    counter("Idle-lock in", o.idle_in === null ? "—" : `${o.idle_in}s`, o.idle_in !== null),
  ]);
  c.body.append(tiles);

  const auditKnown = o.audit_bytes !== null && o.audit_soft_limit !== null && o.audit_hard_limit !== null;
  c.body.append(
    fieldGrid([
      [
        "Secrets total",
        secretsLine +
          (o.secrets_total_exact ? "" : " (broker counted up to a cap)") +
          (o.secrets_total === null ? " (not reported)" : ""),
      ],
      ["Audit log", fmtAuditUsage(o.audit_bytes, o.audit_soft_limit, o.audit_hard_limit) + usageNote(auditKnown)],
      ["Vault file", o.vault_bytes === null ? "—" : fmtBytes(o.vault_bytes)],
      ["Vault max size", o.vault_max_bytes === null ? "—" : fmtBytes(o.vault_max_bytes)],
    ]),
  );
  if (o.vault_bytes !== null && o.vault_max_bytes !== null) {
    c.body.append(meter("Vault file", o.vault_bytes, o.vault_max_bytes));
  }
  if (o.audit_bytes !== null && o.audit_hard_limit !== null) {
    c.body.append(meter("Audit log", o.audit_bytes, o.audit_hard_limit));
  }
  return c;
}

/** Attention strip: actionable, tone-marked, each pointing at a real route. */
function attentionStrip(s: ShellState, nowMs: number): HTMLElement {
  const items = attentionItems(s, nowMs);
  const c = section("Needs attention", {
    subtitle: "Only what the loaded data actually shows.",
  });
  if (items.length === 0) {
    c.body.append(
      para("Nothing needs attention from the data currently loaded.", "muted"),
    );
    return c.root;
  }
  for (const item of items) {
    const link = el("a", { class: `card card-tone-${item.tone}`, href: item.route });
    const header = el("div", { class: "card-header" });
    header.append(el("h3", { class: "card-title" }, item.title));
    link.append(header);
    const body = el("div", { class: "card-body" });
    body.append(para(item.detail, "muted"));
    link.append(body);
    c.body.append(link);
  }
  return c.root;
}

/** Pending approvals, with a live countdown recomputed on every render. */
function approvalsPanel(s: ShellState): HTMLElement {
  const c = section("Pending approvals", { subtitle: "The value itself is never shown here." });
  const list = s.approvals;
  if (list === null) {
    // Filled by the existing visibility-gated 20 s approvals poll (each read
    // appends an audit entry, so this screen never reads it directly).
    c.body.append(para("The inbox has not been read yet — its count updates on the approvals poll.", "muted"));
    c.body.append(el("a", { class: "btn", href: "#/approvals" }, "Open Approvals"));
    return c.root;
  }
  if (list.length === 0) {
    c.body.append(para("Nothing pending — the broker reports no approvals awaiting a decision.", "muted"));
    return c.root;
  }
  const nowMs = Date.now();
  for (const e of list) {
    const row = el("div", { class: "field-grid" });
    row.append(
      el("span", { class: "field-label" }, `${e.agent} → ${e.project}`),
      chip(e.key, { tone: "warn", title: "Secret name — never the value." }),
    );
    const cd = approvalCountdown(e.expires_at, nowMs);
    row.append(el("span", { class: cd.expired ? "expiry expiry-done" : "expiry" }, cd.label));
    c.body.append(row);
  }
  c.body.append(el("a", { class: "btn", href: "#/approvals" }, "Review approvals"));
  return c.root;
}

/** Active runs — identity and status only, never argv/env/cwd. */
function runsPanel(s: ShellState): HTMLElement {
  const c = section("Active runs", {
    subtitle: "The dashboard never sends run signals.",
  });
  const list = s.runs;
  if (list === null) {
    // `runs.list` appends a broker audit entry per read, so the Overview never
    // reads it on its own: it points at the screen that does, on demand.
    c.body.append(
      para(
        "Run history is not read from here — opening the Runs screen loads it. The count above is whatever the broker already reported.",
        "muted",
      ),
    );
    c.body.append(el("a", { class: "btn", href: "#/runs" }, "Open Runs"));
    return c.root;
  }
  if (list.length === 0) {
    c.body.append(para("No runs — the broker reports none.", "muted"));
    return c.root;
  }
  for (const r of list) {
    const row = el("div", { class: "row" });
    row.append(
      el("span", { class: "mono truncate" }, r.run_id),
      el("span", {}, `${r.agent} → ${r.project}`),
      chip(r.status || "unknown", { tone: runStatusTone(r.status) }),
      el("span", { class: "muted" }, fmtRelative(r.started_at, Date.now())),
    );
    c.body.append(row);
  }
  c.body.append(el("a", { class: "btn", href: "#/runs" }, "All runs"));
  return c.root;
}

/** Active agents with their status, as reported. */
function agentsPanel(s: ShellState): HTMLElement {
  const c = section("Agents", { subtitle: "Identity and status only — never token material." });
  const list = s.agents;
  if (list === null) {
    c.body.append(para("Agent identities are not loaded yet.", "muted"));
    return c.root;
  }
  if (list.length === 0) {
    c.body.append(para("No agents enrolled yet.", "muted"));
    return c.root;
  }
  for (const a of list) {
    const row = el("div", { class: "row" });
    row.append(el("span", {}, a.name), chip(a.status || "unknown", { tone: agentStatusTone(a.status) }));
    c.body.append(row);
  }
  c.body.append(el("a", { class: "btn", href: "#/agents" }, "All agents"));
  return c.root;
}

/** Recent projects with their authorized-path counts. */
function projectsPanel(s: ShellState): HTMLElement {
  const c = section("Projects", { subtitle: "Authorized paths are managed per project." });
  const list = s.projects;
  if (list === null) {
    c.body.append(para("The project list is not loaded yet.", "muted"));
    return c.root;
  }
  if (list.length === 0) {
    c.body.append(para("The broker reports an empty project registry.", "muted"));
    return c.root;
  }
  for (const p of list) {
    const row = el("div", { class: "row" });
    row.append(el("span", {}, p.name));
    row.append(
      chip(`${p.paths.length} path${p.paths.length === 1 ? "" : "s"}`, { tone: p.paths.length === 0 ? "warn" : "mute" }),
    );
    c.body.append(row);
  }
  c.body.append(el("a", { class: "btn", href: "#/projects" }, "All projects"));
  return c.root;
}

function shortcuts(): HTMLElement {
  const c = section("Shortcuts", { subtitle: "Navigation only — nothing here calls the broker." });
  const row = el("div", { class: "toolbar" });
  row.append(
    el("a", { class: "btn btn-primary", href: "#/projects" }, "New project"),
    el("a", { class: "btn", href: "#/secrets" }, "New secret"),
    el("a", { class: "btn", href: "#/approvals" }, "Approvals"),
    el("a", { class: "btn", href: "#/grants" }, "Grants"),
    el("a", { class: "btn", href: "#/agents" }, "Agents"),
  );
  c.body.append(row);
  return c.root;
}

export function renderOverview(root: HTMLElement, s: ShellState, actions: OverviewActions): void {
  root.replaceChildren();
  const nowMs = Date.now();
  root.append(
    pageHeader("Overview", {
      subtitle: "Control centre — posture, work awaiting you, and the live surface.",
      actions: [
        iconTextButton("refresh", actions.busy ? "Refreshing…" : "Refresh", {
          disabled: actions.busy || s.conn === "offline",
          onClick: () => actions.onRefresh(),
        }),
      ],
    }),
  );

  if (s.sessionExpired) {
    root.append(banner("warn", "Your session expired — unlock again. It was not retried automatically."));
  }

  const o = s.overview;
  if (o !== null) {
    // Posture-only payload while the vault reads unlocked and the backend holds
    // no session: Refresh cannot help (human ops would fail), so say where the
    // session comes from instead of suggesting it. The signal is the same
    // sessionHeld() the hint uses — banner and hint agree.
    if (isPostureOnly(o) && s.status && !s.status.locked && !sessionHeld(s)) {
      root.append(banner("info", overviewHint(s)));
    }
    root.append(attentionStrip(s, nowMs));
    root.append(posturePanel(o).root);
    root.append(approvalsPanel(s));
    root.append(runsPanel(s));
    root.append(agentsPanel(s));
    root.append(projectsPanel(s));
    root.append(shortcuts());
  } else if (s.status) {
    // Posture known but no overview payload yet (locked, or refresh pending).
    const c = card("Status");
    c.body.append(
      fieldGrid([
        ["Broker", s.conn === "trusted" ? "online, pinned" : s.conn],
        ["Vault", s.status.locked ? "locked" : "unlocked"],
        ["Broker version", String(s.status.version)],
        ["Vault created", s.status.created || "—"],
      ]),
    );
    root.append(c.root);
    root.append(banner("info", overviewHint(s)));
    if (s.status.fingerprint) {
      const id = card("Broker identity");
      id.body.append(codeBlock(s.status.fingerprint));
      root.append(id.root);
    }
    root.append(attentionStrip(s, nowMs));
    root.append(shortcuts());
  } else if (actions.busy) {
    root.append(loadingState("Reading broker counts…"));
  } else {
    root.append(emptyState("Counts are not loaded yet", "Press Refresh to read the broker.", { icon: "refresh" }));
  }
  // The session card describes an unlock outcome: only when actually unlocked.
  // showSessionCard() is the single gate; ABSENT_SESSION text stays honest there.
  if (showSessionCard(s)) {
    const sess = card("Human session");
    // `data-session-live` marks the nodes the 1 s ticker refreshes in place.
    // The countdown must keep ticking, and doing that by re-rendering the whole
    // screen would destroy whatever the operator is typing on it.
    const countdown = para(sessionText(s.session, nowMs, s.unlockedAtMs));
    countdown.setAttribute("data-session-live", "countdown");
    sess.body.append(countdown);
    if (s.session.maxExpiresIn !== undefined && s.session.maxExpiresIn !== null) {
      const ceiling = para(`Absolute ceiling: about ${s.session.maxExpiresIn}s from mint.`, "muted");
      ceiling.setAttribute("data-session-live", "ceiling");
      sess.body.append(ceiling);
    }
    root.append(sess.root);
  }
}

// Shell bootstrap: sidebar + header/status bar + content outlet,
// hash router, global-state wiring, and refresh policy.
//
// Refresh policy (the only refresh triggers — no aggressive polling):
//   1. boot (initial load);
//   2. after every unlock/lock action completes (trust is CLI-only; the dashboard never writes a pin);
//   3. on hash-route change (posture + the entering route's data, one-shot);
//   4. manual Refresh button (Overview, Runs) / Reload (Projects, Secrets, Agents, Grants, Leases, Approvals);
//   5. after any successful mutation (re-read lists + overview counts before rendering);
//   6. the single slow timer (45 s), gated to trusted+unlocked+document-visible,
//      refreshing posture + health + overview only — never project/secret/agent/grant/approval/lease/run lists;
//   7. the single approvals timer (20 s), gated to trusted+unlocked+live-session+document-visible,
//      refreshing approvals_pending ONLY (each read appends an audit entry, so a
//      hidden window is never polled). The Projects/Secrets/Agents/Grants/Leases/Runs lists are never polled.
//   8. the single session ticker (1 s), gated to showSessionCard()+document-visible,
//      render-only — it performs no broker call, it only re-renders so the
//      session countdown ticks while its card can be showing.
import { renderMismatch, renderNoVault, renderUnlockGate, renderUntrusted } from "./screens/gates.js";
import * as api from "./api.js";
import { banner, el, iconButton, iconTextButton, para, pill, statusDot } from "./components.js";
import { dismissToasts, mountToasts, toast } from "./feedback.js";
import { icon } from "./icons.js";
import { closePalette, mountPalette, openPalette, paletteOpen, type PaletteCommand } from "./palette.js";
import { renderAgents, renderOneTimeToken, takeOneTimeToken } from "./screens/agents.js";
import { renderApprovals } from "./screens/approvals.js";
import { renderAudit } from "./screens/audit.js";
import { renderGrants } from "./screens/grants.js";
import { renderLeases } from "./screens/leases.js";
import { renderOverview } from "./screens/overview.js";
import { renderProjects } from "./screens/projects.js";
import { clearReveal, closeReveal, deliverRevealedValue, openRevealModal, revealFailed, takeRevealValue } from "./screens/reveal.js";
import { renderRuns } from "./screens/runs.js";
import { renderSettings } from "./screens/settings.js";
import { renderSecrets } from "./screens/secrets.js";
import {
  applyActiveProject,
  applyAgents,
  applyApprovals,
  applyAuditFilters,
  applyAuditFirstPage,
  applyAuditOlderPage,
  applyAuditVerify,
  applyBoot,
  applyError,
  applyGrants,
  applyLeases,
  applyLock,
  applyMutationDone,
  applyMutationStart,
  applyOverview,
  applyProjectTab,
  applyProjects,
  applyRuns,
  applySecrets,
  applySelectedAgent,
  applySelectedProject,
  applySettingsProbe,
  applyUnlockSuccess,
  AUDIT_PAGE_SIZE,
  approvalCount,
  activeGrantOps,
  auditHasOlder,
  clearAudit,
  errorAdvice,
  fatalStop,
  grantWidens,
  initialForms,
  initialState,
  needsUnlockGate,
  routeFor,
  ROUTES,
  sessionHeld,
  sessionText,
  showSessionCard,
  unlockGateReason,
  type AuditFilters,
  type GrantDraft,
  type MappedError,
  type ProjectTab,
  type RouteId,
  type SecretForm,
  type ShellState,
} from "./state.js";

const SLOW_TICK_MS = 45_000;
const APPROVALS_TICK_MS = 20_000;
const SESSION_TICK_MS = 1_000;

let s: ShellState = initialState();
let busy = false;
let overviewBusy = false;
let unlockFailure: string | null = null;
let probed: string | null = null;
let probeError: string | null = null;
let projectsError: MappedError | null = null;
let secretsError: MappedError | null = null;
let agentsError: MappedError | null = null;
let grantsError: MappedError | null = null;
let approvalsError: MappedError | null = null;
let leasesError: MappedError | null = null;
let runsError: MappedError | null = null;
let auditError: MappedError | null = null;
let settingsError: MappedError | null = null;
let slowTimer: number | null = null;
let approvalsTimer: number | null = null;
let sessionTimer: number | null = null;
/**
 * True while the user has edited something inside the outlet since the last
 * explicit render. Background ticks never repaint a touched outlet: a repaint
 * that destroys a half-typed secret value or the focus in a form is never an
 * acceptable cost for a countdown or a poll.
 */
let outletTouched = false;
// One-time agent token display: the token STRING lives only in the enroll
// handler's closure (which builds the node, then returns) and in the single
// DOM node below — never in ShellState, storage, URL, logs, or the
// clipboard. This binding holds the displayed ELEMENT (the render itself),
// not the string, so re-renders can keep showing it until dismissed.
// ponytail: one module-level Element ref so the stateless render can keep the
// one-time node visible until dismiss/lock/unlock; cleared on every full
// state transition — stashing the string itself here would break the discipline.
let oneTimeTokenNode: HTMLElement | null = null;
// Terminal approve/deny outcomes by approval id (from the mutation
// response), shown honestly when the broker no longer lists the entry.
const decidedApprovals = new Map<string, string>();
/**
 * Terminal approve/deny outcomes we produced, keyed by approval id, so a row
 * the broker no longer lists can still be reported honestly. Bounded: an
 * unlocked session can decide an unbounded number of approvals, so the oldest
 * entries are dropped past the cap (only the newest outcomes can still be on
 * screen — the inbox is re-read after every decision).
 */
const DECIDED_APPROVALS_CAP = 100;
function rememberDecidedApproval(id: string, status: string): void {
  decidedApprovals.delete(id);
  decidedApprovals.set(id, status);
  while (decidedApprovals.size > DECIDED_APPROVALS_CAP) {
    const oldest = decidedApprovals.keys().next();
    if (oldest.done === true) break;
    decidedApprovals.delete(oldest.value);
  }
}
/**
 * Return-to-reveal navigation target. Set by onReturnToReveal, consumed by
 * the secrets branch of renderOutlet: opening the modal is deferred to the
 * render so a hash navigation (#/approvals → #/secrets) cannot wipe a
 * just-opened modal via the route-change clear. Names only — never a value.
 */
let pendingRevealOpen: { project: string; key: string } | null = null;
let sidebarCollapsed = false;
let toastHost!: HTMLElement;
let paletteHost!: HTMLElement;
let topbarEl!: HTMLElement;
let shellEl!: HTMLElement;
let gPrefixAt = 0;
let sidebarEl!: HTMLElement;
let outletEl!: HTMLElement;
let lockBtn!: HTMLButtonElement;
/**
 * Shared tail for any failed broker call. Applies the error (including the
 * E_SESSION_EXPIRED escalation, which clears the local session slice and
 * forces the unlock gate) and routes an expired session back to the gate.
 * Returns true when the session expired. Never retries the failed call.
 * THE single wipe for the reveal value on session expiry: any
 * E_SESSION_EXPIRED reaching here clears the modal's value with the session.
 */
function noteCallError(e: unknown): boolean {
  const hadSession = s.session.present;
  s = applyError(s, e);
  if (s.sessionExpired) {
    // Only a session this app actually held can have expired. Launching against
    // a vault another process unlocked produces the same code from the broker's
    // "no session" refusal, and claiming an expiry there would assert a security
    // event that never happened. The gate's own copy covers the no-session case.
    unlockFailure = hadSession ? "Your session expired — unlock again." : null;
    clearReveal();
    dismissToasts();
    if (window.location.hash !== "#/") window.location.hash = "#/";
    return true;
  }
  // A revealed value must not outlive the posture that justified showing it.
  if (s.conn === "offline" || s.fatal !== null) clearReveal();
  return false;
}
/** The mapped error for the just-failed call: the object, not a formatted string. */
function callError(): MappedError {
  return s.error ?? { code: "E_UNKNOWN", message: "Request failed." };
}

/** Drop the one-time token node, if live. The string copy dies with the node. */
function dropOneTimeToken(): void {
  oneTimeTokenNode?.remove();
  oneTimeTokenNode = null;
}
async function refreshPosture(): Promise<void> {
  const [status, pin] = await Promise.all([api.getStatus(), api.pinStatus()]);
  s = applyBoot(s, status, pin);
  if (s.conn !== "trusted" || s.status?.locked) {
    // Last-known broker data is stale now: drop the D2/D3/D4 slices and forms.
    // The expiry flag is moot while locked — the gate is purely locked-based there.
    s = {
      ...s,
      session: { present: false },
      unlockedAtMs: 0,
      health: null,
      sessionExpired: false,
      overview: null,
      projects: null,
      selectedProject: null,
      projectTab: "overview",
      activeProject: null,
      secrets: null,
      agents: null,
      selectedAgent: null,
      grants: null,
      approvals: null,
      leases: null,
      runs: null,
      forms: initialForms(),
    };
    dropOneTimeToken();
    clearReveal();
    decidedApprovals.clear();
  }
  s = { ...s, error: null };
  projectsError = null;
  secretsError = null;
  agentsError = null;
  grantsError = null;
  approvalsError = null;
  leasesError = null;
  runsError = null;
  auditError = null;
  settingsError = null;
  armSlowTimer();
  armApprovalsTimer();
  armSessionTimer();
}

/** One overview_refresh read. Runs whenever trusted (locked reads report null counters, honestly). */
async function refreshOverviewData(): Promise<void> {
  if (s.conn !== "trusted") return;
  try {
    s = applyOverview(s, await api.overviewRefresh());
  } catch (e) {
    noteCallError(e);
  }
}

async function refreshAll(): Promise<void> {
  await refreshPosture();
  if (s.conn === "trusted" && s.status && !s.status.locked && !s.sessionExpired) {
    try {
      s.health = await api.health();
    } catch (e) {
      noteCallError(e);
    }
  }
  await refreshOverviewData();
  armSlowTimer();
  armApprovalsTimer();
  armSessionTimer();
}
/** One projects_list read. Sets the busy marker synchronously; the caller renders. */
function loadProjectsList(): Promise<void> {
  if (s.conn !== "trusted" || !s.status || s.status.locked || s.sessionExpired) return Promise.resolve();
  s = { ...s, forms: { ...s.forms, busyAction: "projects_list" } };
  return (async () => {
    try {
      const res = await api.projectsList();
      s = applyProjects(s, res.projects);
    } catch (e) {
      s = applyMutationDone(s);
      if (!noteCallError(e)) projectsError = callError();
      return;
    }
    s = applyMutationDone(s);
  })();
}

/** One secrets_list read for the active project. Sets the busy marker synchronously; the caller renders. */
function loadSecretsList(): Promise<void> {
  const active = s.activeProject;
  if (s.conn !== "trusted" || !s.status || s.status.locked || s.sessionExpired || active === null) {
    return Promise.resolve();
  }
  s = { ...s, forms: { ...s.forms, busyAction: "secrets_list" } };
  return (async () => {
    try {
      const res = await api.secretsList(active);
      s = applySecrets(s, active, res.secrets);
    } catch (e) {
      s = applyMutationDone(s);
      if (!noteCallError(e)) secretsError = callError();
      return;
    }
    s = applyMutationDone(s);
  })();
}

 /** One agents_list read. Sets the busy marker synchronously; the caller renders. */
function loadAgentsList(): Promise<void> {
  if (s.conn !== "trusted" || !s.status || s.status.locked || s.sessionExpired) return Promise.resolve();
  s = { ...s, forms: { ...s.forms, busyAction: "agents_list" } };
  return (async () => {
    try {
      const res = await api.agentsList();
      s = applyAgents(s, res.agents);
    } catch (e) {
      s = applyMutationDone(s);
      if (!noteCallError(e)) agentsError = callError();
      return;
    }
    s = applyMutationDone(s);
  })();
}

/** One grants_list read. Sets the busy marker synchronously; the caller renders. */
function loadGrantsList(): Promise<void> {
  if (s.conn !== "trusted" || !s.status || s.status.locked || s.sessionExpired) return Promise.resolve();
  s = { ...s, forms: { ...s.forms, busyAction: "grants_list" } };
  return (async () => {
    try {
      const res = await api.grantsList();
      s = applyGrants(s, res.grants);
    } catch (e) {
      s = applyMutationDone(s);
      if (!noteCallError(e)) grantsError = callError();
      return;
    }
    s = applyMutationDone(s);
  })();
}

/** One leases_list read. Sets the busy marker synchronously; the caller renders. */
function loadLeasesList(): Promise<void> {
  if (s.conn !== "trusted" || !s.status || s.status.locked || s.sessionExpired) return Promise.resolve();
  return (async () => {
    try {
      const res = await api.leasesList();
      s = applyLeases(s, res.leases);
    } catch (e) {
      s = applyMutationDone(s);
      if (!noteCallError(e)) leasesError = callError();
      return;
    }
    s = applyMutationDone(s);
  })();
}

/** One runs_list read. Sets the busy marker synchronously; the caller renders. */
function loadRunsList(): Promise<void> {
  if (s.conn !== "trusted" || !s.status || s.status.locked || s.sessionExpired) return Promise.resolve();
  s = { ...s, forms: { ...s.forms, busyAction: "runs_list" } };
  return (async () => {
    try {
      const res = await api.runsList();
      s = applyRuns(s, res.runs);
    } catch (e) {
      s = applyMutationDone(s);
      if (!noteCallError(e)) runsError = callError();
      return;
    }
    s = applyMutationDone(s);
  })();
}

/** Whether an audit read may run at all: needs the trusted posture, an unlocked vault, and a live session. */
export function auditLoadEligible(
  conn: string,
  locked: boolean | null,
  sessionExpired: boolean,
): boolean {
  return conn === "trusted" && locked === false && !sessionExpired;
}

/**
 * One audit page. `beforeSeq` undefined = the NEWEST page (a reload/replace);
 * some = the next older page (an append). Demand-driven by construction: the
 * broker appends one entry per read, so this is never called from a timer.
 */
function loadAuditPage(beforeSeq?: number): Promise<void> {
  if (!auditLoadEligible(s.conn, s.status ? s.status.locked : null, s.sessionExpired)) {
    return Promise.resolve();
  }
  s = { ...s, forms: { ...s.forms, busyAction: "audit_show" } };
  return (async () => {
    try {
      const page =
        beforeSeq === undefined
          ? await api.auditShow(AUDIT_PAGE_SIZE)
          : await api.auditShow(AUDIT_PAGE_SIZE, beforeSeq);
      s = beforeSeq === undefined ? applyAuditFirstPage(s, page) : applyAuditOlderPage(s, page);
    } catch (e) {
      s = applyMutationDone(s);
      if (!noteCallError(e)) auditError = callError();
      return;
    }
    s = applyMutationDone(s);
  })();
}

/**
 * One audit.verify walk. Never mutates the log; a structural/HMAC/checkpoint
 * failure arrives as `E_VAULT_CORRUPT` and is surfaced as-is — a verification
 * failure must never be swallowed or cleared by a later success.
 */
function loadAuditVerify(): Promise<void> {
  if (!auditLoadEligible(s.conn, s.status ? s.status.locked : null, s.sessionExpired)) {
    return Promise.resolve();
  }
  s = { ...s, forms: { ...s.forms, busyAction: "audit_verify" } };
  return (async () => {
    try {
      s = applyAuditVerify(s, await api.auditVerify());
    } catch (e) {
      s = applyMutationDone(s);
      if (!noteCallError(e)) auditError = callError();
      return;
    }
    s = applyMutationDone(s);
  })();
}

/** Re-read the Settings inputs: posture + pin + the broker's real health. */
function loadSettingsData(): Promise<void> {
  s = { ...s, forms: { ...s.forms, busyAction: "settings_refresh" } };
  return (async () => {
    try {
      const [status, pin] = await Promise.all([api.getStatus(), api.pinStatus()]);
      s = applyBoot(s, status, pin);
      if (s.conn === "trusted" && s.status && !s.status.locked && !s.sessionExpired) {
        try {
          s = { ...s, health: await api.health() };
        } catch (e) {
          if (noteCallError(e)) return;
        }
      }
    } catch (e) {
      s = applyMutationDone(s);
      if (!noteCallError(e)) settingsError = callError();
      return;
    }
    s = applyMutationDone(s);
  })();
}

/**
 * The credential-free live fingerprint probe. DISPLAY ONLY: the result is kept
 * in the settings slice for comparison against the pin. The dashboard has no
 * pin-write path and this call writes no credential bytes.
 */
function loadSettingsProbe(): Promise<void> {
  s = { ...s, forms: { ...s.forms, busyAction: "probe_fingerprint" } };
  return (async () => {
    try {
      const out = await api.probeFingerprint();
      s = applySettingsProbe(s, out.fingerprint, Date.now());
    } catch (e) {
      s = applyMutationDone(s);
      if (!noteCallError(e)) settingsError = callError();
      return;
    }
    s = applyMutationDone(s);
  })();
}

/**
 * One approvals_pending read (also the approvals-timer body). Each read
 * appends an audit entry broker-side, so callers MUST gate on visibility.
 */
function loadApprovalsList(): Promise<void> {
  if (s.conn !== "trusted" || !s.status || s.status.locked || s.sessionExpired) return Promise.resolve();
  s = { ...s, forms: { ...s.forms, busyAction: "approvals_pending" } };
  return (async () => {
    try {
      const res = await api.approvalsPending();
      s = applyApprovals(s, res.approvals);
    } catch (e) {
      s = applyMutationDone(s);
      if (!noteCallError(e)) approvalsError = callError();
      return;
    }
    s = applyMutationDone(s);
  })();
}

/** One-shot data load for the entering route. Never a poll: called on route enter, boot, and unlock only. */
function loadRouteData(route: RouteId): Promise<void> {
  if (route === "overview") {
    return (async () => {
      await refreshOverviewData();
      // The Overview control centre shows projects/agents/leases from the same
      // one-shot reads the dedicated screens use — never polled. Each of those
      // reads appends ONE audit entry (project.list, agents.list and lease.list
      // all audit an Allowed record; docs/dashboard-op-inventory.md §3), which
      // is why they run once per overview load and never on a timer.
      // `approvals.pending` and `runs.list` also append per read, so they are
      // deliberately NOT read here: the approvals panel fills from the existing
      // visibility-gated 20 s poll, and the runs panel links to its own screen.
      if (s.projects === null) await loadProjectsList();
      if (s.agents === null) await loadAgentsList();
      if (s.leases === null) await loadLeasesList();
    })();
  }
  if (route === "projects") {
    if (s.projects === null) return loadProjectsList();
    return Promise.resolve();
  }
  if (route === "secrets") {
    return (async () => {
      if (s.projects === null) await loadProjectsList();
      if (s.secrets === null) await loadSecretsList();
    })();
  }
  if (route === "agents") {
    if (s.agents === null) return loadAgentsList();
    return Promise.resolve();
  }
  if (route === "grants") {
    return (async () => {
      if (s.projects === null) await loadProjectsList();
      if (s.agents === null) await loadAgentsList();
      if (s.grants === null) await loadGrantsList();
    })();
  }
  if (route === "leases") {
    if (s.leases === null) return loadLeasesList();
    return Promise.resolve();
  }
  if (route === "approvals") {
    if (s.approvals === null) return loadApprovalsList();
    return Promise.resolve();
  }
  if (route === "runs") {
    if (s.runs === null) return loadRunsList();
    return Promise.resolve();
  }
  if (route === "audit") return loadAuditPage();
  if (route === "settings") return loadSettingsData();
  return Promise.resolve();
}

/**
 * Run a Projects mutation, then re-read the list (and overview counts)
 * before rendering the result. No optimistic inserts: the list is only ever
 * rendered from a fresh projects_list. If the mutation succeeded but the
 * re-read failed, the UI says so instead of showing stale rows as fresh.
 */
async function mutateProjects(action: string, call: () => Promise<unknown>): Promise<void> {
  s = applyMutationStart(s, action);
  projectsError = null;
  render();
  try {
    await call();
  } catch (e) {
    s = applyMutationDone(s);
    if (!noteCallError(e)) {
      projectsError = callError();
    }
    render();
    return;
  }
  try {
    const res = await api.projectsList();
    s = applyProjects(s, res.projects);
  } catch (e) {
    s = applyMutationDone(s);
    if (!noteCallError(e)) {
      { const cause = callError(); projectsError = { code: cause.code, message: `Saved, but the fresh list could not be read (${cause.code}: ${cause.message}) — shown data may be stale.` }; }
    }
    render();
    return;
  }
  try {
    s = applyOverview(s, await api.overviewRefresh());
  } catch (e) {
    if (!noteCallError(e)) {
      { const cause = callError(); projectsError = { code: cause.code, message: `Saved and the list is fresh, but counts could not be refreshed (${cause.code}: ${cause.message}).` }; }
    }
    s = applyMutationDone(s);
    render();
    return;
  }
  s = applyMutationDone(s);
  toast("success", "Project saved — list and counts re-read.");
  render();
}

// Same contract as mutateProjects, for one project's secret keys.
async function mutateSecrets(action: string, project: string, call: () => Promise<unknown>): Promise<void> {
  s = applyMutationStart(s, action);
  secretsError = null;
  render();
  try {
    await call();
  } catch (e) {
    s = applyMutationDone(s);
    if (!noteCallError(e)) {
      secretsError = callError();
    }
    render();
    return;
  }
  try {
    const res = await api.secretsList(project);
    s = applySecrets(s, project, res.secrets);
  } catch (e) {
    s = applyMutationDone(s);
    if (!noteCallError(e)) {
      { const cause = callError(); secretsError = { code: cause.code, message: `Saved, but the fresh keys could not be read (${cause.code}: ${cause.message}) — shown data may be stale.` }; }
    }
    render();
    return;
  }
  try {
    s = applyOverview(s, await api.overviewRefresh());
  } catch (e) {
    if (!noteCallError(e)) {
      { const cause = callError(); secretsError = { code: cause.code, message: `Saved and the keys are fresh, but counts could not be refreshed (${cause.code}: ${cause.message}).` }; }
    }
    s = applyMutationDone(s);
    render();
    return;
  }
  s = applyMutationDone(s);
  toast("success", "Secret saved — keys and counts re-read.");
  render();
}

// Same contract as mutateProjects, for the agent registry. Enroll is
// special-cased at the handler (not here): the one-time token must bypass
// state, so onAgentEnroll runs its own call + re-read sequence.
async function mutateAgents(action: string, call: () => Promise<unknown>): Promise<void> {
  s = applyMutationStart(s, action);
  agentsError = null;
  render();
  try {
    await call();
  } catch (e) {
    s = applyMutationDone(s);
    if (!noteCallError(e)) {
      agentsError = callError();
    }
    render();
    return;
  }
  try {
    const res = await api.agentsList();
    s = applyAgents(s, res.agents);
  } catch (e) {
    s = applyMutationDone(s);
    if (!noteCallError(e)) {
      { const cause = callError(); agentsError = { code: cause.code, message: `Saved, but the fresh agents could not be read (${cause.code}: ${cause.message}) — shown data may be stale.` }; }
    }
    render();
    return;
  }
  try {
    s = applyOverview(s, await api.overviewRefresh());
  } catch (e) {
    if (!noteCallError(e)) {
      { const cause = callError(); agentsError = { code: cause.code, message: `Saved and the agents are fresh, but counts could not be refreshed (${cause.code}: ${cause.message}).` }; }
    }
    s = applyMutationDone(s);
    render();
    return;
  }
  s = applyMutationDone(s);
  toast("success", "Agent change saved — registry and counts re-read.");
  render();
}

// Same contract as mutateProjects, for the agent × project grant matrix.
async function mutateGrants(action: string, call: () => Promise<unknown>): Promise<void> {
  s = applyMutationStart(s, action);
  grantsError = null;
  render();
  try {
    await call();
  } catch (e) {
    s = applyMutationDone(s);
    if (!noteCallError(e)) {
      grantsError = callError();
    }
    render();
    return;
  }
  try {
    const res = await api.grantsList();
    s = applyGrants(s, res.grants);
  } catch (e) {
    s = applyMutationDone(s);
    if (!noteCallError(e)) {
      { const cause = callError(); grantsError = { code: cause.code, message: `Saved, but the fresh grants could not be read (${cause.code}: ${cause.message}) — shown data may be stale.` }; }
    }
    render();
    return;
  }
  s = applyMutationDone(s);
  toast("success", "Grant saved — grants re-read.");
  render();
}

// Same contract as mutateProjects, for the live lease list: after a revoke,
// re-read leases_list before rendering. Never optimistic.
async function mutateLeases(action: string, call: () => Promise<unknown>): Promise<void> {
  s = applyMutationStart(s, action);
  leasesError = null;
  render();
  try {
    await call();
  } catch (e) {
    s = applyMutationDone(s);
    if (!noteCallError(e)) {
      leasesError = callError();
    }
    render();
    return;
  }
  try {
    const res = await api.leasesList();
    s = applyLeases(s, res.leases);
  } catch (e) {
    s = applyMutationDone(s);
    if (!noteCallError(e)) {
      { const cause = callError(); leasesError = { code: cause.code, message: `Revoked, but the fresh leases could not be read (${cause.code}: ${cause.message}) — shown data may be stale.` }; }
    }
    render();
    return;
  }
  try {
    s = applyOverview(s, await api.overviewRefresh());
  } catch (e) {
    if (!noteCallError(e)) {
      { const cause = callError(); leasesError = { code: cause.code, message: `Revoked and the leases are fresh, but counts could not be refreshed (${cause.code}: ${cause.message}).` }; }
    }
    s = applyMutationDone(s);
    render();
    return;
  }
  s = applyMutationDone(s);
  toast("success", "Lease revoked — leases and counts re-read.");
  render();
}

/**
 * Same no-optimism contract for the HITL inbox: after approve/deny, re-read
 * approvals_pending before rendering. Records the broker's terminal status
 * for the decided id so the UI can say so honestly when the entry is gone.
 */
async function mutateApprovals(
  action: string,
  call: () => Promise<{ approval_id: string; status: string }>,
): Promise<void> {
  s = applyMutationStart(s, action);
  approvalsError = null;
  render();
  try {
    const res = await call();
    rememberDecidedApproval(res.approval_id, res.status);
  } catch (e) {
    s = applyMutationDone(s);
    if (!noteCallError(e)) {
      approvalsError = callError();
    }
    render();
    return;
  }
  try {
    const res = await api.approvalsPending();
    s = applyApprovals(s, res.approvals);
  } catch (e) {
    s = applyMutationDone(s);
    if (!noteCallError(e)) {
      { const cause = callError(); approvalsError = { code: cause.code, message: `Decided, but the fresh inbox could not be read (${cause.code}: ${cause.message}) — shown data may be stale.` }; }
    }
    render();
    return;
  }
  s = applyMutationDone(s);
  toast("success", "Approval decided — inbox re-read.");
  render();
}

function armSlowTimer(): void {
  if (slowTimer !== null) {
    window.clearInterval(slowTimer);
    slowTimer = null;
  }
  const eligible =
    s.conn === "trusted" && s.status !== null && !s.status.locked && document.visibilityState === "visible";
  if (!eligible) return;
  slowTimer = window.setInterval(() => {
    if (document.visibilityState !== "visible") return;
    if (s.conn !== "trusted" || !s.status || s.status.locked) {
      armSlowTimer();
      return;
    }
    void refreshAll()
      .catch(() => undefined)
      .then(() => pollRepaint());
  }, SLOW_TICK_MS);
}

/** Whether the approvals-only poll may run: trusted + unlocked + live session + visible. */
export function approvalsPollEligible(
  conn: string,
  locked: boolean | null,
  session: boolean,
  visible: boolean,
): boolean {
  return conn === "trusted" && locked === false && session && visible;
}

function currentApprovalsEligible(): boolean {
  return approvalsPollEligible(
    s.conn,
    s.status ? s.status.locked : null,
    sessionHeld(s),
    typeof document === "undefined" ? false : document.visibilityState === "visible",
  );
}

/**
 * The single approvals-only timer (20 s). Refreshes approvals_pending and
 * nothing else — never agents, grants, projects, secrets or overview.
 * While the window is hidden the poll is skipped entirely (each read
 * appends a broker audit entry, so polling hidden would pour junk into the
 * tamper-evident log); on becoming visible, one immediate refresh runs.
 * The badge updates from the poll even when the route is not approvals.
 */
function armApprovalsTimer(): void {
  if (approvalsTimer !== null) {
    window.clearInterval(approvalsTimer);
    approvalsTimer = null;
  }
  if (!currentApprovalsEligible()) return;
  approvalsTimer = window.setInterval(() => {
    if (!currentApprovalsEligible()) return;
    void loadApprovalsList()
      .catch(() => undefined)
      .then(() => pollRepaint());
  }, APPROVALS_TICK_MS);
}

/**
 * The single session ticker (1 s). Unlike the slow and approvals timers it
 * performs NO broker call: it refreshes the chrome and the live session
 * countdown nodes in place. It never rebuilds the outlet while the user has
 * something in flight (see `outletTouched`) — typing the passphrase into the
 * session-expired gate must not be interrupted by a countdown.
 * Armed only when showSessionCard() holds and the document is visible;
 * single-instance like the other timers.
 */
function armSessionTimer(): void {
  if (sessionTimer !== null) {
    window.clearInterval(sessionTimer);
    sessionTimer = null;
  }
  if (typeof document !== "undefined" && document.visibilityState !== "visible") return;
  if (!showSessionCard(s)) return;
  sessionTimer = window.setInterval(() => {
    if (document.visibilityState !== "visible") return;
    if (!showSessionCard(s)) {
      armSessionTimer();
      return;
    }
    sessionTick();
  }, SESSION_TICK_MS);
}

function onApprovalsVisibility(): void {
  armSlowTimer();
  armApprovalsTimer();
  armSessionTimer();
  if (document.visibilityState !== "visible" || !currentApprovalsEligible()) {
    renderChrome();
    return;
  }
  const p = loadApprovalsList();
  renderChrome();
  void p.then(() => pollRepaint());
}

function currentRoute(): RouteId {
  return routeFor(window.location.hash);
}

function buildChrome(): void {
  const app = document.getElementById("app");
  if (!app) throw new Error("missing #app outlet in index.html");
  app.replaceChildren();

  shellEl = el("div", { class: "shell" });
  sidebarEl = el("nav", { class: "sidebar", "aria-label": "Sections" });
  const main = el("div", { class: "main" });
  topbarEl = el("header", { class: "topbar" });
  outletEl = el("main", { class: "outlet", id: "outlet" });
  // Any edit inside the outlet marks the screen touched: a background tick then
  // never rebuilds it, so typed text, a selection, focus and an open form
  // survive every repaint. Only an explicit render() (submit, cancel, route
  // change, lock/unlock, Refresh) clears the mark.
  const markTouched = (): void => {
    outletTouched = true;
  };
  outletEl.addEventListener("input", markTouched, true);
  outletEl.addEventListener("change", markTouched, true);
  // Focus alone counts as in flight: a repaint would drop the caret out of an
  // empty field the operator just clicked into.
  outletEl.addEventListener(
    "focusin",
    (ev) => {
      const target = ev.target as HTMLElement | null;
      if (target !== null && (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.tagName === "SELECT")) {
        markTouched();
      }
    },
    true,
  );
  main.append(topbarEl, outletEl);
  shellEl.append(sidebarEl, main);
  toastHost = el("div", { "aria-label": "Notifications" });
  paletteHost = el("div", { "aria-label": "Command palette host" });
  shellEl.append(toastHost, paletteHost);
  app.append(shellEl);
  mountToasts(toastHost);
  mountPalette(paletteHost, () => paletteCommands());
}

const NAV_SECTIONS: Array<{ title: string; ids: RouteId[] }> = [
  { title: "Operate", ids: ["overview", "approvals", "runs"] },
  { title: "Configure", ids: ["projects", "secrets", "agents", "grants", "leases"] },
  { title: "Inspect", ids: ["audit", "settings"] },
];
const ROUTE_ICONS: Record<RouteId, "overview" | "projects" | "secrets" | "agents" | "grants" | "leases" | "approvals" | "runs" | "audit" | "settings"> = {
  overview: "overview",
  projects: "projects",
  secrets: "secrets",
  agents: "agents",
  grants: "grants",
  leases: "leases",
  approvals: "approvals",
  runs: "runs",
  audit: "audit",
  settings: "settings",
};
const ROUTE_KBD: Record<RouteId, string> = {
  overview: "g o",
  projects: "g p",
  secrets: "g s",
  agents: "g a",
  grants: "g g",
  leases: "g l",
  approvals: "g v",
  runs: "g n",
  audit: "g u",
  settings: "g t",
};
function navItem(route: RouteId, current: RouteId, pending: number | null): HTMLAnchorElement {
  const meta = ROUTES.find((r) => r.id === route);
  const label = meta ? meta.label : route;
  const hash = meta ? meta.hash : "#/";
  const link = el("a", { class: `nav-item${route === current ? " nav-item-active" : ""}`, href: hash }, "") as HTMLAnchorElement;
  if (route === current) link.setAttribute("aria-current", "page");
  link.setAttribute("title", `${label} (${ROUTE_KBD[route]})`);
  const ic = el("span", { class: "nav-item-icon", "aria-hidden": "true" });
  ic.append(icon(ROUTE_ICONS[route]));
  link.append(ic, el("span", { class: "nav-item-label" }, label));
  // Global approvals badge: unknown (null) renders as nothing — never a
  // fabricated 0; 0 renders as nothing; >0 renders a prominent badge.
  // Updates from the approvals-only poll even off-route.
  if (route === "approvals" && pending !== null && pending > 0) {
    link.append(el("span", { class: `nav-item-badge${pending > 0 ? " nav-item-badge-hot" : ""}` }, String(pending)));
  }
  link.append(el("span", { class: "nav-item-kbd" }, ROUTE_KBD[route]));
  return link;
}
/**
 * The broker reachability dot, as one derivation shared by the sidebar strip
 * and the topbar so they can never disagree.
 *
 * With no status payload nothing has been observed yet, so "starting" is
 * honest — EXCEPT when the posture is already known to be offline, which is
 * precisely the failure that leaves `status` null. Rendering "starting" beside
 * an "offline" posture (observed in D7 whenever the bridge is absent or the
 * daemon is dead) states two different things in the same row.
 */
function brokerDot(): { tone: "ok" | "bad" | "mute"; label: string } {
  const online = s.status?.online ?? null;
  if (online === null) {
    return s.conn === "offline" ? { tone: "bad", label: "offline" } : { tone: "mute", label: "starting" };
  }
  return online ? { tone: "ok", label: "online" } : { tone: "bad", label: "offline" };
}

function renderSidebar(): void {
  sidebarEl.replaceChildren();
  shellEl.classList.toggle("shell-sidebar-collapsed", sidebarCollapsed);
  const header = el("div", { class: "sidebar-header" });
  const brand = el("div", { class: "brand" });
  const mark = el("span", { class: "brand-mark", "aria-hidden": "true" });
  mark.append(icon("shield"));
  brand.append(mark, document.createTextNode("SecretsVault"));
  header.append(brand);
  const toggle = iconButton(sidebarCollapsed ? "chevron-right" : "chevron-down", sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar", {
    variant: "ghost",
    onClick: () => {
      sidebarCollapsed = !sidebarCollapsed;
      render();
    },
  });
  header.append(toggle);
  sidebarEl.append(header);
  const nav = el("nav", { class: "nav", "aria-label": "Sections" });
  const route = currentRoute();
  const pending = approvalCount(s);
  for (const section of NAV_SECTIONS) {
    const group = el("div", { class: "nav-section" });
    group.append(el("div", { class: "nav-section-title" }, section.title));
    for (const id of section.ids) group.append(navItem(id, route, pending));
    nav.append(group);
  }
  sidebarEl.append(nav);
  // Compact posture strip from the SAME values the topbar reads — no verdicts.
  const status = el("div", { class: "sidebar-status" });
  const dot = brokerDot();
  status.append(statusDot(dot.tone, dot.label));
  status.append(statusDot(s.conn === "trusted" ? "ok" : s.conn === "boot" ? "mute" : s.conn === "offline" ? "bad" : "warn", s.conn));
  // Lock state is only shown once the broker actually reported it.
  if (s.status) status.append(statusDot(s.status.locked ? "mute" : "ok", s.status.locked ? "locked" : "unlocked"));
  sidebarEl.append(status);
}
function routeLabel(route: RouteId): string {
  return ROUTES.find((r) => r.id === route)?.label ?? route;
}
function topbarSub(route: RouteId): string {
  if (s.conn !== "trusted") return `Posture: ${s.conn}`;
  if (needsUnlockGate(s)) return "Unlock the vault to continue";
  if (route === "overview") return "Control centre — posture, attention, counts";
  if (route === "projects") return s.projects === null ? "Project registry not loaded yet" : `${s.projects.length} project${s.projects.length === 1 ? "" : "s"} loaded`;
  if (route === "secrets") return s.activeProject ? `Keys for ${s.activeProject}` : "Pick a project to list keys";
  if (route === "agents") return s.agents === null ? "Agent registry not loaded yet" : `${s.agents.length} agent${s.agents.length === 1 ? "" : "s"} loaded`;
  if (route === "grants") return s.grants === null ? "Capability grants not loaded yet" : `${s.grants.length} grant${s.grants.length === 1 ? "" : "s"} loaded`;
  if (route === "leases") return s.leases === null ? "Live leases not loaded yet" : `${s.leases.length} lease${s.leases.length === 1 ? "" : "s"} loaded`;
  if (route === "approvals") {
    const n = approvalCount(s);
    return n === null ? "Approval inbox not loaded yet" : n === 0 ? "Inbox empty — nothing pending" : `${n} pending approval${n === 1 ? "" : "s"}`;
  }
  if (route === "runs") return s.runs === null ? "Live runs not loaded yet" : `${s.runs.length} run${s.runs.length === 1 ? "" : "s"} loaded`;
  if (route === "audit") {
    if (s.audit === null) return "Audit log not loaded yet";
    const n = s.audit.entries.length;
    return `${n} audit entr${n === 1 ? "y" : "ies"} loaded${auditHasOlder(s) ? " (older available)" : ""}`;
  }
  if (route === "settings") return s.health === null ? "Health not reported yet" : "Broker health reported";
  return "Placeholder — a real screen arrives later";
}
function routeRefreshBusy(route: RouteId): boolean {
  if (route === "overview") return overviewBusy || busy;
  return s.forms.busyAction !== null || busy;
}
function routeRefreshLabel(route: RouteId): string {
  if (route === "overview") return overviewBusy ? "Refreshing…" : "Refresh";
  if (route === "runs") return s.forms.busyAction === "runs_list" ? "Loading…" : "Refresh";
  if (route === "projects") return s.forms.busyAction === "projects_list" ? "Loading…" : "Reload";
  if (route === "secrets") return s.forms.busyAction === "secrets_list" ? "Loading…" : "Reload";
  if (route === "agents") return s.forms.busyAction === "agents_list" ? "Loading…" : "Reload";
  if (route === "grants") return s.forms.busyAction === "grants_list" ? "Loading…" : "Reload";
  if (route === "leases") return "Reload";
  if (route === "approvals") return s.forms.busyAction === "approvals_pending" ? "Loading…" : "Reload";
  if (route === "audit") return s.forms.busyAction === "audit_show" ? "Loading…" : "Reload";
  if (route === "settings") return s.forms.busyAction === "settings_refresh" ? "Refreshing…" : "Reload";
  return "Refresh";
}
function triggerRouteRefresh(route: RouteId): void {
  if (route === "overview") void onManualRefresh();
  else if (route === "projects") onProjectsReload();
  else if (route === "secrets") onSecretsReload();
  else if (route === "agents") onAgentsReload();
  else if (route === "grants") onGrantsReload();
  else if (route === "leases") onLeasesReload();
  else if (route === "approvals") onApprovalsReload();
  else if (route === "runs") onRunsReload();
  else if (route === "audit") onAuditReload();
  else if (route === "settings") onSettingsReload();
}
function canLockNow(): boolean {
  return s.conn === "trusted" && s.status !== null && !s.status.locked;
}
function renderHeader(): void {
  topbarEl.replaceChildren();
  const route = currentRoute();
  const ctx = el("div", { class: "topbar-context" });
  ctx.append(el("div", { class: "topbar-title" }, routeLabel(route)));
  ctx.append(el("div", { class: "topbar-sub" }, topbarSub(route)));
  topbarEl.append(ctx);
  const actions = el("div", { class: "topbar-actions" });
  const dot = brokerDot();
  const trusted = s.conn === "trusted";
  actions.append(statusDot(dot.tone, dot.label));
  actions.append(pill(s.conn, trusted ? "ok" : s.conn === "boot" ? "mute" : s.conn === "offline" ? "bad" : "warn"));
  // The vault pill is rendered only when the broker actually reported lock
  // state — an unexplained "—" pill reads as a broken control. The offline arm
  // of `get_status` synthesizes `locked: true` as a fail-safe *shape*, not an
  // observation (backend.rs), so while offline the truth is unknown and no
  // vault pill is shown at all.
  if (s.status && s.status.online) actions.append(pill(s.status.locked ? "locked" : "unlocked", s.status.locked ? "mute" : "ok"));
  actions.append(statusDot(sessionHeld(s) ? "ok" : "mute", sessionHeld(s) ? "session held" : "no session"));
  const refreshable = route === "overview" || route === "projects" || route === "secrets" || route === "agents" || route === "grants" || route === "leases" || route === "approvals" || route === "runs" || route === "audit" || route === "settings";
  if (refreshable) {
    const label = routeRefreshLabel(route);
    const btn = iconTextButton("refresh", label, {
      disabled: routeRefreshBusy(route) || s.conn === "offline",
      onClick: () => triggerRouteRefresh(route),
    });
    actions.append(btn);
  }
  if (canLockNow()) {
    lockBtn = iconTextButton("lock", "Lock", { disabled: busy, onClick: () => void doLock() });
    actions.append(lockBtn);
  }
  actions.append(iconButton("command", "Command palette (Ctrl K)", { variant: "ghost", onClick: () => openPalette() }));
  topbarEl.append(actions);
}
async function doLock(): Promise<void> {
  busy = true;
  render();
  try {
    await api.lock();
  } catch {
    // Lock is fail-closed locally regardless: clear everything either way.
  } finally {
    s = applyLock();
    unlockFailure = null;
    probed = null;
    probeError = null;
    projectsError = null;
    secretsError = null;
    agentsError = null;
    grantsError = null;
    approvalsError = null;
    leasesError = null;
    runsError = null;
  auditError = null;
  settingsError = null;
    dropOneTimeToken();
    clearReveal();
    decidedApprovals.clear();
    dismissToasts();
    armSlowTimer();
    armApprovalsTimer();
    armSessionTimer();
    if (window.location.hash !== "#/") window.location.hash = "#/";
    busy = false;
    render();
  }
}

const OFFLINE_MSG = "Broker offline — the daemon is unreachable. Privileged actions are disabled.";
const OFFLINE_LIST_MSG = "The broker-backed lists need the broker — they are unavailable while offline.";
const OFFLINE_AUDIT_MSG = "The audit timeline needs the human session — it is unavailable while the broker is offline.";
// Next-action instruction for the offline posture. Names the daemon start
// command; the dashboard never starts or restarts the daemon itself, so no
// control is offered here — instructions only.
const OFFLINE_DAEMON_MSG = "Start the broker daemon yourself with `svault daemon` — the dashboard never starts or restarts it.";

/**
 * Full-stop screen for a vault integrity failure (E_VAULT_CORRUPT). A local
 * function, not a screen under screens/: nothing else may render while it
 * shows. No retry control — a corrupt vault must not simply be retried.
 */
function renderFatal(root: HTMLElement, e: MappedError): void {
  root.replaceChildren();
  root.append(banner("alarm", `${e.code}: ${e.message}`));
  root.append(el("h2", {}, "Vault integrity check failed"));
  const advice = errorAdvice(e.code);
  if (advice !== null) root.append(para(advice));
  root.append(para("The vault should not simply be retried — investigate the vault file before doing anything else."));
}

/** Settings renders identically online and offline: absent broker data is its own honest state. */
function renderSettingsRoute(): void {
  renderSettings(outletEl, s, {
    busyAction: s.forms.busyAction,
    onRefresh: () => onSettingsReload(),
    onLock: () => void doLock(),
    onVerifyAudit: () => onAuditVerify(),
    onProbe: () => onSettingsProbe(),
    inlineError: settingsError,
  });
}

function renderOutlet(): void {
  const route = currentRoute();
  // Full stop outranks every posture: a corrupt vault replaces all routes.
  const fatal = fatalStop(s);
  if (fatal !== null) {
    renderFatal(outletEl, fatal);
    return;
  }
  if (s.conn === "offline") {
    // Exactly one offline explanation per route (the branch-specific line
    // below), plus the daemon-start instruction — never a second blanket
    // prepend. No control here starts or restarts the daemon.
    const daemonNote = para(OFFLINE_DAEMON_MSG);
    if (route === "overview") {
      renderOverview(outletEl, s, { onRefresh: () => void onManualRefresh(), busy: overviewBusy });
      // The overview screen renders its own state honestly offline; the
      // posture line is the single explanation here.
      outletEl.prepend(daemonNote);
      outletEl.prepend(banner("warn", OFFLINE_MSG));
    } else if (
      route === "projects" ||
      route === "secrets" ||
      route === "agents" ||
      route === "grants" ||
      route === "leases" ||
      route === "approvals" ||
      route === "runs"
    ) {
      outletEl.replaceChildren();
      const titles: Record<string, string> = {
        projects: "Projects",
        secrets: "Secrets",
        agents: "Agents",
        grants: "Grants",
        leases: "Leases",
        approvals: "Approvals",
        runs: "Runs",
      };
      outletEl.append(el("h2", {}, titles[route] ?? route));
      outletEl.append(banner("info", OFFLINE_LIST_MSG));
      outletEl.append(daemonNote);
    } else if (route === "audit") {
      outletEl.replaceChildren();
      outletEl.append(el("h2", {}, "Audit"));
      outletEl.append(banner("info", OFFLINE_AUDIT_MSG));
      outletEl.append(daemonNote);
    } else if (route === "settings") {
      // The real screen is reused: its Health section reports that no health
      // has been read, while the locally-known posture, pinned fingerprint and
      // read-only configuration still render. Only broker data is missing.
      // Its own offline line is the single explanation here — plus the
      // daemon-start instruction appended after the screen renders.
      outletEl.replaceChildren();
      renderSettingsRoute();
      outletEl.append(daemonNote);
    }
    return;
  }
  if (s.conn === "mismatch") {
    renderMismatch(outletEl, s);
    return;
  }
  if (s.conn === "untrusted") {
    renderUntrusted(outletEl, {
      busy,
      probed,
      probeError,
      onProbe: () => void onProbe(),
      onRefresh: () => void onUntrustedRefresh(),
    });
    return;
  }
  if (s.conn === "no-vault") {
    renderNoVault(outletEl, { busy, inlineError: s.error, onRefresh: () => void onManualRefresh() });
    return;
  }
  if (s.conn === "boot") {
    outletEl.replaceChildren();
    outletEl.append(banner("info", busy ? "Contacting broker…" : "Starting…"));
    return;
  }
  // trusted — the unlock gate outranks every route when the vault reads
  // locked OR when a human session expired underneath an unlocked vault
  // (needsUnlockGate covers both; canOfferUnlock alone is not sufficient).
  // The two causes must not share a heading: with the vault still unlocked,
  // "Vault is locked" contradicts the lock pill rendered just above it.
  if (needsUnlockGate(s)) {
    renderUnlockGate(outletEl, {
      busy,
      failure: unlockFailure,
      reason: unlockGateReason(s) === "locked" ? "locked" : "session-expired",
      onUnlock: (get, clear) => void onUnlock(get, clear),
    });
    return;
  }
  if (s.conn !== "trusted") {
    outletEl.replaceChildren();
    outletEl.append(banner("info", busy ? "Contacting broker…" : "Starting…"));
    return;
  }
  // trusted + unlocked + live session
  if (route === "overview") {
    renderOverview(outletEl, s, { onRefresh: () => void onManualRefresh(), busy: overviewBusy });
    return;
  }
  if (route === "projects") {
    renderProjects(outletEl, s, {
      busyAction: s.forms.busyAction,
      pendingConfirm: s.forms.pendingConfirm,
      tab: s.projectTab,
      onTab: (t) => onProjectTab(t),
      onCreate: (name, paths) => onProjectCreate(name, paths),
      onRemove: (name) => onProjectRemove(name),
      onPathAdd: (name, path) => onPathAdd(name, path),
      onPathRemove: (name, path) => onPathRemove(name, path),
      onSelect: (name) => onProjectSelect(name),
      onOpen: (name) => onOpenProject(name),
      onCancelConfirm: () => onCancelConfirm(),
      onReload: () => onProjectsReload(),
      inlineError: projectsError,
    });
    return;
  }
  if (route === "secrets") {
    const pc = s.forms.pendingConfirm;
    renderSecrets(outletEl, s, {
      busyAction: s.forms.busyAction,
      confirmKey: pc && pc.kind === "secret" ? (pc.extra ?? null) : null,
      form: s.forms.secretForm,
      onPickProject: (name) => onPickProject(name),
      onReload: () => onSecretsReload(),
      onOpenAdd: () => onSecretFormOpen({ mode: "add" }),
      onOpenEdit: (key) => onSecretFormOpen({ mode: "edit", key }),
      onCloseForm: () => onSecretFormClose(),
      onSubmitAdd: (key, value) => onSecretSubmit(key, value),
      onSubmitEdit: (key, value) => onSecretSubmit(key, value),
      onDelete: (key) => onSecretDelete(key),
      onCancelConfirm: () => onCancelConfirm(),
      onReveal: (key) => onRevealOpen(key),
      inlineError: secretsError,
    });
    // Deferred return-to-reveal open: runs AFTER the secrets render, so the
    // route-change wipe (which fires before this render) cannot clear it.
    if (pendingRevealOpen !== null) {
      const target = pendingRevealOpen;
      pendingRevealOpen = null;
      openRevealModal(target.project, target.key, { onShow: (p, k) => onRevealShow(p, k) });
    }
    return;
  }
  if (route === "agents") {
    renderAgents(outletEl, s, {
      busyAction: s.forms.busyAction,
      pendingConfirm: s.forms.pendingConfirm,
      selected: s.selectedAgent,
      onSelect: (n) => onAgentSelect(n),
      onEnroll: (name, tokenPath) => onAgentEnroll(name, tokenPath),
      onRevoke: (name) => onAgentRevoke(name),
      onCancelConfirm: () => onCancelConfirm(),
      onReload: () => onAgentsReload(),
      inlineError: agentsError,
    });
    // The one-time token node (built once in the enroll handler's closure)
    // is re-attached above the list while it lives. Any full re-render of
    // this route without a live node simply shows the list.
    if (oneTimeTokenNode !== null && oneTimeTokenNode.isConnected === false) {
      outletEl.prepend(oneTimeTokenNode);
    }
    return;
  }
  if (route === "grants") {
    renderGrants(outletEl, s, {
      busyAction: s.forms.busyAction,
      pendingConfirm: s.forms.pendingConfirm,
      draft: s.forms.grantDraft,
      pair: s.forms.grantPair,
      onSave: (agent, project, ops) => onGrantSave(agent, project, ops),
      onPairChange: (agent, project) => onGrantPairChange(agent, project),
      onConfirmSave: () => onGrantConfirmSave(),
      onRevoke: (agent, project) => onGrantRevoke(agent, project),
      onCancelConfirm: () => onGrantCancelConfirm(),
      onReload: () => onGrantsReload(),
      inlineError: grantsError,
    });
    return;
  }
  if (route === "leases") {
    renderLeases(outletEl, s, {
      busyAction: s.forms.busyAction,
      pendingConfirm: s.forms.pendingConfirm,
      onRevoke: (leaseId) => onLeaseRevoke(leaseId),
      onCancelConfirm: () => onCancelConfirm(),
      onReload: () => onLeasesReload(),
      inlineError: leasesError,
    });
    return;
  }
  if (route === "approvals") {
    renderApprovals(outletEl, s, {
      busyAction: s.forms.busyAction,
      onApprove: (id) => onApprovalDecide(id, true),
      onDeny: (id) => onApprovalDecide(id, false),
      onReload: () => onApprovalsReload(),
      inlineError: approvalsError,
      decided: decidedApprovals,
      onReturnToReveal: (project, key) => onReturnToReveal(project, key),
    });
    return;
  }
  if (route === "runs") {
    renderRuns(outletEl, s, {
      busyAction: s.forms.busyAction,
      onReload: () => onRunsReload(),
      inlineError: runsError,
    });
    return;
  }
  if (route === "audit") {
    renderAudit(outletEl, s, {
      busyAction: s.forms.busyAction,
      onReload: () => onAuditReload(),
      onLoadOlder: () => onAuditLoadOlder(),
      onVerify: () => onAuditVerify(),
      onFilter: (f) => onAuditFilter(f),
      inlineError: auditError,
    });
    return;
  }
  if (route === "settings") {
    renderSettingsRoute();
    return;
  }
  outletEl.replaceChildren();
  outletEl.append(banner("warn", `Unknown route: ${route}`));
}
/** Sidebar + header only. Never touches the outlet, so it is safe from a tick. */
function renderChrome(): void {
  renderSidebar();
  renderHeader();
}

/**
 * Text-only refresh of the live countdown nodes the 1 s ticker exists for.
 * `updateSessionNodes` mutates `textContent` in place, so it cannot disturb an
 * input, a selection or the focus.
 */
function updateSessionNodes(): void {
  if (outletEl === undefined) return;
  const nodes = outletEl.querySelectorAll("[data-session-live]");
  if (nodes.length === 0) return;
  const nowMs = Date.now();
  nodes.forEach((node) => {
    const kind = node.getAttribute("data-session-live");
    if (kind === "countdown") node.textContent = sessionText(s.session, nowMs, s.unlockedAtMs);
    else if (kind === "ceiling" && s.session.maxExpiresIn !== undefined && s.session.maxExpiresIn !== null) {
      node.textContent = `Absolute ceiling: about ${s.session.maxExpiresIn}s from mint.`;
    }
  });
}

/** The outlet paint path: route content, then the one global failure banner. */
function paintOutlet(): void {
  renderOutlet();
  // The global failure banner is suppressed while the posture is already
  // offline. Offline IS the failure, and every offline branch above renders
  // its own single explanation (plus the daemon-start instruction); letting
  // the raw transport error also surface would stack a second, redundant
  // banner on top of it — observed in D7 as the bridge's
  // `OFFLINE: Tauri bridge unavailable` sitting above Settings' own offline
  // line, and the same would happen for a dead daemon's `E_IO`. The code is
  // still carried by the posture pills and the screen's own text, so nothing
  // is hidden; only the duplicate is dropped.
  if (s.error && s.conn !== "mismatch" && s.conn !== "offline") {
    const advice = errorAdvice(s.error.code);
    outletEl.prepend(banner("warn", advice !== null ? `${s.error.code}: ${s.error.message} ${advice}` : `${s.error.code}: ${s.error.message}`));
  }
}

/**
 * Repaint the outlet only when the user is not mid-edit. When the screen is
 * touched the repaint is skipped: the data is already in state, and the next
 * explicit render (submit, cancel, route change, lock, Refresh) paints it.
 */
function renderOutletWhenIdle(): boolean {
  if (outletTouched) return false;
  paintOutlet();
  return true;
}

/**
 * The 1 s session ticker's paint. The chrome is always refreshed; the outlet is
 * repainted only while the screen is untouched — exactly as it always was — and
 * while it IS touched only the live countdown nodes are rewritten in place. A
 * tick never destroys typed text, a selection, the focus or an open form.
 */
function sessionTick(): void {
  renderChrome();
  if (outletTouched) updateSessionNodes();
  else paintOutlet();
}

/**
 * Paint after a data poll (20 s / 45 s). Chrome and live countdowns always; the
 * outlet only when the operator is not mid-edit. The fresh data is already in
 * state, and the next explicit render (submit, cancel, route change, lock,
 * Refresh) or the next idle poll paints it.
 */
function pollRepaint(): void {
  renderChrome();
  updateSessionNodes();
  renderOutletWhenIdle();
}

function render(): void {
  renderChrome();
  // An explicit render always wins: it is a submit, a cancel, a route change,
  // a lock/unlock or a Refresh, i.e. a point where repainting is intended.
  outletTouched = false;
  paintOutlet();
}
function paletteCommands(): PaletteCommand[] {
  const cmds: PaletteCommand[] = [];
  for (const r of ROUTES) {
    const id = r.id;
    cmds.push({
      id: `go-${id}`,
      label: `Go to ${r.label}`,
      hint: ROUTE_KBD[id],
      run: () => {
        if (window.location.hash !== r.hash) window.location.hash = r.hash;
        else render();
      },
    });
  }
  const route = currentRoute();
  cmds.push({ id: "refresh", label: `Refresh ${routeLabel(route)}`, keys: "r", run: () => triggerRouteRefresh(route) });
  if (canLockNow()) cmds.push({ id: "lock", label: "Lock Vault", keys: "l", run: () => void doLock() });
  cmds.push({ id: "new-project", label: "New Project", hint: "Go to Projects", run: () => { if (window.location.hash !== "#/projects") window.location.hash = "#/projects"; else render(); } });
  cmds.push({ id: "new-secret", label: "New Secret", hint: "Go to Secrets", run: () => { if (window.location.hash !== "#/secrets") window.location.hash = "#/secrets"; else render(); } });
  return cmds;
}

// ---- Projects handlers ----

function onProjectCreate(name: string, paths: string[]): void {
  if (!name) {
    projectsError = { code: "E_INVALID_INPUT", message: "Enter a project name." };
    render();
    return;
  }
  void mutateProjects("project_add", () => api.projectAdd(name, paths));
}

function onProjectRemove(name: string): void {
  const c = s.forms.pendingConfirm;
  if (!c || c.kind !== "project" || c.project !== name) {
    s = { ...s, forms: { ...s.forms, pendingConfirm: { kind: "project", project: name } } };
    render();
    return;
  }
  void mutateProjects("project_remove", () => api.projectRemove(name));
}

function onPathAdd(name: string, path: string): void {
  if (!path) {
    projectsError = { code: "E_INVALID_INPUT", message: "Enter a path to authorize." };
    render();
    return;
  }
  void mutateProjects("project_path_add", () => api.projectPathAdd(name, path));
}

function onPathRemove(name: string, path: string): void {
  const c = s.forms.pendingConfirm;
  if (!c || c.kind !== "path" || c.project !== name || c.extra !== path) {
    s = { ...s, forms: { ...s.forms, pendingConfirm: { kind: "path", project: name, extra: path } } };
    render();
    return;
  }
  void mutateProjects("project_path_remove", () => api.projectPathRemove(name, path));
}

function onProjectSelect(name: string | null): void {
  s = applySelectedProject(s, name);
  render();
}
function onProjectTab(tab: ProjectTab): void {
  s = applyProjectTab(s, tab);
  render();
}
function onAgentSelect(name: string | null): void {
  s = applySelectedAgent(s, name);
  render();
}

function onOpenProject(name: string): void {
  s = applySelectedProject(s, name);
  if (name !== s.activeProject) s = applyActiveProject(s, name);
  if (window.location.hash !== "#/secrets") {
    window.location.hash = "#/secrets";
    render();
    return;
  }
  const p = loadSecretsList();
  render();
  void p.then(() => render());
}

function onCancelConfirm(): void {
  s = { ...s, forms: { ...s.forms, pendingConfirm: null } };
  render();
}

function onGrantCancelConfirm(): void {
  s = { ...s, forms: { ...s.forms, pendingConfirm: null, grantDraft: null } };
  render();
}

function onProjectsReload(): void {
  projectsError = null;
  const p = loadProjectsList();
  render();
  void p.then(() => render());
}

// ---- Agents handlers ----

function onAgentsReload(): void {
  agentsError = null;
  const p = loadAgentsList();
  render();
  void p.then(() => render());
}

/**
 * Enroll submit. The token travels the discipline path: `agent_add` returns
 * it once into this closure's locals; `takeOneTimeToken` splits display
 * from persistence (nothing to persist); the single DOM node built here is
 * the only other copy, kept as an element ref until dismiss or any full
 * state transition. The string itself is never stored in ShellState, in a
 * module binding, in storage, in the URL, in logs, or on the clipboard —
 * and never kept automatically.
 */
function onAgentEnroll(name: string, tokenPath?: string): void {
  if (!name) {
    agentsError = { code: "E_INVALID_INPUT", message: "Enter an agent name." };
    render();
    return;
  }
  s = applyMutationStart(s, "agent_add");
  agentsError = null;
  render();
  void (async () => {
    try {
      const res = await api.agentAdd(name, tokenPath);
      const { shown } = takeOneTimeToken(res);
      const savedPath = res.token_saved_path;
      oneTimeTokenNode = renderOneTimeToken(shown, savedPath, () => onTokenDismiss());
    } catch (e) {
      s = applyMutationDone(s);
      if (!noteCallError(e)) {
        agentsError = callError();
      }
      render();
      return;
    }
    try {
      const res = await api.agentsList();
      s = applyAgents(s, res.agents);
    } catch (e) {
      s = applyMutationDone(s);
      if (!noteCallError(e)) {
        { const cause = callError(); agentsError = { code: cause.code, message: `Enrolled, but the fresh agents could not be read (${cause.code}: ${cause.message}) — shown data may be stale.` }; }
      }
      render();
      return;
    }
    try {
      s = applyOverview(s, await api.overviewRefresh());
    } catch (e) {
      if (!noteCallError(e)) {
        { const cause = callError(); agentsError = { code: cause.code, message: `Enrolled and the agents are fresh, but counts could not be refreshed (${cause.code}: ${cause.message}).` }; }
      }
      s = applyMutationDone(s);
      render();
      return;
    }
    s = applyMutationDone(s);
    toast("success", "Agent enrolled — copy the one-time token now.");
    render();
  })();
}

/** Dismiss the one-time token display. The node (and its copy) is dropped — unrecoverable by design. */
function onTokenDismiss(): void {
  dropOneTimeToken();
  render();
}

function onAgentRevoke(name: string): void {
  const c = s.forms.pendingConfirm;
  if (!c || c.kind !== "agent" || c.project !== name) {
    s = { ...s, forms: { ...s.forms, pendingConfirm: { kind: "agent", project: name } } };
    render();
    return;
  }
  void mutateAgents("agent_revoke", () => api.agentRevoke(name));
}

// ---- Grants handlers ----

function onGrantsReload(): void {
  grantsError = null;
  const p = (async () => {
    if (s.projects === null) await loadProjectsList();
    if (s.agents === null) await loadAgentsList();
    await loadGrantsList();
  })();
  render();
  void p.then(() => render());
}

/**
 * Point the grants editor at another agent × project pair. Recorded in form
 * state so a repaint cannot silently revert the target to the first option,
 * and a widening draft staged for the previous pair is dropped with it — a
 * draft belongs to the pair it was staged from.
 */
function onGrantPairChange(agent: string, project: string): void {
  s = { ...s, forms: { ...s.forms, grantPair: { agent, project }, grantDraft: null } };
  render();
}

/**
 * Stage a grant save. Widening saves (adding any capability) park in
 * `grantDraft` for the confirm step in the Grants screen; narrowing saves
 * go straight through the normal re-read mutation.
 */
function onGrantSave(agent: string, project: string, ops: string[]): void {
  if (!agent || !project) {
    grantsError = { code: "E_INVALID_INPUT", message: "Pick an agent and a project first." };
    render();
    return;
  }
  const saved = activeGrantOps(s, agent, project) ?? [];
  const draft: GrantDraft = { agent, project, ops: [...ops] };
  if (grantWidens(saved, ops)) {
    s = { ...s, forms: { ...s.forms, grantDraft: draft, pendingConfirm: null } };
    render();
    return;
  }
  void mutateGrants("grant_set", () => api.grantSet(agent, project, ops));
}

function onGrantConfirmSave(): void {
  const draft = s.forms.grantDraft;
  if (!draft) return;
  const { agent, project, ops } = draft;
  s = { ...s, forms: { ...s.forms, grantDraft: null } };
  void mutateGrants("grant_set", () => api.grantSet(agent, project, ops));
}

function onGrantRevoke(agent: string, project: string): void {
  const c = s.forms.pendingConfirm;
  if (!c || c.kind !== "grant" || c.project !== agent || c.extra !== project) {
    s = { ...s, forms: { ...s.forms, pendingConfirm: { kind: "grant", project: agent, extra: project } } };
    render();
    return;
  }
  void mutateGrants("grant_revoke", () => api.grantRevoke(agent, project));
}

// ---- Approvals handlers ----

function onApprovalsReload(): void {
  approvalsError = null;
  const p = loadApprovalsList();
  render();
  void p.then(() => render());
}

/** Approve or deny one entry, then IMMEDIATELY re-read the inbox. Never optimistic, never auto. */
function onApprovalDecide(id: string, approve: boolean): void {
  if (!id) return;
  void mutateApprovals(approve ? "approval_approve" : "approval_deny", () =>
    approve ? api.approvalApprove(id) : api.approvalDeny(id),
  );
}

/**
 * Return-to-reveal: after a reveal approval was approved, navigate to the
 * Secrets screen for (project, key) and open the masked modal. NAVIGATION
 * ONLY — no claim is performed, here or anywhere in the dashboard: the claim
 * belongs to the requesting agent. The human's own reveal is a separate,
 * direct owner action that needs no approval. The value is never shown here.
 * Deferred through pendingRevealOpen (consumed by the secrets branch of
 * renderOutlet) so the route-change wipe cannot clear a just-opened modal.
 */
function onReturnToReveal(project: string, key: string): void {
  if (!project || !key) return;
  s = applyActiveProject(s, project);
  pendingRevealOpen = { project, key };
  if (window.location.hash !== "#/secrets") window.location.hash = "#/secrets";
  render();
}

// ---- Secrets handlers ----
function onPickProject(name: string): void {
  if (name === s.activeProject && s.secrets !== null) return;
  s = applyActiveProject(s, name);
  secretsError = null;
  const p = loadSecretsList();
  render();
  void p.then(() => render());
}

function onSecretsReload(): void {
  secretsError = null;
  const p = loadSecretsList();
  render();
  void p.then(() => render());
}

function onSecretFormOpen(form: SecretForm): void {
  s = { ...s, forms: { ...s.forms, secretForm: form, pendingConfirm: null } };
  secretsError = null;
  render();
}

function onSecretFormClose(): void {
  // render() replaces the outlet subtree, so the form inputs (and any typed
  // value still in them) are dropped from the DOM here.
  s = { ...s, forms: { ...s.forms, secretForm: null } };
  render();
}

/**
 * Secret-value submit. `value` arrives as a function-local from the form's
 * submit handler (which already cleared the input). It travels straight
 * into this single secret_set call and goes out of scope below — never
 * stored in state, storage, the URL, or logs, and never kept on failure
 * (the cleared input forces a retype).
 */
function onSecretSubmit(key: string, value: string): void {
  const project = s.activeProject;
  if (project === null || !key || !value) return;
  void mutateSecrets("secret_set", project, () => api.secretSet(project, key, value));
}

function onSecretDelete(key: string): void {
  const project = s.activeProject;
  if (project === null) return;
  const c = s.forms.pendingConfirm;
  if (!c || c.kind !== "secret" || c.project !== project || c.extra !== key) {
    s = { ...s, forms: { ...s.forms, pendingConfirm: { kind: "secret", project, extra: key } } };
    render();
    return;
  }
  void mutateSecrets("secret_delete", project, () => api.secretDelete(project, key));
}

// ---- Reveal handlers ----
//
// The value never enters ShellState: `takeRevealValue` splits display from
// persistence (nothing to persist); the modal's module-local holds the only
// copy until hide/close/lock/expiry clears it. Re-read policy follows the
// existing mutate* pattern — no optimistic state.

/** Open the masked modal for one key. Never auto-reveals. */
function onRevealOpen(key: string): void {
  const project = s.activeProject;
  if (project === null || !key) return;
  openRevealModal(project, key, { onShow: (p, k) => onRevealShow(p, k) });
}

/** Explicit human reveal from the modal (owner's direct reveal, no approval):
 *  reveal(project, key), then hand the value to the modal only. */
function onRevealShow(project: string, key: string): void {
  s = applyMutationStart(s, "reveal");
  secretsError = null;
  render();
  void (async () => {
    try {
      const res = await api.reveal(project, key);
      const { shown } = takeRevealValue(res);
      deliverRevealedValue(project, key, shown);
    } catch (e) {
      s = applyMutationDone(s);
      if (!noteCallError(e)) revealFailed(project, key, callError().message);
      render();
      return;
    }
    s = applyMutationDone(s);
    render();
  })();
}

// ---- Leases handlers ----

function onLeasesReload(): void {
  leasesError = null;
  const p = loadLeasesList();
  render();
  void p.then(() => render());
}

function onLeaseRevoke(leaseId: string): void {
  const c = s.forms.pendingConfirm;
  if (!c || c.kind !== "lease" || c.project !== leaseId) {
    s = { ...s, forms: { ...s.forms, pendingConfirm: { kind: "lease", project: leaseId } } };
    render();
    return;
  }
  void mutateLeases("lease_revoke", () => api.leaseRevoke(leaseId));
}

// ---- Runs handlers ----

function onRunsReload(): void {
  runsError = null;
  const p = loadRunsList();
  render();
  void p.then(() => render());
}

// ---- D6 handlers: Audit + Settings ----

/** Newest audit page (a replace, not an append). Demand-driven: never called by a timer. */
function onAuditReload(): void {
  auditError = null;
  const p = loadAuditPage();
  render();
  void p.then(() => render());
}

/**
 * Next older page via the real cursor. A fresh walk after the newest page
 * lands restarts from the cursor the slice actually holds, so this never
 * fabricates a page boundary.
 */
function onAuditLoadOlder(): void {
  const next = s.audit?.nextBeforeSeq;
  if (next === null || next === undefined) return;
  auditError = null;
  const p = loadAuditPage(next);
  render();
  void p.then(() => render());
}

function onAuditVerify(): void {
  auditError = null;
  const p = loadAuditVerify();
  render();
  void p.then(() => render());
}

/** Local-only filter change: mutates the view state and re-renders. Issues no request. */
function onAuditFilter(f: Partial<AuditFilters>): void {
  s = applyAuditFilters(s, f);
  render();
}

function onSettingsReload(): void {
  settingsError = null;
  const p = loadSettingsData();
  render();
  void p.then(() => render());
}

function onSettingsProbe(): void {
  settingsError = null;
  const p = loadSettingsProbe();
  render();
  void p.then(() => render());
}

// ---- D1 handlers (unchanged contract) ----
async function onProbe(): Promise<void> {
  busy = true;
  render();
  probeError = null;
  try {
    probed = (await api.probeFingerprint()).fingerprint;
  } catch (e) {
    s = applyError(s, e);
    probeError = s.error ? `${s.error.code}: ${s.error.message}` : "Probe failed.";
  } finally {
    busy = false;
    render();
  }
}

// Refresh from the untrusted panel: re-runs the full posture check so a
// pin made at the CLI (TTY) is picked up without any in-app trust write.
async function onUntrustedRefresh(): Promise<void> {
  busy = true;
  render();
  try {
    await refreshAll();
  } catch (e) {
    s = applyError(s, e);
  } finally {
    busy = false;
    render();
  }
}

async function onUnlock(getPassphrase: () => string, clear: () => void): Promise<void> {
  // The passphrase lives only in the input element; read once, clear
  // immediately, never store in state/URL/storage/logs.
  const passphrase = getPassphrase();
  clear();
  if (!passphrase) {
    unlockFailure = "Enter the passphrase.";
    render();
    return;
  }
  busy = true;
  render();
  try {
    s = applyUnlockSuccess(s, await api.unlock(passphrase), Date.now());
    dropOneTimeToken();
    decidedApprovals.clear();
    dismissToasts();
    await refreshAll();
    await loadRouteData(currentRoute());
    armSessionTimer();
    toast("success", "Vault unlocked.");
    if (window.location.hash !== "#/") window.location.hash = "#/";
  } catch (e) {
    s = applyError(s, e);
    unlockFailure = s.error ? `${s.error.code}: ${s.error.message}` : "Unlock failed.";
  } finally {
    busy = false;
    render();
  }
}

async function onManualRefresh(): Promise<void> {
  overviewBusy = true;
  render();
  try {
    await refreshAll();
    toast("success", "Refreshed — posture and counts re-read.");
  } catch (e) {
    s = applyError(s, e);
  } finally {
    overviewBusy = false;
    render();
  }
}
const G_PREFIX_MS = 1500;
const G_TARGETS: Record<string, RouteId> = {
  o: "overview",
  p: "projects",
  s: "secrets",
  a: "agents",
  g: "grants",
  l: "leases",
  v: "approvals",
  n: "runs",
  u: "audit",
  t: "settings",
};
function keyTargetIsForm(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  if (target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement || target instanceof HTMLSelectElement) return true;
  return target.isContentEditable;
}
function goRoute(id: RouteId): void {
  const hash = ROUTES.find((r) => r.id === id)?.hash ?? "#/";
  if (window.location.hash !== hash) window.location.hash = hash;
  else render();
}
function onGlobalKeydown(e: KeyboardEvent): void {
  const inForm = keyTargetIsForm(e.target);
  const modK = (e.ctrlKey || e.metaKey) && !e.altKey && (e.key === "k" || e.key === "K");
  if (modK) {
    e.preventDefault();
    if (paletteOpen()) closePalette();
    else openPalette();
    return;
  }
  if (e.key === "Escape") {
    if (paletteOpen()) closePalette();
    else closeReveal();
    return;
  }
  if (paletteOpen()) return;
  if (inForm) return;
  if (e.ctrlKey || e.metaKey || e.altKey) return;
  if (e.key === "/") {
    e.preventDefault();
    openPalette();
    return;
  }
  if (e.key.length === 1 && e.key.toLowerCase() === "g") {
    // "g g" jumps to Grants; a lone g arms the prefix.
    if (gPrefixAt !== 0 && Date.now() - gPrefixAt <= G_PREFIX_MS) {
      gPrefixAt = 0;
      goRoute("grants");
      return;
    }
    gPrefixAt = Date.now();
    return;
  }
  const prefixAge = Date.now() - gPrefixAt;
  if (prefixAge <= G_PREFIX_MS && e.key.length === 1) {
    const target = G_TARGETS[e.key.toLowerCase()];
    gPrefixAt = 0;
    if (target) {
      goRoute(target);
      return;
    }
    return;
  }
  if (e.key === "l" && canLockNow()) {
    void doLock();
    return;
  }
  if (e.key === "r") triggerRouteRefresh(currentRoute());
}
export function boot(): void {
  buildChrome();
  render();
  document.addEventListener("visibilitychange", () => onApprovalsVisibility());
  document.addEventListener("keydown", onGlobalKeydown);
  window.addEventListener("hashchange", () => {
    // Route changes drop the reveal modal's value — it is tied to its screen.
    clearReveal();
    const route = currentRoute();
    // The audit pages are route-scoped: carrying a loaded range into another
    // screen would misrepresent what has been read, and every re-read costs a
    // log entry. Released the moment the user leaves Audit.
    if (route !== "audit" && s.audit !== null) s = clearAudit(s);
    render();
    const p = (async () => {
      try {
        await refreshPosture();
        await loadRouteData(route);
        armApprovalsTimer();
        armSessionTimer();
      } catch (e) {
        s = applyError(s, e);
      }
    })();
    void p.then(() => render());
  });
  busy = true;
  render();
  void refreshAll()
    .catch((e: unknown) => {
      s = applyError(s, e);
    })
    .then(() => loadRouteData(currentRoute()))
    .catch((e: unknown) => {
      s = applyError(s, e);
    })
    .then(() => {
      busy = false;
      armApprovalsTimer();
      armSessionTimer();
      render();
    });
}

if (typeof document !== "undefined") {
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot, { once: true });
  else boot();
}

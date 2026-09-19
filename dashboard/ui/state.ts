// Pure shell-state logic for the SecretsVault dashboard.
// No DOM, no invoke, no timers — unit-tested under `node --test`.

export interface BrokerStatus {
  /** Wire protocol version (broker envelope VERSION, e.g. 1). Numeric, not semver. */
  version: number;
  created: string;
  locked: boolean;
  online: boolean;
  trusted: boolean;
  /** False when no vault file exists yet (fresh backend, nothing created). */
  initialized: boolean;
  fingerprint?: string;
}

export interface PinStatus {
  pinned: boolean;
  fingerprint?: string;
}

export interface UnlockResponse {
  unlocked: boolean;
  session_prefix?: string;
  expires_at?: string;
  expires_in?: number;
  max_expires_at?: string;
  max_expires_in?: number;
}

export interface HealthResponse {
  locked: boolean;
  idle_lock_secs: number;
  idle_in: number | null;
  audit_bytes: number;
  audit_soft_limit: number;
  audit_hard_limit: number;
  vault_bytes: number;
  vault_max_bytes: number;
  runs_active: number;
  leases_active: number | null;
  approvals_pending: number | null;
}

export interface MappedError {
  code: string;
  message: string;
}

// ---- D6 slices: audit timeline, verification, settings metadata ----
//
// The audit timeline is bounded by construction: a page is at most
// `AUDIT_PAGE_SIZE` entries and older pages arrive only on explicit demand
// through the broker's real `next_before_seq` cursor. Filtering happens
// locally over the pages already loaded — the wire has no actor/op filter,
// and adding one was not justified by any demonstrated need.

/** One audit entry as the backend projects it. Secret NAMES only; chain bytes never cross. */
export interface AuditEntry {
  seq: number;
  ts: string;
  actor: string;
  op: string;
  project?: string;
  /** Secret key NAMES — the API cannot carry values. */
  keys: string[];
  /** `"allowed"` | `"denied"`. */
  decision: string;
  /** Stable `E_*` code, when the entry records a denial. */
  reason?: string;
  run_id?: string;
  /** True iff the entry carried a MAC: written while the vault was unlocked. */
  authenticated: boolean;
}

export interface AuditVerifyResult {
  entries: number;
  macs_verified: number;
  macs_null: number;
}

/** Local filter draft. `""` in any field means that field does not narrow. */
export interface AuditFilters {
  actor: string;
  op: string;
  project: string;
  decision: string;
}

/** Loaded audit pages, oldest..newest, plus the cursor for the next older page. */
export interface AuditSlice {
  entries: AuditEntry[];
  nextBeforeSeq: number | null;
}

/** Settings metadata that is observed rather than broker-reported (the live probe). */
export interface SettingsSlice {
  probedFingerprint: string | null;
  probedAtMs: number;
}

/** A read-only configuration row. `readonly` is a literal so values can never be mistaken for controls. */
export interface SettingsField {
  label: string;
  value: string;
  readonly: true;
}

/** An operational warning derived from a real observed value. Never a broker verdict. */
export interface HealthWarning {
  id: string;
  tone: Tone;
  title: string;
  detail: string;
}

// ---- D2 slices: overview data, projects, secrets metadata ----
//
// Every counter in OverviewData is `number | null`: null means the broker
// did not report a value (locked/offline/untrusted) and MUST render as
// "—", never as a fabricated 0.

export interface OverviewData {
  online: boolean;
  trusted: boolean;
  fingerprint?: string;
  version: number;
  created: string;
  locked: boolean;
  /**
   * Posture: whether the backend currently holds a human session for this
   * app instance. Present in every payload including posture-only ones —
   * that is what distinguishes "no session" from "broker reported nothing".
   * Authoritative over the local `session.present`, which can go stale
   * after a silent TTL lapse (300 s session vs 900 s idle-lock).
   */
  session_held: boolean;
  projects: number | null;
  secrets_total: number | null;
  /** false ⇒ the broker counted only up to a cap: render "≥ N". */
  secrets_total_exact: boolean;
  agents_active: number | null;
  runs_active: number | null;
  approvals_pending: number | null;
  leases_active: number | null;
  idle_lock_secs: number | null;
  idle_in: number | null;
  audit_bytes: number | null;
  audit_soft_limit: number | null;
  audit_hard_limit: number | null;
  vault_bytes: number | null;
  vault_max_bytes: number | null;
}

export interface ProjectEntry {
  name: string;
  paths: string[];
}

/**
 * Secret METADATA only: key + updated timestamp. There is deliberately no
 * `value` field on this type or anywhere in state — values live in the
 * form `<input>` for the moment of submission and nowhere else.
 */
export interface SecretMeta {
  key: string;
  updated: string;
}

// ---- D3 slices: agents, grants, approvals (HITL inbox) ----

/**
 * The five grantable capabilities, in canonical order. Single source of
 * truth for the Grants editor checkboxes. `manage` has no agent-callable op
 * consuming it yet, but grants holding it are real — omitting it here would
 * silently drop it on save (a privilege change the human never asked for).
 */
export const CAPABILITIES = ["read", "inject", "run", "reveal", "manage"] as const;
export type Capability = (typeof CAPABILITIES)[number];

/**
 * Capabilities the broker models and grants but no agent-callable op consumes
 * yet (`Op::Manage` in `src/model.rs`: management is human-only in the MVP).
 * They stay fully grantable and round-trip faithfully — this drives only the
 * "reserved" marker in the Grants editor, never the save/read path.
 */
export const RESERVED_CAPABILITIES: Record<string, true> = { manage: true };

/** Agent identity: name + status + token PREFIX. No token material, ever. */
export interface AgentEntry {
  name: string;
  status: string;
  token_prefix: string;
}

/** One agent × project grant. `ops` arrives as an array of lowercase strings. */
export interface GrantEntry {
  agent: string;
  project: string;
  ops: string[];
  revoked: boolean;
}

/**
 * One pending approval. `key` is a secret NAME (safe to show); the secret
 * VALUE is never in this type or anywhere in state.
 */
export interface ApprovalEntry {
  approval_id: string;
  agent: string;
  project: string;
  key: string;
  status: string;
  expires_at: string;
}

/**
 * `agent_add` result. `token` is one-time and can never be re-issued: hand
 * it to `takeOneTimeToken` (screens/agents.ts) for display and persist
 * nothing. `token_saved_path` echoes where the backend wrote it, if asked.
 */
export interface AgentAddResult {
  agent_id: string;
  token: string;
  token_saved_path: string | null;
}
/**
 * `reveal` result. Hand it to `takeRevealValue` (screens/reveal.ts) for
 * display and persist nothing — there is deliberately no state field that
 * can hold a revealed value (see ShellState below).
 */
export interface RevealResult {
  value: string;
}

/**
 * One live lease. The wire carries NO agent identity and NO credential
 * material — project + public lease_prefix + ops + status + expiry only.
 * `applyLeases` maps rows field-by-field so a smuggled extra key never lands.
 */
export interface LeaseEntry {
  lease_id: string;
  lease_prefix: string;
  project: string;
  ops: string[];
  expires_at: string;
  expires_in: number;
  /** "active" | "expired" | "revoked" — rendered via leaseStatusTone. */
  status: string;
}

/**
 * One agent run. Process detail only — never argv/env/cwd/executable.
 * `applyRuns` maps rows field-by-field so a smuggled extra key never lands.
 */
export interface RunEntry {
  run_id: string;
  agent: string;
  project: string;
  pid: number;
  started_at: string;
  status: string;
}
/** A destructive action awaiting its second (confirming) click. No payload beyond ids. */
export interface PendingConfirm {
  kind: "project" | "path" | "secret" | "agent" | "grant" | "lease";
  project: string;
  /** path for kind "path", secret key for kind "secret"; agent name for kind "agent" (in project) or kind "grant" (in extra); lease id for kind "lease" (in project). */
  extra?: string;
}

/** Which secret form is open. The value being typed is NOT here — it stays in the DOM input. */
export type SecretForm = { mode: "add" } | { mode: "edit"; key: string };

/**
 * Non-sensitive form UI only: pending confirmations, which action is busy,
 * which secret form is open, and the Grants editor draft awaiting its
 * save-confirm click. Plaintext secret values and the one-time agent token
 * NEVER enter this (or any) state slice — capability names are safe.
 */
export interface FormsState {
  pendingConfirm: PendingConfirm | null;
  busyAction: string | null;
  secretForm: SecretForm | null;
  /** Agent × project × capability names staged for the second save click. */
  grantDraft: GrantDraft | null;
  /**
   * The agent × project pair the grants editor is pointed at. It lives here
   * because every re-render rebuilds the screen: a pair held only by the DOM
   * would fall back to the first option of each list on the next repaint and
   * silently retarget the save.
   */
  grantPair: GrantPair | null;
}

/** Grants editor draft: ids plus capability names. Nothing sensitive. */
export interface GrantDraft {
  agent: string;
  project: string;
  ops: string[];
}

/** The grants editor's target pair. Ids only. */
export interface GrantPair {
  agent: string;
  project: string;
}

/** Connection/trust posture. `boot` = nothing known yet; `no-vault` = verified identity, no vault file yet. */
export type Conn = "boot" | "offline" | "untrusted" | "mismatch" | "no-vault" | "trusted";

export interface SessionState {
  present: boolean;
  prefix?: string;
  expiresAt?: string;
  expiresIn?: number;
  maxExpiresAt?: string;
  maxExpiresIn?: number;
}

/** Visual weight for pills/badges/chips. Declared here; `components.ts` imports it as a type. */
export type Tone = "ok" | "bad" | "warn" | "mute" | "info";

/**
 * Which tab the Projects detail shows. Interactive view state: it lives in
 * `ShellState` (not module-local) because `render()` wipes screen-local
 * state on every render, and it resets with the rest of state on lock.
 */
export type ProjectTab = "overview" | "secrets" | "access" | "paths";

export interface ShellState {
  conn: Conn;
  status: BrokerStatus | null;
  pin: PinStatus | null;
  session: SessionState;
  /** Wall-clock ms when the current session was seeded (unlock time). Never a secret. */
  unlockedAtMs: number;
  health: HealthResponse | null;
  error: MappedError | null;
  /** Set on E_VAULT_CORRUPT: a full stop the shell renders instead of any route. Cleared by boot/lock. */
  fatal: MappedError | null;
  /** True after an E_SESSION_EXPIRED: forces the unlock gate even if the vault reads unlocked. */
  sessionExpired: boolean;
  /** Last overview_refresh payload, or null before the first successful refresh. */
  overview: OverviewData | null;
  /** Broker project registry (names + authorized paths). Re-read after every mutation. */
  projects: ProjectEntry[] | null;
  /** Which project row is selected in the Projects list (survives refresh when still present). */
  selectedProject: string | null;
  /** Which tab the Projects detail shows. View state only — reset by lock. */
  projectTab: ProjectTab;
  /** Which project the Secrets screen is showing. Defaults to the first project after load. */
  activeProject: string | null;
  /** Secret keys (+updated) for activeProject. Metadata only — never values. */
  secrets: SecretMeta[] | null;
  /** Agent identities (name + status + token prefix). Re-read after every mutation. */
  agents: AgentEntry[] | null;
  /** Which agent row is selected in the Agents list (survives refresh when still present). */
  selectedAgent: string | null;
  /** Agent × project capability grants. Re-read after every mutation. */
  grants: GrantEntry[] | null;
  /** Pending human approvals (HITL inbox). Polled; re-read after every mutation. */
  approvals: ApprovalEntry[] | null;
  /**
   * Live leases. Prefixes/projects/ops/status/expiry only — agent identity
   * and credential material never appear here (the wire has neither). There
   * is deliberately NO field anywhere in this state that can hold a revealed
   * secret value — values live in the reveal modal's module-local only.
   */
  leases: LeaseEntry[] | null;
  /** Live agent runs. Process detail only — never argv/env/cwd. */
  runs: RunEntry[] | null;
  /**
   * Loaded audit pages, or null before the first successful read. Route-scoped:
   * released on leaving Audit, because the timeline is a view of one log range
   * and a stale page would misrepresent what has been read.
   */
  audit: AuditSlice | null;
  /** Local filter draft over the loaded audit pages. Nothing here is sent to the broker. */
  auditFilters: AuditFilters;
  /** Last verification report, or null when verification has not run. */
  auditVerify: AuditVerifyResult | null;
  /** Settings-observed metadata (the credential-free live fingerprint probe). */
  settings: SettingsSlice;
  forms: FormsState;
}

export function initialForms(): FormsState {
  return { pendingConfirm: null, busyAction: null, secretForm: null, grantDraft: null, grantPair: null };
}

export function initialState(): ShellState {
  return {
    conn: "boot",
    status: null,
    pin: null,
    session: { present: false },
    unlockedAtMs: 0,
    health: null,
    error: null,
    fatal: null,
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
    audit: null,
    auditFilters: initialAuditFilters(),
    auditVerify: null,
    settings: initialSettingsSlice(),
    forms: initialForms(),
  };
}

/**
 * Derive posture from the broker's own report. The broker is the authority:
 * - offline when it says it cannot reach the daemon;
 * - untrusted when this app has no pin yet (first contact);
 * - mismatch when a pin exists but the broker no longer verifies it
 *   (identity changed — fail closed, never auto-repin);
 * - no-vault when the pin verifies but no vault file exists yet;
 * - trusted only when the pin exists, verifies, AND a vault exists.
 * Trust outranks vault creation because trust is a CLI+TTY ceremony the
 * dashboard cannot perform; a verified identity with no vault is distinct and actionable, not offline.
 */
export function deriveConn(status: BrokerStatus, pin: PinStatus): Conn {
  if (!status.online) return "offline";
  if (!pin.pinned) return "untrusted";
  if (status.trusted === false) return "mismatch";
  if (status.initialized === false) return "no-vault";
  return "trusted";
}

/** Reconcile after a fresh `get_status` + `pin_status` pair. Keeps the session, D2/D3/D4 slices, and forms. */
export function applyBoot(prev: ShellState, status: BrokerStatus, pin: PinStatus): ShellState {
  return {
    ...initialState(),
    status,
    pin,
    conn: deriveConn(status, pin),
    session: prev.session,
    unlockedAtMs: prev.unlockedAtMs,
    sessionExpired: prev.sessionExpired,
    overview: prev.overview,
    projects: prev.projects,
    selectedProject: prev.selectedProject,
    projectTab: prev.projectTab,
    activeProject: prev.activeProject,
    secrets: prev.secrets,
    agents: prev.agents,
    selectedAgent: prev.selectedAgent,
    grants: prev.grants,
    approvals: prev.approvals,
    leases: prev.leases,
    runs: prev.runs,
    forms: prev.forms,
  };
}

const ABSENT_SESSION =
  "Unlocked, but no session was seeded — the next privileged action may ask for the passphrase again.";

/**
 * Apply a successful `unlock` response. The six session/expiry fields are
 * OPTIONAL: when absent, record "no session" and never fabricate one.
 */
export function applyUnlockSuccess(prev: ShellState, resp: UnlockResponse, nowMs: number): ShellState {
  const has = typeof resp.session_prefix === "string" && resp.session_prefix.length > 0;
  return {
    ...prev,
    status: prev.status ? { ...prev.status, locked: false } : prev.status,
    session: has
      ? {
          present: true,
          prefix: resp.session_prefix,
          expiresAt: resp.expires_at,
          expiresIn: resp.expires_in,
          maxExpiresAt: resp.max_expires_at,
          maxExpiresIn: resp.max_expires_in,
        }
      : { present: false },
    unlockedAtMs: nowMs,
    health: null,
    error: null,
    sessionExpired: false,
    forms: initialForms(),
  };
}

/** Lock clears every slice. Nothing sensitive may survive. */
export function applyLock(): ShellState {
  return initialState();
}

const KNOWN_CODE = /^(E_[A-Z0-9_]+|OFFLINE|UNTRUSTED|MISMATCH)$/;

/**
 * Single error-rendering path. Never assumes a raw exception: accepts the
 * backend's `{code, message}` shape, a bare string, or anything else.
 */
export function mapError(err: unknown): MappedError {
  if (typeof err === "string") return { code: "E_UNKNOWN", message: err || "Request failed." };
  if (err && typeof err === "object") {
    const o = err as Record<string, unknown>;
    const code = typeof o.code === "string" && KNOWN_CODE.test(o.code) ? o.code : "E_UNKNOWN";
    const message = typeof o.message === "string" && o.message ? o.message : "Request failed.";
    return { code, message };
  }
  return { code: "E_UNKNOWN", message: "Request failed." };
}

/** Full-stop error code: the vault file failed integrity checks. */
export const VAULT_CORRUPT = "E_VAULT_CORRUPT";

/**
 * Apply a failed call. A failed unlock (or any failure) never moves the
 * state to unlocked; a broker-identity failure escalates to the mismatch
 * screen and drops local session/health; offline escalates to offline.
 */
export function applyError(prev: ShellState, err: unknown): ShellState {
  const mapped = mapError(err);
  if (mapped.code === "E_SESSION_EXPIRED") {
    // The Rust-held session is gone; the vault may still read unlocked.
    // Force the unlock gate via sessionExpired — never retry automatically.
    return {
      ...prev,
      session: { present: false },
      unlockedAtMs: 0,
      sessionExpired: true,
      health: null,
      overview: prev.overview,
      error: mapped,
    };
  }
  if (mapped.code === "E_BROKER_UNTRUSTED" || mapped.code === "MISMATCH") {
    return { ...prev, conn: "mismatch", session: { present: false }, unlockedAtMs: 0, health: null, error: mapped };
  }
  if (mapped.code === "OFFLINE") {
    return { ...prev, conn: "offline", error: mapped };
  }
  if (mapped.code === VAULT_CORRUPT) {
    return { ...prev, error: mapped, fatal: mapped };
  }
  if (mapped.code === "E_LOCKED" && prev.status !== null) {
    // The vault really is locked broker-side, so this is an observation, not a guess.
    return { ...prev, status: { ...prev.status, locked: true }, error: mapped };
  }
  return { ...prev, error: mapped };
}

/** The one named thing the shell renders as a full stop: null unless the vault failed integrity checks. */
export function fatalStop(s: ShellState): MappedError | null {
  return s.fatal;
}

/**
 * One short actionable sentence per error code, or null when there is
 * nothing useful to add. Static map only — no guarantees, no retry claims,
 * no paths.
 */
export function errorAdvice(code: string): string | null {
  switch (code) {
    case "E_AUTH":
      return "The passphrase was wrong — nothing was unlocked. Try again.";
    case "E_LOCKED":
      return "The vault locked itself — unlock again to continue.";
    case "E_SESSION_EXPIRED":
      return "The human session lapsed — unlock again. It was not retried.";
    case "E_BUSY":
      return "The broker is at its concurrency limit — wait a moment and retry.";
    case "E_AUDIT_FULL":
      return "The audit log is at its ceiling — free space or rotate before further changes.";
    case "E_VAULT_CORRUPT":
      return "The vault file failed its integrity check — do not retry; investigate the vault file.";
    case "E_PERMISSION":
      return "The identity lacks the capability — check grants.";
    case "E_HUMAN_REQUIRED":
      return "This operation is human-only.";
    case "E_PATH_NOT_AUTHORIZED":
      return "Add the folder to the project first.";
    case "E_LEASE_EXPIRED":
      return "The lease lapsed or was revoked.";
    case "E_VAULT_TOO_LARGE":
      return "The vault would exceed its maximum size.";
    case "E_WEAK_PASSPHRASE":
      return "Choose a passphrase of at least 12 characters.";
    default:
      return null;
  }
}

// ---- D2 transitions (pure, DOM-free) ----

/**
 * Store a fresh `overview_refresh` payload. Counters the broker left null
 * stay null — never defaulted to 0. Callers render null as "—".
 */
export function applyOverview(prev: ShellState, data: OverviewData): ShellState {
  return { ...prev, overview: { ...data }, error: null };
}

/**
 * Store a fresh `projects_list` payload. Drops empty-named rows the broker
 * should never send (defensive), keeps selection only when still present,
 * defaults activeProject to the first project when unset or stale.
 */
export function applyProjects(prev: ShellState, projects: ProjectEntry[]): ShellState {
  const clean = projects.filter((p) => typeof p.name === "string" && p.name.length > 0);
  const present = (name: string | null): name is string =>
    name !== null && clean.some((p) => p.name === name);
  const selectedProject = present(prev.selectedProject) ? prev.selectedProject : null;
  const activeProject = present(prev.activeProject) ? prev.activeProject : (clean[0]?.name ?? null);
  const secrets = activeProject !== prev.activeProject ? null : prev.secrets;
  return { ...prev, projects: clean, selectedProject, activeProject, secrets, error: null };
}
/** Record which project the Secrets screen shows. The old key list is stale until re-read. */
export function applyActiveProject(prev: ShellState, name: string): ShellState {
  if (name === prev.activeProject) return prev;
  return { ...prev, activeProject: name, secrets: null, error: null, forms: initialForms() };
}

/** Record which project row is selected in the Projects list. */
export function applySelectedProject(prev: ShellState, name: string | null): ShellState {
  return { ...prev, selectedProject: name };
}

/**
 * Runtime pin: a secrets row MUST carry only key+updated. Throws when a
 * `value` key is present, so a payload smuggling a value fails loudly.
 * (The type level already forbids it: `SecretMeta` has no `value` field.)
 */
export function assertMetadataOnly(row: unknown): void {
  if (row !== null && typeof row === "object" && "value" in row) {
    throw new Error("secret row must not carry a value field");
  }
}

/**
 * Store a fresh `secrets_list` payload for one project. Metadata only:
 * rows carry key+updated; the runtime check above rejects a `value` key.
 */
export function applySecrets(prev: ShellState, project: string, secrets: SecretMeta[]): ShellState {
  const clean = secrets
    .filter((e) => typeof e.key === "string" && e.key.length > 0)
    .map((e) => {
      assertMetadataOnly(e);
      return { key: e.key, updated: typeof e.updated === "string" ? e.updated : "" };
    });
  return { ...prev, activeProject: project, secrets: clean, error: null };
}

/**
 * Mark a mutation boundary: clear pending form UI and record which action
 * is busy. The caller MUST re-read from the broker (projects_list /
 * secrets_list / overview_refresh) before rendering the result — no
 * optimistic inserts. The affected list slices are intentionally NOT
 * cleared here: loadProjectsList/loadSecretsList render their own busy
 * states, and mutate* re-reads right after (clearing would flash empty).
 */
export function applyMutationStart(prev: ShellState, action: string): ShellState {
  return {
    ...prev,
    forms: { pendingConfirm: null, secretForm: null, grantDraft: null, grantPair: prev.forms.grantPair, busyAction: action },
    error: null,
  };
}

/** Clear the busy marker after a mutation settles (success or failure). */
export function applyMutationDone(prev: ShellState): ShellState {
  return { ...prev, forms: { ...prev.forms, busyAction: null } };
}

/**
 * Whether the session-expired gate forces the unlock screen. The vault may
 * still read unlocked (the session TTL is shorter than the idle-lock), so
 * `canOfferUnlock`'s `locked` requirement alone is not sufficient.
 */
export function mustOfferUnlockForExpiry(s: ShellState): boolean {
  return s.conn === "trusted" && s.sessionExpired;
}

/**
 * The unlock gate is reachable when the vault reads locked (existing rule)
 * OR when a human session expired underneath an unlocked vault (the
 * session TTL is shorter than the vault idle-lock). Exported so it is
 * unit-testable without a DOM. Call sites MUST use this — never
 * `canOfferUnlock` alone — for the trusted-branch gate decision.
 */
export function needsUnlockGate(s: ShellState): boolean {
  return canOfferUnlock(s) || mustOfferUnlockForExpiry(s);
}

/**
 * WHY the unlock gate is up, as the one thing the gate copy keys off.
 *
 * Both causes land on the same screen but they are different facts and must
 * not share a heading: `locked` means the vault itself is locked (the lock
 * pill in the chrome agrees, so "Vault is locked" is consistent); `session`
 * means the vault is STILL UNLOCKED broker-side while this app holds no
 * usable human session, so the pill reads `unlocked` — telling the human
 * "Vault is locked" there is a visibly false statement about their own vault.
 * Precedence: a genuinely locked vault is reported as locked even if a
 * session also lapsed, because the lock is the stronger fact.
 *
 * Pure and exported so it is unit-testable without a DOM. Precondition: call
 * only when `needsUnlockGate(s)` is true.
 */
export function unlockGateReason(s: ShellState): "locked" | "session" {
  return canOfferUnlock(s) ? "locked" : "session";
}

/** Whether the unlock gate may be offered. Trusted posture only — every other
 * posture (boot, offline, untrusted, mismatch) shows no gate and sends no
 * passphrase. Exported so it is unit-testable without a DOM. */
export function canOfferUnlock(s: ShellState): boolean {
  return s.conn === "trusted" && s.status !== null && s.status.locked;
}

/**
 * Render a nullable broker counter honestly: null is the broker staying
 * silent (locked/offline/untrusted) and renders as "—" — never 0.
 */
export function fmtCount(n: number | null): string {
  return n === null ? "—" : String(n);
}

/**
 * Render the broker's secret total: exact counts as "N", capped counts as
 * "≥ N" (the broker counted only up to a cap). Null stays "—".
 */
export function fmtSecretsTotal(n: number | null, exact: boolean): string {
  if (n === null) return "—";
  return exact ? String(n) : `≥ ${n}`;
}

/** One-line audit usage without implying any verification result. Null-safe. */
export function fmtAuditUsage(bytes: number | null, soft: number | null, hard: number | null): string {
  if (bytes === null || soft === null || hard === null) return "—";
  return `${fmtBytes(bytes)} of ${fmtBytes(soft)} (soft) / ${fmtBytes(hard)} (hard)`;
}

/**
 * Whether the backend currently holds a human session for this app, per the
 * latest overview payload (authoritative — present in posture-only payloads
 * too). Falls back to the local session slice only when no payload, or a
 * malformed one without the field, is available: the local flag can go
 * stale after a silent TTL lapse (300 s session vs 900 s idle-lock).
 */
export function sessionHeld(s: ShellState): boolean {
  if (!s.overview) return s.session.present;
  const o: unknown = s.overview;
  if (o !== null && typeof o === "object" && "session_held" in o) {
    const raw: unknown = o.session_held;
    if (typeof raw === "boolean") return raw;
  }
  return s.session.present;
}

/**
 * Honest hint for the Overview counts area. Three cases, not two:
 * - locked → unlock first;
 * - unlocked but the backend holds no human session → counts cannot be read
 *   here; unlocking again establishes one (Refresh cannot help);
 * - otherwise → not loaded yet; press Refresh.
 * The middle case reads the backend's `session_held`, never the possibly
 * stale local flag alone (see `sessionHeld`).
 */
export function overviewHint(s: ShellState): string {
  if (s.status?.locked) {
    return "Detailed counts are available after unlock — unlock, then press Refresh.";
  }
  if (!sessionHeld(s)) {
    return "The vault is open but this app holds no human session, so counts cannot be read and closing this window will not lock the vault — run `svault lock` in a terminal, then unlock here again to establish a session.";
  }
  return "Counts are not loaded yet — press Refresh.";
}

/** True when an overview payload carries no counters at all (posture-only). */
export function isPostureOnly(o: OverviewData): boolean {
  return (
    o.projects === null &&
    o.secrets_total === null &&
    o.agents_active === null &&
    o.runs_active === null &&
    o.approvals_pending === null &&
    o.leases_active === null &&
    o.idle_lock_secs === null &&
    o.audit_bytes === null &&
    o.vault_bytes === null
  );
}

/** Byte scale shared with the settings/health surfaces — one definition. */
export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MiB`;
}

/**
 * Whether Overview may render the Human-session card. The card describes an
 * unlock outcome, so it exists only when actually unlocked: trusted AND
 * status known AND not locked. Every other posture renders no session card
 * at all — this is what keeps ABSENT_SESSION honest (it is only reachable
 * post-unlock). Named and exported so it is unit-testable without a DOM.
 */
export function showSessionCard(s: ShellState): boolean {
  return s.conn === "trusted" && s.status !== null && !s.status.locked;
}

/**
 * Human-readable session line for an observed unlock outcome. Precondition:
 * call only when showSessionCard() is true. Never invents a session: when
 * the broker seeded none, says so plainly instead of fabricating one.
 */
export function sessionText(s: SessionState, nowMs: number, unlockedAtMs: number): string {
  if (!s.present) return ABSENT_SESSION;
  const label = s.prefix ? `Session ${s.prefix}` : "Session";
  if (typeof s.expiresIn === "number" && unlockedAtMs > 0) {
    const remain = Math.max(0, Math.floor(s.expiresIn - (nowMs - unlockedAtMs) / 1000));
    if (remain <= 0) return `${label} has expired — the next privileged action may ask for the passphrase again.`;
    if (s.expiresAt) return `${label} active — about ${remain}s remaining (expires ${s.expiresAt}).`;
    return `${label} active — about ${remain}s remaining.`;
  }
  if (s.expiresAt) return `${label} active (expires ${s.expiresAt}).`;
  return `${label} active.`;
}

/** Credential-shaped runs: long token-like strings (base64url-ish, 32+ chars). */
const TOKEN_LIKE = /[A-Za-z0-9_\-+/=]{32,}/g;
/** Public identity material that is safe to keep visible in logs. */
const PUBLIC_ID = /^[0-9a-fA-F]{8}$|^[0-9a-fA-F]{64}$/;

/**
 * The single guard for anything logged. Replaces caller-supplied secrets
 * verbatim, then masks any remaining credential-shaped token run while
 * leaving fingerprints / session prefixes (public identity) readable.
 */
export function redactForLog(text: string, secrets: readonly string[] = []): string {
  let out = text;
  for (const s of secrets) {
    if (s && s.length >= 2 && out.includes(s)) out = out.split(s).join("[redacted]");
  }
  return out.replace(TOKEN_LIKE, (m) => (PUBLIC_ID.test(m) ? m : "[credential]"));
}

// --- Router (no dependency) ---

export const ROUTES = [
  { id: "overview", hash: "#/", label: "Overview" },
  { id: "projects", hash: "#/projects", label: "Projects" },
  { id: "secrets", hash: "#/secrets", label: "Secrets" },
  { id: "agents", hash: "#/agents", label: "Agents" },
  { id: "grants", hash: "#/grants", label: "Grants" },
  { id: "leases", hash: "#/leases", label: "Leases" },
  { id: "approvals", hash: "#/approvals", label: "Approvals" },
  { id: "runs", hash: "#/runs", label: "Runs" },
  { id: "audit", hash: "#/audit", label: "Audit" },
  { id: "settings", hash: "#/settings", label: "Settings" },
] as const;

export type RouteId = (typeof ROUTES)[number]["id"];

export function routeFor(hash: string): RouteId {
  const found = ROUTES.find((r) => r.hash === hash);
  return found ? found.id : "overview";
}

// ---- D3 transitions (pure, DOM-free) ----

/**
 * Store a fresh `agents_list` payload. Drops empty-named rows the broker
 * should never send (defensive). Re-read is mandatory after any mutation —
 * no optimistic inserts. Carries no token material (prefix only).
 */
export function applyAgents(prev: ShellState, agents: AgentEntry[]): ShellState {
  const clean = agents
    .filter((a) => typeof a.name === "string" && a.name.length > 0)
    .map((a) => ({
      name: a.name,
      status: typeof a.status === "string" ? a.status : "",
      token_prefix: typeof a.token_prefix === "string" ? a.token_prefix : "",
    }));
  // Mirror applyProjects: keep the selection only when still present.
  const selectedAgent =
    prev.selectedAgent !== null && clean.some((a) => a.name === prev.selectedAgent)
      ? prev.selectedAgent
      : null;
  return { ...prev, agents: clean, selectedAgent, error: null };
}

/** Store a fresh `grants_list` payload. Same no-optimism discipline. */
export function applyGrants(prev: ShellState, grants: GrantEntry[]): ShellState {
  const clean = grants
    .filter((g) => typeof g.agent === "string" && g.agent.length > 0 && typeof g.project === "string" && g.project.length > 0)
    .map((g) => ({
      agent: g.agent,
      project: g.project,
      ops: Array.isArray(g.ops) ? g.ops.filter((o) => typeof o === "string") : [],
      revoked: g.revoked === true,
    }));
  return { ...prev, grants: clean, error: null };
}

/**
 * Store a fresh `approvals_pending` payload. Re-read after every
 * approve/deny — rows are never removed optimistically.
 */
export function applyApprovals(prev: ShellState, approvals: ApprovalEntry[]): ShellState {
  const clean = approvals
    .filter((a) => typeof a.approval_id === "string" && a.approval_id.length > 0)
    .map((a) => ({
      approval_id: a.approval_id,
      agent: typeof a.agent === "string" ? a.agent : "",
      project: typeof a.project === "string" ? a.project : "",
      key: typeof a.key === "string" ? a.key : "",
      status: typeof a.status === "string" ? a.status : "",
      expires_at: typeof a.expires_at === "string" ? a.expires_at : "",
    }));
  return { ...prev, approvals: clean, error: null };
}

/**
 * Pending-approvals count for the global badge. Null when the broker has
 * not answered (unknown) — NEVER a fabricated 0. Renders as nothing/"—".
 */
export function approvalCount(s: ShellState): number | null {
  return s.approvals === null ? null : s.approvals.length;
}

export interface ApprovalCountdown {
  expired: boolean;
  /** ms until expiry; always >= 0 — never a negative number. */
  remainingMs: number;
  label: string;
}

/**
 * Countdown label for an approval's remaining lifetime. Delegates to the one
 * duration formatter ([`fmtDuration`], seconds) so the app has a single
 * duration vocabulary; `ms` is only rounded down to whole seconds here.
 */
function fmtCountdownMs(ms: number): string {
  return fmtDuration(Math.floor(ms / 1000));
}

/**
 * Pure countdown for an approval's `expires_at`, recomputed on every render
 * from the broker's timestamp vs now. Past timestamps report "expired" with
 * remainingMs 0 — never a negative time. Unparseable timestamps stay honest
 * ("expiry unknown") instead of inventing a number.
 */
export function approvalCountdown(expiresAt: string, nowMs: number): ApprovalCountdown {
  const ms = Date.parse(expiresAt) - nowMs;
  if (Number.isNaN(ms)) return { expired: false, remainingMs: 0, label: "expiry unknown" };
  if (ms <= 0) return { expired: true, remainingMs: 0, label: "expired" };
  return { expired: false, remainingMs: ms, label: `expires in ${fmtCountdownMs(ms)}` };
}

/**
 * Whether the proposed capability set WIDENS current authority: true when
 * it adds ANY capability (especially `manage`/`reveal`), even alongside
 * removals. Drives the save-confirmation step in the Grants editor.
 */
export function grantWidens(current: readonly string[], proposed: readonly string[]): boolean {
  return proposed.some((c) => current.indexOf(c) < 0);
}

/** Whether saving `proposed` would remove `run` — terminates the agent's active runs. */
export function grantRunRemoved(current: readonly string[], proposed: readonly string[]): boolean {
  return current.indexOf("run") >= 0 && proposed.indexOf("run") < 0;
}

// ---- D4 transitions (pure, DOM-free) ----

/**
 * Store a fresh `leases_list` payload. Same no-optimism discipline: rows
 * are mapped field-by-field, so a payload smuggling a credential-shaped key
 * (e.g. `lease_credential`) or an invented `agent` identity never lands.
 */
export function applyLeases(prev: ShellState, leases: LeaseEntry[]): ShellState {
  const clean = leases
    .filter((l) => typeof l.lease_id === "string" && l.lease_id.length > 0)
    .map((l) => ({
      lease_id: l.lease_id,
      lease_prefix: typeof l.lease_prefix === "string" ? l.lease_prefix : "",
      project: typeof l.project === "string" ? l.project : "",
      ops: Array.isArray(l.ops) ? l.ops.filter((o) => typeof o === "string") : [],
      expires_at: typeof l.expires_at === "string" ? l.expires_at : "",
      expires_in: typeof l.expires_in === "number" ? l.expires_in : 0,
      status: typeof l.status === "string" ? l.status : "",
    }));
  return { ...prev, leases: clean, error: null };
}

/**
 * Store a fresh `runs_list` payload. Rows are mapped field-by-field, so a
 * payload smuggling process detail (`argv`/`env`/`cwd`/`executable`) never
 * lands — the dashboard shows identity and status only.
 */
export function applyRuns(prev: ShellState, runs: RunEntry[]): ShellState {
  const clean = runs
    .filter((r) => typeof r.run_id === "string" && r.run_id.length > 0)
    .map((r) => ({
      run_id: r.run_id,
      agent: typeof r.agent === "string" ? r.agent : "",
      project: typeof r.project === "string" ? r.project : "",
      pid: typeof r.pid === "number" ? r.pid : 0,
      started_at: typeof r.started_at === "string" ? r.started_at : "",
      status: typeof r.status === "string" ? r.status : "",
    }));
  return { ...prev, runs: clean, error: null };
}

/**
 * Pill tone for the three lease states, kept visually unambiguous: active
 * (ok), expired (mute), revoked (bad). Anything unrecognized renders mute —
 * never an approving tone for an unknown state.
 */
export function leaseStatusTone(status: string): "ok" | "mute" | "bad" {
  const lower = typeof status === "string" ? status.toLowerCase() : "";
  if (lower === "active") return "ok";
  if (lower === "revoked") return "bad";
  return "mute";
}

// ---- D5 additions (pure, DOM-free) ----
//
// Interactive view state (projectTab, selectedAgent) lives in ShellState
// because render() wipes screen-local state on every render. Secret VALUES
// never enter state — see the ShellState comment above.

/** Record which tab the Projects detail shows. View state only. */
export function applyProjectTab(prev: ShellState, tab: ProjectTab): ShellState {
  return { ...prev, projectTab: tab };
}

/** Record which agent row is selected in the Agents list. */
export function applySelectedAgent(prev: ShellState, name: string | null): ShellState {
  return { ...prev, selectedAgent: name };
}

/** Project row by exact name, or null. */
export function projectByName(s: ShellState, name: string): ProjectEntry | null {
  const found = (s.projects ?? []).find((p) => p.name === name);
  return found ?? null;
}

/** Locale-independent string order: plain </> comparison, never localeCompare. */
function cmpStr(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Non-revoked grants for one project (empty array when grants are not loaded). */
export function activeGrantsFor(s: ShellState, project: string): GrantEntry[] {
  if (s.grants === null) return [];
  return s.grants.filter((g) => g.project === project && g.revoked === false);
}

/**
 * Ops of the ACTIVE grant for one agent × project, or null when the pair holds
 * none. The broker keeps a revoked row and appends a new active one on a
 * re-grant, and `grants.list` returns the revoked row first — so any baseline
 * derived from `grants.find(pair)` without this filter describes an authority
 * the agent does not have. Every widen/narrow decision must use this.
 */
export function activeGrantOps(s: ShellState, agent: string, project: string): string[] | null {
  if (s.grants === null) return null;
  const g = s.grants.find((x) => x.agent === agent && x.project === project && x.revoked === false) ?? null;
  return g ? [...g.ops] : null;
}

/** Agents with a non-revoked grant on `project`, with their ops. Sorted by agent name. */
export function agentsWithAccess(s: ShellState, project: string): Array<{ agent: string; ops: string[] }> {
  return activeGrantsFor(s, project)
    .map((g) => ({ agent: g.agent, ops: [...g.ops] }))
    .sort((a, b) => cmpStr(a.agent, b.agent));
}

/** Non-revoked grants held by one agent, with the project name. Sorted by project. */
export function projectsForAgent(s: ShellState, agent: string): Array<{ project: string; ops: string[] }> {
  if (s.grants === null) return [];
  return s.grants
    .filter((g) => g.agent === agent && g.revoked === false)
    .map((g) => ({ project: g.project, ops: [...g.ops] }))
    .sort((a, b) => cmpStr(a.project, b.project));
}

/** Sorted union of agent names and project names referenced by non-revoked grants. */
export function capabilityMatrix(s: ShellState): { agents: string[]; projects: string[] } {
  if (s.grants === null) return { agents: [], projects: [] };
  const agents = new Set<string>();
  const projects = new Set<string>();
  for (const g of s.grants) {
    if (g.revoked !== false) continue;
    agents.add(g.agent);
    projects.add(g.project);
  }
  return {
    agents: [...agents].sort(cmpStr),
    projects: [...projects].sort(cmpStr),
  };
}

/**
 * Visual weight of a capability: reveal/manage => "warn", run/inject =>
 * "info", read => "mute", anything unknown => "mute". Never returns an
 * approving tone for an unknown capability.
 */
export function capabilityTone(cap: string): Tone {
  const lower = typeof cap === "string" ? cap.toLowerCase() : "";
  if (lower === "reveal" || lower === "manage") return "warn";
  if (lower === "run" || lower === "inject") return "info";
  return "mute";
}

/** Agent status tone: active => "ok", revoked => "bad", anything else => "mute". */
export function agentStatusTone(status: string): Tone {
  const lower = typeof status === "string" ? status.toLowerCase() : "";
  if (lower === "active") return "ok";
  if (lower === "revoked") return "bad";
  return "mute";
}

/** Run status tone: running/active => "ok", failed/error/killed => "bad", else "mute". */
export function runStatusTone(status: string): Tone {
  const lower = typeof status === "string" ? status.toLowerCase() : "";
  if (lower === "running" || lower === "active") return "ok";
  if (lower === "failed" || lower === "error" || lower === "killed") return "bad";
  return "mute";
}

/**
 * Pending decided-ness tone for an approval row: pending => "warn",
 * approved => "ok", denied => "bad", else "mute".
 */
export function approvalStatusTone(status: string): Tone {
  const lower = typeof status === "string" ? status.toLowerCase() : "";
  if (lower === "pending") return "warn";
  if (lower === "approved") return "ok";
  if (lower === "denied") return "bad";
  return "mute";
}

/**
 * Short relative age ("just now", "4m ago", "2h ago", "3d ago") from an ISO
 * timestamp. Unparseable or empty input => "unknown" (never a fabricated
 * time). Future => "just now". Never negative.
 */
export function fmtRelative(iso: string, nowMs: number): string {
  if (typeof iso !== "string" || iso.length === 0) return "unknown";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "unknown";
  const diffMs = nowMs - t;
  if (diffMs < 60_000) return "just now";
  const diffSec = Math.floor(diffMs / 1000);
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  return `${Math.floor(diffSec / 86400)}d ago`;
}

/**
 * Count of keys currently loaded for one project, or null when that
 * project's key list is not the loaded one (honest: unknown, never 0).
 */
export function loadedSecretCount(s: ShellState, project: string): number | null {
  if (s.secrets === null || s.activeProject !== project) return null;
  return s.secrets.length;
}

/**
 * Actionable "needs attention" items derived ONLY from real broker data.
 * Each item is a plain description plus the hash route to act on; an empty
 * array is a valid, honest answer. Pure function of ShellState: no DOM, no
 * timers, no invented numbers or health verdicts.
 */
export function attentionItems(
  s: ShellState,
  nowMs: number,
): Array<{ id: string; tone: Tone; title: string; detail: string; route: string }> {
  const items: Array<{ id: string; tone: Tone; title: string; detail: string; route: string }> = [];
  if (s.approvals !== null && s.approvals.length > 0) {
    const n = s.approvals.length;
    items.push({
      id: "approvals-pending",
      tone: "warn",
      title: `${n} pending approval${n === 1 ? "" : "s"}`,
      detail: "Human approval is waiting — review the inbox before anything auto-expires.",
      route: "#/approvals",
    });
  }
  if (s.sessionExpired) {
    items.push({
      id: "session-expired",
      tone: "warn",
      title: "Session expired",
      detail: "The human session expired — unlock again to continue.",
      route: "#/",
    });
  }
  if (s.overview !== null && isPostureOnly(s.overview) && !s.overview.locked && !sessionHeld(s)) {
    items.push({
      id: "overview-posture-only",
      tone: "info",
      title: "Counts not loaded",
      detail: "The broker reported posture only — press Refresh to load counts.",
      route: "#/",
    });
  }
  const o = s.overview;
  // The 80% limit thresholds live in ONE place (`auditLimitWarning` /
  // `vaultLimitWarning`), shared with the Settings health warnings — two
  // copies of the same constant is exactly the drift this avoids.
  if (o !== null) {
    const a = auditLimitWarning(o.audit_bytes, o.audit_soft_limit, o.audit_hard_limit);
    if (a !== null) items.push({ ...a, route: "#/audit" });
    const v = vaultLimitWarning(o.vault_bytes, o.vault_max_bytes);
    if (v !== null) items.push({ ...v, route: "#/" });
  }
  const sessionWarn = sessionExpiryWarning(s, nowMs);
  if (sessionWarn !== null) items.push({ ...sessionWarn, route: "#/settings" });
  if (s.conn === "trusted" && s.status !== null && !s.status.locked && !sessionHeld(s)) {
    items.push({
      id: "no-session",
      tone: "warn",
      title: "Unlocked but no human session",
      detail:
        "The vault is open but this app holds no human session — closing this window will not lock it. Lock it with `svault lock` in a terminal, then unlock here again.",
      route: "#/",
    });
  }
  if (s.grants !== null && s.grants.some((g) => g.revoked === true)) {
    const n = s.grants.filter((g) => g.revoked === true).length;
    items.push({
      id: "grants-revoked",
      tone: "mute",
      title: `${n} revoked grant${n === 1 ? "" : "s"} still listed`,
      detail: "Revoked grants are kept for audit — they grant nothing.",
      route: "#/grants",
    });
  }
  return items;
}

// ---- D6: audit timeline, verification, settings + health warnings ----

/**
 * Page size for one audit read. 50 keeps a page dense enough to triage while
 * one read stays cheap — and every read appends ONE entry to the log being
 * read, so this number is also the cost of opening the screen.
 */
export const AUDIT_PAGE_SIZE = 50;

/** The 80% usage threshold both limit warnings share. One definition, two consumers. */
const LIMIT_WARN_RATIO = 0.8;

/** Below this many seconds of session life, warn before the next action asks again. */
const SESSION_WARN_SECS = 60;

export function initialAuditFilters(): AuditFilters {
  return { actor: "", op: "", project: "", decision: "" };
}

export function initialSettingsSlice(): SettingsSlice {
  return { probedFingerprint: null, probedAtMs: 0 };
}

/**
 * Sanitize one wire row into an AuditEntry. A row without a numeric `seq` is
 * dropped (returns null): a timeline position that cannot be ordered is not
 * something to render as if it had one.
 */
function sanitizeAuditEntry(row: unknown): AuditEntry | null {
  if (row === null || typeof row !== "object") return null;
  const r = row as Record<string, unknown>;
  const seq = typeof r.seq === "number" ? r.seq : Number.NaN;
  if (!Number.isFinite(seq)) return null;
  const str = (v: unknown): string => (typeof v === "string" ? v : "");
  const opt = (v: unknown): string | undefined =>
    typeof v === "string" && v.length > 0 ? v : undefined;
  return {
    seq,
    ts: str(r.ts),
    actor: str(r.actor),
    op: str(r.op),
    project: opt(r.project),
    keys: Array.isArray(r.keys) ? r.keys.filter((k): k is string => typeof k === "string") : [],
    decision: str(r.decision),
    reason: opt(r.reason),
    run_id: opt(r.run_id),
    authenticated: r.authenticated === true,
  };
}

function sanitizeAuditPage(page: {
  entries: AuditEntry[];
  next_before_seq?: number | null;
}): { entries: AuditEntry[]; nextBeforeSeq: number | null } {
  const rows = Array.isArray(page.entries) ? page.entries : [];
  const entries = rows
    .map((r) => sanitizeAuditEntry(r))
    .filter((e): e is AuditEntry => e !== null);
  const next = page.next_before_seq;
  return { entries, nextBeforeSeq: typeof next === "number" ? next : null };
}

/** Newest page REPLACES the slice — a reload is not an append. */
export function applyAuditFirstPage(
  prev: ShellState,
  page: { entries: AuditEntry[]; next_before_seq?: number | null },
): ShellState {
  return { ...prev, audit: sanitizeAuditPage(page), error: null };
}

/**
 * Older page APPENDS, keeping the slice ascending by seq. Entries already
 * loaded are dropped by seq: a repeated "Load older" click (or an
 * overlapping page) must not duplicate a row.
 */
export function applyAuditOlderPage(
  prev: ShellState,
  page: { entries: AuditEntry[]; next_before_seq?: number | null },
): ShellState {
  const incoming = sanitizeAuditPage(page);
  const existing = prev.audit;
  if (existing === null) return { ...prev, audit: incoming, error: null };
  const seen = new Set(existing.entries.map((e) => e.seq));
  const merged = existing.entries.concat(incoming.entries.filter((e) => !seen.has(e.seq)));
  merged.sort((a, b) => a.seq - b.seq);
  return {
    ...prev,
    audit: { entries: merged, nextBeforeSeq: incoming.nextBeforeSeq },
    error: null,
  };
}

/** Release the route-scoped audit slices (leaving Audit, or a lock). */
export function clearAudit(prev: ShellState): ShellState {
  return {
    ...prev,
    audit: null,
    auditVerify: null,
    auditFilters: initialAuditFilters(),
  };
}

export function applyAuditVerify(prev: ShellState, r: AuditVerifyResult): ShellState {
  return { ...prev, auditVerify: { ...r }, error: null };
}

export function applyAuditFilters(prev: ShellState, f: Partial<AuditFilters>): ShellState {
  return { ...prev, auditFilters: { ...prev.auditFilters, ...f } };
}

/**
 * Local filter over the pages already loaded. Case-insensitive substring for
 * actor/op/project; exact (case-insensitive) match for decision when set. An
 * all-empty filter returns the input order untouched.
 */
export function filterAuditEntries(
  entries: readonly AuditEntry[],
  f: AuditFilters,
): AuditEntry[] {
  const needle = (needle: string): string => needle.trim().toLowerCase();
  const actor = needle(f.actor);
  const op = needle(f.op);
  const project = needle(f.project);
  const decision = needle(f.decision);
  const has = (v: string | undefined, q: string): boolean =>
    q === "" || (v !== undefined && v.toLowerCase().includes(q));
  return entries.filter(
    (e) =>
      has(e.actor, actor) &&
      has(e.op, op) &&
      has(e.project, project) &&
      (decision === "" || e.decision.toLowerCase() === decision),
  );
}

/** Whether an older page can still be fetched (a real cursor is outstanding). */
export function auditHasOlder(s: ShellState): boolean {
  return s.audit !== null && s.audit.nextBeforeSeq !== null;
}

/** `allowed` reads as a normal decision, `denied` as a refusal; anything else is unknown. */
export function decisionTone(decision: string): Tone {
  const lower = typeof decision === "string" ? decision.toLowerCase() : "";
  if (lower === "allowed") return "ok";
  if (lower === "denied") return "bad";
  return "mute";
}

/**
 * RFC3339 -> `YYYY-MM-DD HH:MM:SS` in LOCAL time, for reading a dense table.
 * The exact wire instant stays available as a title attribute on the cell.
 * Unparsable/empty input is "unknown" rather than a fabricated epoch.
 */
export function fmtAuditTs(iso: string): string {
  if (typeof iso !== "string" || iso.length === 0) return "unknown";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "unknown";
  const d = new Date(t);
  const p = (n: number): string => String(n).padStart(2, "0");
  return (
    `${String(d.getFullYear()).padStart(4, "0")}-${p(d.getMonth() + 1)}-${p(d.getDate())} ` +
    `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
  );
}

/**
 * Record a live probe result. DISPLAY ONLY: this never touches `pin`, because
 * the dashboard has no pin-write path — a probed fingerprint exists only so a
 * human can compare it against the pinned one.
 */
export function applySettingsProbe(
  prev: ShellState,
  fingerprint: string | null,
  nowMs: number,
): ShellState {
  return {
    ...prev,
    settings: {
      probedFingerprint: typeof fingerprint === "string" && fingerprint.length > 0 ? fingerprint : null,
      probedAtMs: nowMs,
    },
  };
}

function limitRatio(value: number | null, max: number | null): number | null {
  if (typeof value !== "number" || typeof max !== "number") return null;
  if (!Number.isFinite(value) || !Number.isFinite(max) || max <= 0) return null;
  return value / max;
}

/**
 * Audit-log pressure. A WARNING, never an error: the broker is healthy and
 * still serving; only ordinary operations pay for the remaining headroom.
 * Returns null whenever any input is unknown, so a locked/silent broker can
 * never manufacture a limit alarm.
 */
export function auditLimitWarning(
  bytes: number | null,
  soft: number | null,
  hard: number | null,
): HealthWarning | null {
  const ratio = limitRatio(bytes, soft);
  if (ratio === null || ratio < LIMIT_WARN_RATIO) return null;
  const used = fmtBytes(bytes as number);
  const softTxt = fmtBytes(soft as number);
  const past = ratio >= 1;
  return {
    id: "audit-near-limit",
    tone: "warn",
    title: past ? "Audit log is at its soft limit" : "Audit log near its soft limit",
    detail: past
      ? `${used} of ${softTxt} used — ordinary operations are now refused (E_AUDIT_FULL); ` +
        `lifecycle actions still apply. Hard limit ${hard === null ? "—" : fmtBytes(hard)}.`
      : `${used} of ${softTxt} used (soft limit). Ordinary writes are refused once it is reached.`,
  };
}

/** Vault file pressure. Same discipline: a real ratio or nothing, and never an error. */
export function vaultLimitWarning(
  bytes: number | null,
  max: number | null,
): HealthWarning | null {
  const ratio = limitRatio(bytes, max);
  if (ratio === null || ratio < LIMIT_WARN_RATIO) return null;
  return {
    id: "vault-near-max",
    tone: "warn",
    title: "Vault file near its maximum",
    detail: `${fmtBytes(bytes as number)} of ${fmtBytes(max as number)} used.`,
  };
}

/**
 * Human-session life. Only warns when a session is actually held and its
 * remaining life is under a minute, computed exactly as `sessionText` does.
 * Null when nothing is held — an absent session is not an expiry.
 */
export function sessionExpiryWarning(s: ShellState, nowMs: number): HealthWarning | null {
  if (!s.session.present) return null;
  if (typeof s.session.expiresIn !== "number" || s.unlockedAtMs <= 0) return null;
  const remain = Math.max(0, Math.floor(s.session.expiresIn - (nowMs - s.unlockedAtMs) / 1000));
  if (remain >= SESSION_WARN_SECS) return null;
  return {
    id: "session-about-to-expire",
    tone: "warn",
    title: remain <= 0 ? "Human session expired" : "Human session about to expire",
    detail:
      remain <= 0
        ? "The human session has lapsed — the next privileged action may ask for the passphrase again."
        : `About ${remain}s of session life left — the next privileged action may ask for the passphrase again.`,
  };
}

/**
 * Every operational warning that has a REAL basis, in reading order. A warning
 * is never promoted to an error here: the connection posture owns
 * offline/untrusted/mismatch, and a healthy broker nearing a limit stays
 * healthy.
 */
export function healthWarnings(s: ShellState, nowMs: number): HealthWarning[] {
  const out: HealthWarning[] = [];
  if (s.health !== null) {
    const audit = auditLimitWarning(
      s.health.audit_bytes,
      s.health.audit_soft_limit,
      s.health.audit_hard_limit,
    );
    if (audit !== null) out.push(audit);
    const vault = vaultLimitWarning(s.health.vault_bytes, s.health.vault_max_bytes);
    if (vault !== null) out.push(vault);
  }
  const session = sessionExpiryWarning(s, nowMs);
  if (session !== null) out.push(session);
  return out;
}

/** Durations in the largest two units, integers only. `0 s` is honest, not "—". */
export function fmtDuration(secs: number): string {
  if (!Number.isFinite(secs) || secs <= 0) return "0 s";
  const s = Math.floor(secs);
  if (s < 60) return `${s} s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min ${s % 60} s`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} h ${m % 60} min`;
  const d = Math.floor(h / 24);
  return `${d} d ${h % 24} h`;
}

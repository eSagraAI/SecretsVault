// Audit: read-only over `audit_show` / `audit_verify`. The timeline loads
// ON DEMAND ONLY — route enter plus explicit Reload — because every read
// appends one entry of its own, so polling would both grow the log and shift
// the page under the reader. Filtering is local over the loaded pages; the
// broker offers no server-side filter. Row shape is display-only: only the
// entry metadata the dashboard already holds (seq, time, actor, op, key
// NAMES, project, decision, reason code, run id, MAC presence) — never hash,
// prev_hash, mac bytes, cwd, executable, arg_count, result, exit_code or
// signal, and there is no approval_id to show.

import {
  badge,
  banner,
  button,
  card,
  chipList,
  el,
  emptyState,
  errorState,
  fieldGrid,
  iconTextButton,
  loadingState,
  pageHeader,
  para,
  table,
  toolbar,
} from "../components.js";
import {
  AUDIT_PAGE_SIZE,
  auditHasOlder,
  auditLimitWarning,
  decisionTone,
  errorAdvice,
  filterAuditEntries,
  fmtAuditTs,
  sessionHeld,
  type AuditEntry,
  type AuditFilters,
  type AuditVerifyResult,
  type MappedError,
  type ShellState,
  type Tone,
} from "../state.js";

export interface AuditActions {
  busyAction: string | null;
  onReload: () => void;
  onLoadOlder: () => void;
  onVerify: () => void;
  onFilter: (f: Partial<AuditFilters>) => void;
  inlineError: MappedError | null;
}

/** "0 entries" / "1 entry" / "50 entries" — the count half of the paging line. */
export function auditRowCountLabel(n: number): string {
  return `${n} ${n === 1 ? "entry" : "entries"}`;
}

/** True when any filter field narrows the loaded pages. "" means unfiltered. */
export function auditFilterIsActive(f: AuditFilters): boolean {
  return f.actor !== "" || f.op !== "" || f.project !== "" || f.decision !== "";
}

/**
 * Auth column content. MAC presence is a fact about the entry, not a verdict:
 * the unauthenticated branch is labelled in TEXT ("unauthenticated"), never
 * colour alone — a colour-only distinction is invisible to some readers.
 */
export function auditAuthBadge(authenticated: boolean): { label: string; tone: Tone } {
  return authenticated ? { label: "authenticated", tone: "mute" } : { label: "unauthenticated", tone: "warn" };
}

/** Bottom paging line: how many are loaded, which seq range, and whether the log continues below. */
export function auditSummary(entries: readonly AuditEntry[], hasOlder: boolean): string {
  if (entries.length === 0) return "No entries loaded.";
  const first = entries[0].seq;
  const last = entries[entries.length - 1].seq;
  const range = first === last ? `seq ${first}` : `seq ${first}–${last}`;
  const tail = hasOlder ? "Older entries remain." : "Beginning of the log reached.";
  return `${auditRowCountLabel(entries.length)} loaded (${range}). ${tail}`;
}

/**
 * The verify card copy. Bounded on purpose: it states exactly what the walk
 * proves (internal consistency + MAC chain under the current key) and what it
 * cannot prove (a key holder rewriting + re-MACing, an unauthenticated tail).
 * Never "secure", never a bare "OK".
 */
export function auditVerifyWording(r: AuditVerifyResult | null): string {
  if (r === null) return "Verification has not been run — press Verify audit to walk the on-disk log.";
  const nouns = `${r.entries} ${r.entries === 1 ? "entry" : "entries"}`;
  return (
    `Walked ${nouns}: ${r.macs_verified} MACs verified under the current audit key, ` +
    `${r.macs_null} without a MAC (unauthenticated). ` +
    "This proves the on-disk log is internally consistent and its MAC chain verifies under the " +
    "current audit key. It does not prove the log was never rewritten: a holder of the audit key " +
    "could rewrite entries and re-apply MACs, and a tail of entries written without a MAC is " +
    "undetectable without the key."
  );
}

export function renderAudit(root: HTMLElement, s: ShellState, a: AuditActions): void {
  root.replaceChildren();
  const busy = a.busyAction !== null;
  const showing = a.busyAction === "audit_show";
  const verifying = a.busyAction === "audit_verify";
  root.append(
    pageHeader("Audit", {
      subtitle: `Tamper-evident log of broker decisions — newest first, loaded in pages of ${AUDIT_PAGE_SIZE}.`,
      actions: [
        iconTextButton("refresh", showing ? "Loading…" : "Refresh", {
          disabled: busy,
          onClick: () => a.onReload(),
        }),
        button(verifying ? "Verifying…" : "Verify audit", {
          disabled: busy,
          onClick: () => a.onVerify(),
        }),
      ],
    }),
  );

  // The read side-effect is the reason this screen never polls: say so once,
  // next to the buttons, so nobody files "audit should auto-refresh".
  root.append(
    banner(
      "info",
      "Reading the audit log appends one entry per read. This screen never polls it — it loads when you enter this screen and when you press Refresh, nothing else.",
    ),
  );
  if (s.sessionExpired) {
    root.append(banner("warn", "Your session expired — unlock again before reading the audit log."));
  }
  // Same rule as Settings: while the posture is offline, the shell's single
  // offline explanation is the whole story. A loaded `inlineError` here would
  // duplicate it as a full error-state card for the same transport failure.
  if (a.inlineError !== null && s.conn !== "offline") {
    root.append(
      errorState(a.inlineError.message, errorAdvice(a.inlineError.code) ?? "", { code: a.inlineError.code }),
    );
  }
  if (s.health !== null) {
    const w = auditLimitWarning(s.health.audit_bytes, s.health.audit_soft_limit, s.health.audit_hard_limit);
    if (w !== null) root.append(banner("warn", `${w.title} — ${w.detail}`));
  }

  // Audit reads authenticate with the human session: locked, or open without
  // one, means no timeline at all — and no table pretending otherwise.
  if (s.status?.locked || !sessionHeld(s)) {
    root.append(
      emptyState(
        "Audit unavailable",
        s.status?.locked
          ? "Audit reads need the human session and are unavailable while the vault is locked — unlock first."
          : "The vault is open but this app holds no human session, so audit reads cannot be authenticated — lock, then unlock again to establish one.",
        { icon: "audit" },
      ),
    );
    return;
  }

  root.append(verifyCard(s.auditVerify));

  const page = s.audit;
  if (page === null && showing) {
    root.append(loadingState("Loading audit entries…"));
    return;
  }
  if (page === null) {
    root.append(
      emptyState("Audit not loaded", "Entries are not loaded yet — press Refresh.", {
        icon: "audit",
        actions: [button("Refresh", { disabled: busy, onClick: () => a.onReload() })],
      }),
    );
    return;
  }
  if (page.entries.length === 0) {
    // Genuinely empty log page (e.g. before_seq = 0) — the broker said so.
    root.append(
      emptyState("No audit entries", "The log reports no entries — nothing has been recorded in this range.", {
        icon: "audit",
      }),
    );
    return;
  }
  root.append(filterBar(s.auditFilters, a, busy));
  const visible = filterAuditEntries(page.entries, s.auditFilters);
  if (visible.length === 0) {
    // Loaded entries exist; the filters hide all of them. A different fact
    // from an empty log — keep the two states unmistakable.
    root.append(
      emptyState(
        "No entries match these filters",
        `The loaded page holds ${auditRowCountLabel(page.entries.length)} and none match — the log itself is not empty.`,
        {
          icon: "audit",
          actions: [
            button("Clear filters", {
              disabled: busy,
              onClick: () => a.onFilter({ actor: "", op: "", project: "", decision: "" }),
            }),
          ],
        },
      ),
    );
    return;
  }
  root.append(auditTable(visible));
  root.append(pagingBar(page.entries, auditHasOlder(s), a, busy, showing));
}

function verifyCard(r: AuditVerifyResult | null): HTMLElement {
  const c = card("Audit verification", {
    subtitle: "A verification walk over the on-disk log — run on demand, never automatic.",
  });
  if (r === null) {
    c.body.append(para(auditVerifyWording(null), "muted"));
    return c.root;
  }
  c.body.append(
    fieldGrid([
      ["Entries walked", String(r.entries)],
      ["MACs verified", String(r.macs_verified)],
      // mac: null entries carry no MAC to check — unauthenticated by construction.
      ["Entries without a MAC", String(r.macs_null)],
    ]),
  );
  c.body.append(para(auditVerifyWording(r)));
  return c.root;
}

/** Local-only filters: every change re-renders from the loaded pages, never a request. */
function filterBar(f: AuditFilters, a: AuditActions, busy: boolean): HTMLElement {
  const actor = el("input", {
    type: "text",
    class: "input",
    placeholder: "Actor",
    "aria-label": "Filter by actor",
    value: f.actor,
  }) as HTMLInputElement;
  const op = el("input", {
    type: "text",
    class: "input",
    placeholder: "Operation",
    "aria-label": "Filter by operation",
    value: f.op,
  }) as HTMLInputElement;
  const project = el("input", {
    type: "text",
    class: "input",
    placeholder: "Project",
    "aria-label": "Filter by project",
    value: f.project,
  }) as HTMLInputElement;
  const decision = el("select", { class: "select", "aria-label": "Filter by decision" }) as HTMLSelectElement;
  const opts: Array<[string, string]> = [
    ["", "Decision: any"],
    ["allowed", "allowed"],
    ["denied", "denied"],
  ];
  for (const [value, label] of opts) {
    const o = el("option", { value }, label) as HTMLOptionElement;
    if (value === f.decision) o.selected = true;
    decision.append(o);
  }
  if (busy) {
    actor.disabled = true;
    op.disabled = true;
    project.disabled = true;
    decision.disabled = true;
  }
  actor.addEventListener("input", () => a.onFilter({ actor: actor.value }));
  op.addEventListener("input", () => a.onFilter({ op: op.value }));
  project.addEventListener("input", () => a.onFilter({ project: project.value }));
  decision.addEventListener("change", () => a.onFilter({ decision: decision.value }));
  return toolbar([actor, op, project, decision]);
}

function auditTable(list: AuditEntry[]): HTMLElement {
  const rows: HTMLElement[][] = list.map((e) => {
    const seq = el("span", { class: "mono" }, String(e.seq));
    // Local-time reading; the exact wire instant stays one hover away.
    const time = el("span", { title: e.ts }, fmtAuditTs(e.ts));
    const actor = el("span", {}, e.actor);
    const operation = el("span", { class: "mono" }, e.op);
    // Secret NAMES only — the wire cannot carry values and neither do we.
    const keys = chipList(
      e.keys.map((k) => ({ text: k })),
      { empty: "—" },
    );
    const project = e.project === undefined || e.project === "" ? el("span", { class: "muted" }, "—") : el("span", {}, e.project);
    const decision = badge(e.decision || "unknown", decisionTone(e.decision));
    const reason =
      e.reason === undefined || e.reason === "" ? el("span", { class: "muted" }, "—") : el("span", { class: "mono" }, e.reason);
    const run = e.run_id === undefined || e.run_id === "" ? el("span", { class: "muted" }, "—") : el("span", { class: "mono" }, e.run_id);
    const auth = auditAuthBadge(e.authenticated);
    return [seq, time, actor, operation, keys, project, decision, reason, run, badge(auth.label, auth.tone)];
  });
  return table(
    ["Seq", "Time", "Actor", "Operation", "Keys", "Project", "Decision", "Reason", "Run", "Auth"].map((label, i) =>
      i === 0 ? { label, numeric: true } : label,
    ),
    rows,
    { dense: true, label: "Audit entries" },
  );
}

function pagingBar(
  loaded: AuditEntry[],
  hasOlder: boolean,
  a: AuditActions,
  busy: boolean,
  showing: boolean,
): HTMLElement {
  const older = button(showing ? "Loading…" : hasOlder ? "Load older" : "No older entries", {
    disabled: !hasOlder || busy,
    onClick: () => a.onLoadOlder(),
  });
  return toolbar([older, para(auditSummary(loaded, hasOlder), "muted")]);
}

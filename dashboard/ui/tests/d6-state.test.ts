// D6 state: the audit timeline slice, its local filters, the verification
// result, settings metadata, and the limit/session warnings. Every rule here
// is a spec requirement rather than a style choice: pages append without
// duplicating, a lock clears everything, a local filter never needs a request,
// a warning stays a warning, and no unknown value can manufacture an alarm.
// Pure functions only — no DOM, no framework.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import {
  AUDIT_PAGE_SIZE,
  applyAuditFilters,
  applyAuditFirstPage,
  applyAuditOlderPage,
  applyAuditVerify,
  applyLock,
  applySettingsProbe,
  auditHasOlder,
  auditLimitWarning,
  clearAudit,
  decisionTone,
  filterAuditEntries,
  fmtAuditTs,
  fmtDuration,
  healthWarnings,
  initialState,
  sessionExpiryWarning,
  vaultLimitWarning,
  type AuditEntry,
  type AuditFilters,
  type ShellState,
} from "../state.js";

function entry(seq: number, partial: Partial<AuditEntry> = {}): AuditEntry {
  return {
    seq,
    ts: "2026-09-17T20:00:00Z",
    actor: "human",
    op: "secret.set",
    project: "acme",
    keys: ["STRIPE_KEY"],
    decision: "allowed",
    authenticated: true,
    ...partial,
  };
}

function filters(partial: Partial<AuditFilters> = {}): AuditFilters {
  return { actor: "", op: "", project: "", decision: "", ...partial };
}

function withHealth(s: ShellState, partial: Partial<NonNullable<ShellState["health"]>>): ShellState {
  return {
    ...s,
    health: {
      locked: false,
      idle_lock_secs: 900,
      idle_in: 100,
      audit_bytes: 0,
      audit_soft_limit: 1_000_000,
      audit_hard_limit: 2_000_000,
      vault_bytes: 0,
      vault_max_bytes: 1_000_000,
      runs_active: 0,
      leases_active: 0,
      approvals_pending: 0,
      ...partial,
    },
  };
}

describe("audit page, cursor and ordering", () => {
  it("the first page replaces the slice and stores the real cursor", () => {
    const s = applyAuditFirstPage(initialState(), {
      entries: [entry(3), entry(4)],
      next_before_seq: 2,
    });
    assert.deepEqual(
      s.audit?.entries.map((e) => e.seq),
      [3, 4],
    );
    assert.equal(s.audit?.nextBeforeSeq, 2);
  });

  it("a reload replaces rather than appends", () => {
    let s = applyAuditFirstPage(initialState(), { entries: [entry(1)], next_before_seq: null });
    s = applyAuditFirstPage(s, { entries: [entry(9)], next_before_seq: null });
    assert.deepEqual(
      s.audit?.entries.map((e) => e.seq),
      [9],
    );
  });

  it("an older page appends and keeps the slice ascending", () => {
    let s = applyAuditFirstPage(initialState(), {
      entries: [entry(5), entry(6)],
      next_before_seq: 4,
    });
    s = applyAuditOlderPage(s, { entries: [entry(3), entry(4)], next_before_seq: 2 });
    assert.deepEqual(
      s.audit?.entries.map((e) => e.seq),
      [3, 4, 5, 6],
    );
    assert.equal(s.audit?.nextBeforeSeq, 2);
  });

  it("re-appending an overlapping page never duplicates a seq", () => {
    let s = applyAuditFirstPage(initialState(), { entries: [entry(5), entry(6)], next_before_seq: 4 });
    s = applyAuditOlderPage(s, { entries: [entry(3), entry(4)], next_before_seq: 2 });
    s = applyAuditOlderPage(s, { entries: [entry(3), entry(4)], next_before_seq: 2 });
    assert.deepEqual(
      s.audit?.entries.map((e) => e.seq),
      [3, 4, 5, 6],
    );
  });

  it("an unorderable row is dropped rather than rendered", () => {
    const broken = { ...entry(7), seq: Number.NaN };
    const s = applyAuditFirstPage(initialState(), { entries: [broken, entry(8)], next_before_seq: null });
    assert.deepEqual(
      s.audit?.entries.map((e) => e.seq),
      [8],
    );
  });

  it("auditHasOlder tracks the real cursor, and is false without a slice", () => {
    assert.equal(auditHasOlder(initialState()), false);
    const withMore = applyAuditFirstPage(initialState(), { entries: [entry(2)], next_before_seq: 1 });
    assert.equal(auditHasOlder(withMore), true);
    const exhausted = applyAuditFirstPage(initialState(), { entries: [entry(1)], next_before_seq: null });
    assert.equal(auditHasOlder(exhausted), false);
  });

  it("the page size is pinned", () => {
    assert.equal(AUDIT_PAGE_SIZE, 50);
  });
});

describe("leaving the route and locking release the audit state", () => {
  it("clearAudit drops pages, verification and filters", () => {
    let s = applyAuditFirstPage(initialState(), { entries: [entry(1)], next_before_seq: 1 });
    s = applyAuditVerify(s, { entries: 1, macs_verified: 1, macs_null: 0 });
    s = applyAuditFilters(s, { actor: "human" });
    s = clearAudit(s);
    assert.equal(s.audit, null);
    assert.equal(s.auditVerify, null);
    assert.deepEqual(s.auditFilters, filters());
  });

  it("a lock resets every D6 slice", () => {
    let s = applyAuditFirstPage(initialState(), { entries: [entry(1)], next_before_seq: 1 });
    s = applyAuditVerify(s, { entries: 1, macs_verified: 1, macs_null: 0 });
    s = applySettingsProbe(s, "a".repeat(64), 5);
    const locked = applyLock();
    assert.equal(locked.audit, null);
    assert.equal(locked.auditVerify, null);
    assert.deepEqual(locked.auditFilters, filters());
    assert.deepEqual(locked.settings, { probedFingerprint: null, probedAtMs: 0 });
  });
});

describe("audit filters are local and honest about an empty filter", () => {
  const rows = [
    entry(1, { actor: "human", op: "secret.set", project: "acme", decision: "allowed" }),
    entry(2, { actor: "agent:bot01", op: "reveal", project: "acme", decision: "denied" }),
    entry(3, { actor: "human", op: "vault.lock", project: "ops", decision: "allowed" }),
  ];

  it("an empty filter returns the input order untouched", () => {
    assert.deepEqual(
      filterAuditEntries(rows, filters()).map((e) => e.seq),
      [1, 2, 3],
    );
  });

  it("filters by actor, op, project and decision", () => {
    assert.deepEqual(filterAuditEntries(rows, filters({ actor: "bot" })).map((e) => e.seq), [2]);
    assert.deepEqual(filterAuditEntries(rows, filters({ op: "reveal" })).map((e) => e.seq), [2]);
    assert.deepEqual(filterAuditEntries(rows, filters({ project: "ops" })).map((e) => e.seq), [3]);
    assert.deepEqual(filterAuditEntries(rows, filters({ decision: "denied" })).map((e) => e.seq), [2]);
  });

  it("matching is case-insensitive and trims the needle", () => {
    assert.deepEqual(filterAuditEntries(rows, filters({ actor: "  HUMAN  " })).map((e) => e.seq), [1, 3]);
    assert.deepEqual(filterAuditEntries(rows, filters({ decision: "ALLOWED" })).map((e) => e.seq), [1, 3]);
  });

  it("an entry with no project is not matched by a project filter", () => {
    const noProject = [entry(1, { project: undefined })];
    assert.deepEqual(filterAuditEntries(noProject, filters({ project: "acme" })).map((e) => e.seq), []);
  });

  it("applyAuditFilters merges a partial without dropping the other fields", () => {
    const s = applyAuditFilters(initialState(), { actor: "human" });
    const t = applyAuditFilters(s, { op: "reveal" });
    assert.deepEqual(t.auditFilters, filters({ actor: "human", op: "reveal" }));
  });
});

describe("verification result and decision tone", () => {
  it("stores the three real counters and clears the error", () => {
    const s = { ...initialState(), error: { code: "E_X", message: "x" } };
    const out = applyAuditVerify(s, { entries: 12, macs_verified: 10, macs_null: 2 });
    assert.deepEqual(out.auditVerify, { entries: 12, macs_verified: 10, macs_null: 2 });
    assert.equal(out.error, null);
  });

  it("decision tone separates allowed, denied and unknown", () => {
    assert.equal(decisionTone("allowed"), "ok");
    assert.equal(decisionTone("DENIED"), "bad");
    assert.equal(decisionTone(""), "mute");
    assert.equal(decisionTone("something-else"), "mute");
  });
});

describe("audit timestamps and durations stay honest", () => {
  it("formats an RFC3339 instant as local parts and never invents one", () => {
    assert.match(fmtAuditTs("2026-09-17T20:31:05Z"), /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
    assert.equal(fmtAuditTs(""), "unknown");
    assert.equal(fmtAuditTs("not-a-date"), "unknown");
  });

  it("durations use the largest two units", () => {
    assert.equal(fmtDuration(0), "0 s");
    assert.equal(fmtDuration(-5), "0 s");
    assert.equal(fmtDuration(59), "59 s");
    assert.equal(fmtDuration(60), "1 min 0 s");
    assert.equal(fmtDuration(3599), "59 min 59 s");
    assert.equal(fmtDuration(3600), "1 h 0 min");
    assert.equal(fmtDuration(86399), "23 h 59 min");
    assert.equal(fmtDuration(86400), "1 d 0 h");
  });
});

describe("limit warnings are real, bounded and never errors", () => {
  it("a missing input can never manufacture an alarm", () => {
    assert.equal(auditLimitWarning(null, 100, 200), null);
    assert.equal(auditLimitWarning(90, null, 200), null);
    assert.equal(auditLimitWarning(90, 0, 200), null);
    assert.equal(vaultLimitWarning(null, 100), null);
    assert.equal(vaultLimitWarning(90, 0), null);
  });

  it("well below the threshold there is no warning", () => {
    assert.equal(auditLimitWarning(10, 100, 200), null);
    assert.equal(vaultLimitWarning(10, 100), null);
  });

  it("at and past the soft limit it warns, with tone warn and the pinned id", () => {
    const at = auditLimitWarning(80, 100, 200);
    assert.equal(at?.id, "audit-near-limit");
    assert.equal(at?.tone, "warn");
    const past = auditLimitWarning(120, 100, 200);
    assert.equal(past?.tone, "warn");
    assert.notEqual(past?.title, at?.title);
  });

  it("the vault maximum uses its own pinned id and tone", () => {
    const w = vaultLimitWarning(90, 100);
    assert.equal(w?.id, "vault-near-max");
    assert.equal(w?.tone, "warn");
  });
});

describe("session expiry warning only fires on a live, soon-to-lapse session", () => {
  const live = (expiresIn: number): ShellState => ({
    ...initialState(),
    session: { present: true, expiresIn },
    unlockedAtMs: 1_000_000,
  });

  it("no session means no expiry warning", () => {
    assert.equal(sessionExpiryWarning(initialState(), 1_000_000), null);
  });

  it("plenty of life left is not a warning", () => {
    assert.equal(sessionExpiryWarning(live(300), 1_000_000), null);
  });

  it("under a minute of life warns", () => {
    const w = sessionExpiryWarning(live(300), 1_000_000 + 250_000);
    assert.equal(w?.id, "session-about-to-expire");
    assert.equal(w?.tone, "warn");
  });

  it("an already-lapsed session warns without going negative", () => {
    const w = sessionExpiryWarning(live(60), 1_000_000 + 600_000);
    assert.equal(w?.tone, "warn");
    assert.doesNotMatch(w?.detail ?? "", /-\d/);
  });
});

describe("healthWarnings compose only from real values", () => {
  it("a healthy broker with no session produces nothing", () => {
    assert.deepEqual(healthWarnings(initialState(), 0), []);
  });

  it("a null counter can never produce a warning", () => {
    const s = withHealth(initialState(), { audit_bytes: 999_999_999, audit_soft_limit: 0 });
    assert.deepEqual(healthWarnings(s, 0), []);
  });

  it("audit then vault warnings compose in reading order", () => {
    const s = withHealth(initialState(), {
      audit_bytes: 90,
      audit_soft_limit: 100,
      audit_hard_limit: 200,
      vault_bytes: 90,
      vault_max_bytes: 100,
    });
    assert.deepEqual(
      healthWarnings(s, 0).map((w) => w.id),
      ["audit-near-limit", "vault-near-max"],
    );
  });
});

describe("the settings probe is display-only", () => {
  it("records a fingerprint and its time", () => {
    const s = applySettingsProbe(initialState(), "b".repeat(64), 1234);
    assert.equal(s.settings.probedFingerprint, "b".repeat(64));
    assert.equal(s.settings.probedAtMs, 1234);
  });

  it("clears it, and never touches the pin", () => {
    const pinned = { ...initialState(), pin: { pinned: true, fingerprint: "c".repeat(64) } };
    const probed = applySettingsProbe(pinned, "d".repeat(64), 1);
    const cleared = applySettingsProbe(probed, null, 2);
    assert.equal(cleared.settings.probedFingerprint, null);
    assert.deepEqual(cleared.pin, pinned.pin);
  });
});

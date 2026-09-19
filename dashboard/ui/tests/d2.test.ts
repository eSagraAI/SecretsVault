// D2 slices: overview counters (null-safe), projects re-read discipline,
// secrets metadata-only shape, session-expiry gate, and the secret-submit
// lifecycle twin. Pure functions only — no DOM, no framework.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import {
  applyError,
  applyMutationDone,
  applyMutationStart,
  applyOverview,
  applyProjects,
  applySecrets,
  applySelectedProject,
  assertMetadataOnly,
  canOfferUnlock,
  fmtCount,
  fmtSecretsTotal,
  initialState,
  isPostureOnly,
  mustOfferUnlockForExpiry,
  needsUnlockGate,
  overviewHint,
  sessionHeld,
  type OverviewData,
} from "../state.js";
import { takeSecretSubmit } from "../screens/secrets.js";

function overview(partial: Partial<OverviewData> = {}): OverviewData {
  return {
    online: true,
    trusted: true,
    fingerprint: undefined,
    version: 1,
    created: "2026-09-16",
    locked: false,
    session_held: true,
    projects: 2,
    secrets_total: 7,
    secrets_total_exact: true,
    agents_active: 1,
    runs_active: 0,
    approvals_pending: 0,
    leases_active: 0,
    idle_lock_secs: 300,
    idle_in: 120,
    audit_bytes: 512,
    audit_soft_limit: 1024,
    audit_hard_limit: 2048,
    vault_bytes: 300,
    vault_max_bytes: 4096,
    ...partial,
  };
}

describe("overview counters never fabricate", () => {
  it("locked ⇒ every counter null and the UI text shows — (pure mapping)", () => {
    const s0 = applyOverview(initialState(), overview({ locked: true }));
    const o = s0.overview;
    assert.ok(o);
    const locked = overview({
      locked: true,
      projects: null,
      secrets_total: null,
      agents_active: null,
      runs_active: null,
      approvals_pending: null,
      leases_active: null,
      idle_lock_secs: null,
      idle_in: null,
      audit_bytes: null,
      audit_soft_limit: null,
      audit_hard_limit: null,
      vault_bytes: null,
      vault_max_bytes: null,
    });
    const s = applyOverview(initialState(), locked);
    assert.equal(fmtCount(s.overview?.projects ?? null), "—");
    assert.equal(fmtCount(s.overview?.agents_active ?? null), "—");
    assert.equal(fmtSecretsTotal(s.overview?.secrets_total ?? null, true), "—");
    assert.notEqual(fmtCount(s.overview?.projects ?? null), "0");
    void o;
  });
  it("unlocked ⇒ numbers render as-is", () => {
    const s = applyOverview(initialState(), overview({ projects: 3, agents_active: 2 }));
    assert.equal(fmtCount(s.overview?.projects ?? null), "3");
    assert.equal(fmtCount(s.overview?.agents_active ?? null), "2");
    assert.equal(fmtSecretsTotal(7, true), "7");
  });
  it("secrets_total_exact false ⇒ the ≥ N form", () => {
    assert.equal(fmtSecretsTotal(7, false), "≥ 7");
    assert.equal(fmtSecretsTotal(7, true), "7");
    assert.equal(fmtSecretsTotal(null, false), "—");
  });
});

describe("projects slice", () => {
  it("applyProjects stores the list and defaults activeProject to the first", () => {
    const s = applyProjects(initialState(), [
      { name: "a", paths: ["/x"] },
      { name: "b", paths: [] },
    ]);
    assert.equal(s.projects?.length, 2);
    assert.equal(s.activeProject, "a");
    assert.equal(s.selectedProject, null);
  });
  it("selection survives a refresh only when still present", () => {
    let s = applyProjects(initialState(), [{ name: "a", paths: [] }]);
    s = applySelectedProject(s, "a");
    s = applyProjects(s, [{ name: "b", paths: [] }]);
    assert.equal(s.selectedProject, null);
    assert.equal(s.activeProject, "b");
    assert.equal(s.secrets, null);
  });
  it("a mutation marks busy and clears form UI instead of optimistically inserting", () => {
    let s = applyProjects(initialState(), [{ name: "a", paths: [] }]);
    s = applyMutationStart(s, "project_add");
    assert.equal(s.forms.busyAction, "project_add");
    assert.equal(s.projects?.length, 1);
    assert.ok(!s.projects?.some((p) => p.name === "optimistic"));
    s = applyMutationDone(s);
    assert.equal(s.forms.busyAction, null);
  });
});

describe("secrets metadata slice", () => {
  it("keys render and rows carry only key+updated at runtime", () => {
    const s = applySecrets(initialState(), "a", [{ key: "k1", updated: "t1" }]);
    assert.equal(s.secrets?.length, 1);
    assert.deepEqual(Object.keys(s.secrets?.[0] ?? {}).sort(), ["key", "updated"]);
  });
  it("a value-smuggling row fails loudly", () => {
    assert.throws(() => assertMetadataOnly({ key: "k", updated: "t", value: "SECRET" }), /must not carry a value/);
    assert.throws(
      () => applySecrets(initialState(), "a", [{ key: "k", updated: "t", value: "x" } as never]),
      /must not carry a value/,
    );
  });
});

describe("session expiry", () => {
  it("E_SESSION_EXPIRED clears the session and forces the unlock gate, no retry", () => {
    const base = { ...initialState(), conn: "trusted" as const };
    const s = applyError(base, { code: "E_SESSION_EXPIRED", message: "session expired" });
    assert.equal(s.session.present, false);
    assert.equal(s.sessionExpired, true);
    assert.equal(mustOfferUnlockForExpiry(s), true);
    assert.equal(needsUnlockGate(s), true);
  });
  it("expiry wins even when the vault still reads unlocked", () => {
    const base = {
      ...initialState(),
      conn: "trusted" as const,
      status: { version: 1, created: "c", locked: false, online: true, trusted: true, initialized: true },
    };
    assert.equal(canOfferUnlock(base), false);
    const s = applyError(base, { code: "E_SESSION_EXPIRED", message: "gone" });
    assert.equal(mustOfferUnlockForExpiry(s), true);
    assert.equal(needsUnlockGate(s), true);
  });
});
describe("overview hint honesty", () => {
  const unlocked = { version: 1, created: "c", locked: false, online: true, trusted: true, initialized: true };
  it("locked ⇒ unlock-first hint", () => {
    const s = { ...initialState(), status: { version: 1, created: "c", locked: true, online: true, trusted: true, initialized: true } };
    assert.match(overviewHint(s), /unlock/);
  });
  it("unlocked with session_held false ⇒ no-session hint, never Refresh", () => {
    const s = { ...applyOverview(initialState(), overview({ session_held: false })), status: unlocked };
    assert.match(overviewHint(s), /no human session/);
    assert.ok(!overviewHint(s).includes("Refresh"));
  });
  it("unlocked with a payload but no counters held ⇒ refresh hint", () => {
    const s = { ...applyOverview(initialState(), overview()), status: unlocked };
    assert.match(overviewHint(s), /press Refresh/);
  });
  it("session_held true with all counters null ⇒ refresh hint, NOT no-session (stale-flag regression)", () => {
    // This is the silent-TTL-lapse shape: the local session slice may still
    // claim present (or not), but the backend says it holds a session while
    // every counter degraded to null. The hint must blame loading, and the
    // banner gate must stay shut — never claim "no session".
    const empty = overview({
      session_held: true,
      projects: null,
      secrets_total: null,
      agents_active: null,
      runs_active: null,
      approvals_pending: null,
      leases_active: null,
      idle_lock_secs: null,
      audit_bytes: null,
      vault_bytes: null,
    });
    assert.equal(isPostureOnly(empty), true);
    assert.equal(isPostureOnly(overview()), false);
    const staleLocal = {
      ...applyOverview(initialState(), empty),
      status: unlocked,
      session: { present: false },
    };
    assert.match(overviewHint(staleLocal), /press Refresh/);
    assert.ok(!overviewHint(staleLocal).includes("no human session"));
    const freshLocal = {
      ...applyOverview(initialState(), empty),
      status: unlocked,
      session: { present: true, prefix: "ab12cd34" },
    };
    assert.match(overviewHint(freshLocal), /press Refresh/);
    assert.ok(!overviewHint(freshLocal).includes("no human session"));
  });
  it("stale-flag regression both directions: backend field always wins over the local slice", () => {
    // TTL-lapse shape: local slice still claims a session, backend says none.
    const lapsed = {
      ...applyOverview(initialState(), overview({ session_held: false })),
      status: unlocked,
      session: { present: true, prefix: "ab12cd34" },
    };
    assert.match(overviewHint(lapsed), /no human session/);
    assert.equal(sessionHeld(lapsed), false);
    // Best-effort-seed shape: local slice never saw a session, backend holds one.
    const seeded = {
      ...applyOverview(initialState(), overview()),
      status: unlocked,
      session: { present: false },
    };
    assert.match(overviewHint(seeded), /press Refresh/);
    assert.equal(sessionHeld(seeded), true);
  });
  it("malformed payload without the field ⇒ falls back to the local session slice", () => {
    const bare = { ...applyOverview(initialState(), overview()), status: unlocked };
    const noPayload = { ...bare, overview: null };
    assert.match(overviewHint({ ...noPayload, session: { present: false } }), /no human session/);
    // Present payload but the field itself missing (older/partial backend):
    // must not crash or mislabel — falls back to the local slice.
    const full = overview();
    const { session_held: _drop, ...rest } = full;
    void _drop;
    const fieldless = { ...bare, overview: { ...rest, session_held: undefined } as unknown as OverviewData };
    assert.equal(sessionHeld({ ...fieldless, session: { present: false } }), false);
    assert.equal(sessionHeld({ ...fieldless, session: { present: true } }), true);
  });
});

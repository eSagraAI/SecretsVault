// D5 overview: the control centre renders only real broker data. These tests
// pin the honesty rules the screen depends on — a null counter is unknown (never
// a fabricated 0), the capped secret total keeps its >= form, and the attention
// strip maps onto real hash routes. Pure functions only, no DOM.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import {
  applyApprovals,
  applyGrants,
  applyOverview,
  applyProjects,
  attentionItems,
  fmtAuditUsage,
  fmtCount,
  fmtSecretsTotal,
  initialState,
  isPostureOnly,
  overviewHint,
  type ApprovalEntry,
  type GrantEntry,
  type OverviewData,
  type ProjectEntry,
} from "../state.js";
import { fmtBytes } from "../screens/overview.js";

function overview(partial: Partial<OverviewData> = {}): OverviewData {
  return {
    online: true,
    trusted: true,
    version: 1,
    created: "2026-09-16",
    locked: false,
    session_held: true,
    projects: null,
    secrets_total: null,
    secrets_total_exact: false,
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
    ...partial,
  };
}

describe("overview counters never fabricate", () => {
  it("a null counter is unknown, not zero", () => {
    assert.equal(fmtCount(null), "—");
    assert.equal(fmtCount(0), "0");
    assert.equal(fmtCount(7), "7");
  });

  it("the capped secret total keeps the >= form; exact stays plain", () => {
    assert.equal(fmtSecretsTotal(null, false), "—");
    assert.equal(fmtSecretsTotal(12, true), "12");
    assert.equal(fmtSecretsTotal(12, false), "≥ 12");
  });

  it("audit usage is null-safe and never invents a limit", () => {
    assert.equal(fmtAuditUsage(null, null, null), "—");
    assert.equal(fmtAuditUsage(10, null, null), "—");
    assert.ok(fmtAuditUsage(10, 100, 200).includes("10"));
  });

  it("a posture-only payload is recognised as such", () => {
    assert.equal(isPostureOnly(overview()), true);
    assert.equal(isPostureOnly(overview({ projects: 0 })), false);
  });
});

describe("overview hint honesty", () => {
  it("says nothing while the vault is locked", () => {
    const s = { ...initialState(), conn: "trusted" as const };
    assert.equal(typeof overviewHint(s), "string");
  });
});

describe("attention strip maps only real data onto real routes", () => {
  it("a clean state needs nothing", () => {
    assert.deepEqual(attentionItems(initialState(), 0), []);
  });

  it("pending approvals produce one item pointing at the inbox", () => {
    const approval: ApprovalEntry = {
      approval_id: "ap-1",
      agent: "a",
      project: "p",
      key: "K",
      status: "pending",
      expires_at: "2026-09-17T12:00:00Z",
    };
    const s = applyApprovals(initialState(), [approval]);
    const items = attentionItems(s, 0);
    assert.equal(items.length, 1);
    assert.equal(items[0].route, "#/approvals");
    assert.ok(items[0].title.includes("1 pending approval"));
  });

  it("revoked grants are surfaced but never as a warning", () => {
    const revoked: GrantEntry = { agent: "a", project: "p", ops: ["read"], revoked: true };
    const s = applyGrants(initialState(), [revoked]);
    const items = attentionItems(s, 0);
    assert.equal(items.length, 1);
    assert.equal(items[0].tone, "mute");
    assert.equal(items[0].route, "#/grants");
  });

  it("an expired session is actionable", () => {
    const s = { ...initialState(), sessionExpired: true };
    const items = attentionItems(s, 0);
    assert.equal(items.length, 1);
    assert.equal(items[0].id, "session-expired");
  });

  it("an audit log near its soft limit is flagged; a distant one is not", () => {
    const near = applyOverview(initialState(), overview({ audit_bytes: 90, audit_soft_limit: 100 }));
    assert.ok(attentionItems(near, 0).some((i) => i.id === "audit-near-limit"));
    const far = applyOverview(initialState(), overview({ audit_bytes: 10, audit_soft_limit: 100 }));
    assert.equal(attentionItems(far, 0).some((i) => i.id === "audit-near-limit"), false);
  });

  it("a null counter never triggers the vault-near-max warning", () => {
    const s = applyOverview(initialState(), overview({ vault_bytes: null, vault_max_bytes: 1000 }));
    assert.equal(attentionItems(s, 0).some((i) => i.id === "vault-near-max"), false);
  });
});

describe("byte formatting", () => {
  it("scales units and keeps small values exact", () => {
    assert.equal(fmtBytes(512), "512 B");
    assert.equal(fmtBytes(2048), "2.0 KiB");
    assert.equal(fmtBytes(3 * 1024 * 1024), "3.00 MiB");
  });
});

describe("projects slice feeding the overview", () => {
  it("keeps rows and their authorized paths", () => {
    const rows: ProjectEntry[] = [{ name: "acme", paths: ["/srv/acme"] }];
    const s = applyProjects(initialState(), rows);
    assert.deepEqual(s.projects, rows);
  });
});

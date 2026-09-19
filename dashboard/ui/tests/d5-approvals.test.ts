// D5 approvals: honest countdowns, decided-ness tones, and the null-count
// rule for the approvals slice. Pure functions only — no DOM, no framework.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import {
  applyApprovals,
  approvalCountdown,
  approvalCount,
  approvalStatusTone,
  initialState,
} from "../state.js";

const NOW = Date.parse("2026-09-17T12:00:00.000Z");

describe("approvalCountdown stays honest", () => {
  it("reports expired with remainingMs 0 for a past timestamp, never negative", () => {
    const out = approvalCountdown("2026-09-17T11:59:00.000Z", NOW);
    assert.equal(out.expired, true);
    assert.equal(out.label, "expired");
    assert.equal(out.remainingMs, 0);
    assert.ok(out.remainingMs >= 0);
  });
  it("reports expiry unknown for an unparseable timestamp", () => {
    const out = approvalCountdown("not-a-time", NOW);
    assert.equal(out.label, "expiry unknown");
    assert.equal(out.remainingMs, 0);
  });
  it("reports a positive remaining time for a future timestamp", () => {
    const out = approvalCountdown("2026-09-17T12:05:00.000Z", NOW);
    assert.equal(out.expired, false);
    assert.ok(out.remainingMs > 0);
    assert.match(out.label, /^expires in /);
  });
});

describe("approvalStatusTone maps decided-ness without an approving fallback", () => {
  it("maps pending/approved/denied to warn/ok/bad", () => {
    assert.equal(approvalStatusTone("pending"), "warn");
    assert.equal(approvalStatusTone("approved"), "ok");
    assert.equal(approvalStatusTone("denied"), "bad");
  });
  it("maps anything else to mute, never an approving tone", () => {
    assert.equal(approvalStatusTone("expired"), "mute");
    assert.equal(approvalStatusTone(""), "mute");
    assert.equal(approvalStatusTone("APPROVED-ish"), "mute");
  });
});

describe("approvalCount stays honest for the unloaded slice", () => {
  it("is null, never 0, when approvals are not loaded", () => {
    assert.equal(approvalCount(initialState()), null);
  });
  it("counts the loaded rows once the broker answers", () => {
    const s = applyApprovals(initialState(), [
      { approval_id: "a1", agent: "g", project: "p", key: "k", status: "pending", expires_at: "" },
      { approval_id: "a2", agent: "g", project: "p", key: "k", status: "pending", expires_at: "" },
    ]);
    assert.equal(approvalCount(s), 2);
  });
});

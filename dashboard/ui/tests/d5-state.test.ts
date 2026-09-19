// D5 additions: project tabs, agent selection, grant derivations, tones,
// relative time, secret-count honesty, and attention items.
// Pure functions only — no DOM, no framework.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import {
  activeGrantsFor,
  agentsWithAccess,
  agentStatusTone,
  applyAgents,
  applyApprovals,
  applyGrants,
  applyLock,
  applyProjectTab,
  applySecrets,
  applySelectedAgent,
  approvalStatusTone,
  attentionItems,
  capabilityMatrix,
  capabilityTone,
  fmtRelative,
  initialState,
  loadedSecretCount,
  projectsForAgent,
  runStatusTone,
} from "../state.js";

function grantsState() {
  return applyGrants(initialState(), [
    { agent: "bob", project: "web", ops: ["read", "run"], revoked: false },
    { agent: "alice", project: "web", ops: ["read"], revoked: false },
    { agent: "bob", project: "api", ops: ["reveal"], revoked: false },
    { agent: "mallory", project: "web", ops: ["manage"], revoked: true },
  ]);
}

describe("grant derivations exclude revoked rows and tolerate null grants", () => {
  it("activeGrantsFor returns only the live rows for one project", () => {
    const rows = activeGrantsFor(grantsState(), "web");
    assert.equal(rows.length, 2);
    assert.ok(rows.every((g) => g.revoked === false));
    assert.deepEqual(
      rows.map((g) => g.agent).sort(),
      ["alice", "bob"],
    );
  });

  it("agentsWithAccess sorts by agent and hides revoked agents", () => {
    const rows = agentsWithAccess(grantsState(), "web");
    assert.deepEqual(
      rows.map((r) => r.agent),
      ["alice", "bob"],
    );
    assert.deepEqual(rows[0], { agent: "alice", ops: ["read"] });
  });

  it("projectsForAgent sorts by project and hides revoked rows", () => {
    const rows = projectsForAgent(grantsState(), "bob");
    assert.deepEqual(
      rows.map((r) => r.project),
      ["api", "web"],
    );
  });

  it("capabilityMatrix unions live agents/projects, sorted", () => {
    assert.deepEqual(capabilityMatrix(grantsState()), {
      agents: ["alice", "bob"],
      projects: ["api", "web"],
    });
  });

  it("null grants mean empty answers, never a throw", () => {
    const clean = initialState();
    assert.deepEqual(activeGrantsFor(clean, "web"), []);
    assert.deepEqual(agentsWithAccess(clean, "web"), []);
    assert.deepEqual(projectsForAgent(clean, "bob"), []);
    assert.deepEqual(capabilityMatrix(clean), { agents: [], projects: [] });
  });
});

describe("tone mappings", () => {
  it("capabilityTone weights sensitive caps and mutes the unknown", () => {
    assert.equal(capabilityTone("reveal"), "warn");
    assert.equal(capabilityTone("manage"), "warn");
    assert.equal(capabilityTone("run"), "info");
    assert.equal(capabilityTone("inject"), "info");
    assert.equal(capabilityTone("read"), "mute");
    assert.equal(capabilityTone("teleport"), "mute");
  });

  it("agentStatusTone only approves active", () => {
    assert.equal(agentStatusTone("active"), "ok");
    assert.equal(agentStatusTone("revoked"), "bad");
    assert.equal(agentStatusTone("suspended"), "mute");
  });

  it("runStatusTone only approves live runs and condemns failures", () => {
    assert.equal(runStatusTone("running"), "ok");
    assert.equal(runStatusTone("active"), "ok");
    assert.equal(runStatusTone("failed"), "bad");
    assert.equal(runStatusTone("error"), "bad");
    assert.equal(runStatusTone("killed"), "bad");
    assert.equal(runStatusTone("done"), "mute");
  });

  it("approvalStatusTone tracks decided-ness", () => {
    assert.equal(approvalStatusTone("pending"), "warn");
    assert.equal(approvalStatusTone("approved"), "ok");
    assert.equal(approvalStatusTone("denied"), "bad");
    assert.equal(approvalStatusTone("expired"), "mute");
  });
});

describe("fmtRelative boundaries", () => {
  const nowMs = Date.parse("2026-09-17T12:00:00.000Z");
  const ago = (ms: number): string => new Date(nowMs - ms).toISOString();

  it("unparseable or empty input stays honest", () => {
    assert.equal(fmtRelative("", nowMs), "unknown");
    assert.equal(fmtRelative("not-a-time", nowMs), "unknown");
  });

  it("future timestamps read as just now, never negative", () => {
    assert.equal(fmtRelative(new Date(nowMs + 30_000).toISOString(), nowMs), "just now");
  });

  it("seconds, minutes, hours, days render in the short form", () => {
    assert.equal(fmtRelative(ago(30_000), nowMs), "just now");
    assert.equal(fmtRelative(ago(60_000), nowMs), "1m ago");
    assert.equal(fmtRelative(ago(4 * 60_000), nowMs), "4m ago");
    assert.equal(fmtRelative(ago(2 * 3_600_000), nowMs), "2h ago");
    assert.equal(fmtRelative(ago(3 * 86_400_000), nowMs), "3d ago");
  });
});

describe("view-state reconciliation", () => {
  it("applyAgents drops a selected agent that is no longer listed", () => {
    const picked = applySelectedAgent(initialState(), "alice");
    const dropped = applyAgents(picked, [{ name: "bob", status: "active", token_prefix: "ab12" }]);
    assert.equal(dropped.selectedAgent, null);
  });

  it("applyAgents keeps the selection while the agent is still listed", () => {
    const picked = applySelectedAgent(initialState(), "bob");
    const kept = applyAgents(picked, [
      { name: "bob", status: "active", token_prefix: "ab12" },
      { name: "alice", status: "active", token_prefix: "cd34" },
    ]);
    assert.equal(kept.selectedAgent, "bob");
  });

  it("applyProjectTab records the tab", () => {
    assert.equal(applyProjectTab(initialState(), "access").projectTab, "access");
  });

  it("applyLock resets the project tab and the agent selection", () => {
    assert.equal(initialState().projectTab, "overview");
    assert.equal(initialState().selectedAgent, null);
    const dirty = applySelectedAgent(applyProjectTab(initialState(), "paths"), "alice");
    const locked = applyLock();
    assert.equal(locked.projectTab, "overview");
    assert.equal(locked.selectedAgent, null);
    assert.equal(dirty.projectTab, "paths");
  });
});

describe("loadedSecretCount honesty", () => {
  it("null when nothing is loaded or the wrong project is asked", () => {
    assert.equal(loadedSecretCount(initialState(), "web"), null);
    const s = applySecrets(initialState(), "web", [{ key: "a", updated: "t" }]);
    assert.equal(loadedSecretCount(s, "api"), null);
  });

  it("counts the loaded project", () => {
    const s = applySecrets(initialState(), "web", [
      { key: "a", updated: "t1" },
      { key: "b", updated: "t2" },
    ]);
    assert.equal(loadedSecretCount(s, "web"), 2);
  });
});

describe("attentionItems honesty", () => {
  it("clean state means no items, not a fabricated summary", () => {
    assert.deepEqual(attentionItems(initialState(), 0), []);
  });

  it("flags pending approvals with a real route", () => {
    const s = applyApprovals(initialState(), [
      { approval_id: "a1", agent: "bob", project: "web", key: "k", status: "pending", expires_at: "" },
    ]);
    const items = attentionItems(s, 0);
    const pending = items.find((i) => i.id === "approvals-pending");
    assert.ok(pending);
    assert.equal(pending.tone, "warn");
    assert.equal(pending.route, "#/approvals");
  });

  it("flags an expired session with a real route", () => {
    const s = { ...initialState(), sessionExpired: true };
    const items = attentionItems(s, 0);
    const expired = items.find((i) => i.id === "session-expired");
    assert.ok(expired);
    assert.equal(expired.route, "#/");
  });

  it("every item carries a description plus a hash route", () => {
    const s = applyApprovals(
      { ...initialState(), sessionExpired: true },
      [{ approval_id: "a1", agent: "bob", project: "web", key: "k", status: "pending", expires_at: "" }],
    );
    for (const item of attentionItems(s, 0)) {
      assert.ok(item.id.length > 0);
      assert.ok(item.title.length > 0);
      assert.ok(item.detail.length > 0);
      assert.ok(item.route.startsWith("#/"));
    }
  });
});

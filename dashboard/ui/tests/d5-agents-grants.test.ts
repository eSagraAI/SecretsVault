// D5 agents + grants: one-time-token discipline, tone mappings, grant-diff
// boundaries, and the revoked/null grant derivations. Pure functions only —
// no DOM, no framework.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { takeOneTimeToken } from "../screens/agents.js";
import {
  agentStatusTone,
  applyGrants,
  capabilityMatrix,
  capabilityTone,
  grantRunRemoved,
  grantWidens,
  initialState,
  type AgentAddResult,
} from "../state.js";

const SECRET = "sv1-test-token-abcdef0123456789abcdef";

describe("takeOneTimeToken returns display-only output", () => {
  it("shows the token and persists nothing", () => {
    const res: AgentAddResult = { agent_id: "ag1", token: SECRET, token_saved_path: "/tmp/tok" };
    const out = takeOneTimeToken(res);
    assert.equal(out.shown, SECRET);
    assert.equal(out.persisted, null);
  });

  it("exposes no other key a caller could stash in state", () => {
    const out = takeOneTimeToken({ agent_id: "ag1", token: SECRET, token_saved_path: null });
    assert.deepEqual(Object.keys(out).sort(), ["persisted", "shown"]);
  });

  it("throws when the result carries no token instead of inventing one", () => {
    assert.throws(() => takeOneTimeToken({ agent_id: "a", token: "", token_saved_path: null }), /no token/);
  });
});

describe("capabilityTone weights sensitivity without approving the unknown", () => {
  it("maps reveal/manage to warn", () => {
    assert.equal(capabilityTone("reveal"), "warn");
    assert.equal(capabilityTone("manage"), "warn");
  });

  it("maps run/inject to info and read to mute", () => {
    assert.equal(capabilityTone("run"), "info");
    assert.equal(capabilityTone("inject"), "info");
    assert.equal(capabilityTone("read"), "mute");
  });

  it("mutes anything unknown instead of approving it", () => {
    assert.equal(capabilityTone("teleport"), "mute");
    assert.equal(capabilityTone(""), "mute");
  });
});

describe("agentStatusTone only approves active", () => {
  it("maps active to ok and revoked to bad", () => {
    assert.equal(agentStatusTone("active"), "ok");
    assert.equal(agentStatusTone("revoked"), "bad");
  });

  it("mutes anything else", () => {
    assert.equal(agentStatusTone("suspended"), "mute");
    assert.equal(agentStatusTone(""), "mute");
  });
});

describe("capabilityMatrix excludes revoked grants and tolerates null grants", () => {
  it("unions only the live agents and projects", () => {
    const s = applyGrants(initialState(), [
      { agent: "bob", project: "vault", ops: ["read"], revoked: false },
      { agent: "alice", project: "vault", ops: ["run"], revoked: false },
      { agent: "ghost", project: "vault", ops: ["manage"], revoked: true },
      { agent: "bob", project: "archive", ops: ["read"], revoked: true },
    ]);
    const m = capabilityMatrix(s);
    assert.deepEqual(m.agents, ["alice", "bob"]);
    assert.deepEqual(m.projects, ["vault"]);
  });

  it("null grants mean an empty matrix, never a throw", () => {
    assert.deepEqual(capabilityMatrix(initialState()), { agents: [], projects: [] });
  });
});

describe("grantWidens fires on any added capability", () => {
  it("adding manage alone widens", () => {
    assert.equal(grantWidens(["read", "inject", "run", "reveal"], ["read", "inject", "run", "reveal", "manage"]), true);
  });

  it("pure narrowing never widens, even to empty", () => {
    assert.equal(grantWidens(["read", "run"], ["read"]), false);
    assert.equal(grantWidens(["read"], []), false);
  });

  it("add-plus-remove still widens when anything is added", () => {
    assert.equal(grantWidens(["read", "run"], ["read", "reveal"]), true);
  });
});

describe("grantRunRemoved fires exactly on held-then-dropped run", () => {
  it("detects the boundary cases", () => {
    assert.equal(grantRunRemoved(["read", "run"], ["read"]), true);
    assert.equal(grantRunRemoved(["read"], ["read"]), false);
    assert.equal(grantRunRemoved([], ["run"]), false);
    assert.equal(grantRunRemoved(["run"], ["run"]), false);
    assert.equal(grantRunRemoved(["run"], []), true);
  });
});

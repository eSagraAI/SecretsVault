// D3 slices: agents / grants / approvals (HITL inbox), the one-time token
// discipline, the grant-diff helpers, the countdown helper, and the badge
// count rule. Pure functions only — no DOM, no framework.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import * as api from "../api.js";
import { approvalsPollEligible } from "../app.js";
import { takeOneTimeToken } from "../screens/agents.js";
import {
  applyAgents,
  applyApprovals,
  applyBoot,
  applyGrants,
  applyLock,
  approvalCount,
  approvalCountdown,
  applyProjects,
  CAPABILITIES,
  RESERVED_CAPABILITIES,
  grantRunRemoved,
  grantWidens,
  initialState,
  type AgentAddResult,
  type BrokerStatus,
  type PinStatus,
} from "../state.js";

const STATUS: BrokerStatus = { version: 1, created: "c", locked: false, online: true, trusted: true, initialized: true };
const PIN: PinStatus = { pinned: true };

describe("api surface covers the nine D3 commands", () => {
  it("API_COMMANDS holds the D3 nine within the frozen surface and exposes no passthrough", () => {
    // Grown 28 -> 30 in D6 (audit_show / audit_verify); the nine D3 entries
    // and the no-passthrough property are what this test is about.
    assert.equal(api.API_COMMANDS.length, 30);
    assert.ok(api.API_COMMANDS.includes("agents_list"));
    assert.ok(api.API_COMMANDS.includes("agent_add"));
    assert.ok(api.API_COMMANDS.includes("agent_revoke"));
    assert.ok(api.API_COMMANDS.includes("grants_list"));
    assert.ok(api.API_COMMANDS.includes("grant_set"));
    assert.ok(api.API_COMMANDS.includes("grant_revoke"));
    assert.ok(api.API_COMMANDS.includes("approvals_pending"));
    assert.ok(api.API_COMMANDS.includes("approval_approve"));
    assert.ok(api.API_COMMANDS.includes("approval_deny"));
    assert.equal("call" in api, false);
    assert.equal("invoke" in api, false);
    assert.equal("bridge" in api, false);
  });
});

describe("capabilities and the reserved marker", () => {
  it("exposes exactly the five grantable capabilities, manage included", () => {
    assert.deepEqual([...CAPABILITIES], ["read", "inject", "run", "reveal", "manage"]);
  });
  it("flags manage as reserved without removing it from the grantable set", () => {
    // The marker is display-only: `manage` must stay grantable and round-trip.
    assert.equal(RESERVED_CAPABILITIES.manage, true);
    assert.equal(RESERVED_CAPABILITIES.read, undefined);
    assert.ok(CAPABILITIES.includes("manage"));
    const s = applyGrants(initialState(), [{ agent: "a", project: "p", ops: ["read", "manage"], revoked: false }]);
    assert.deepEqual(s.grants?.[0]?.ops, ["read", "manage"]);
  });
});

describe("one-time token is never persisted", () => {
  const SECRET = "sv1-test-token-abcdef0123456789abcdef";
  it("takeOneTimeToken shows the token and persists nothing", () => {
    const res: AgentAddResult = { agent_id: "ag1", token: SECRET, token_saved_path: "/tmp/tok" };
    const out = takeOneTimeToken(res);
    assert.equal(out.shown, SECRET);
    assert.equal(out.persisted, null);
  });
  it("the agents payload leaves no token material anywhere in state", () => {
    const res: AgentAddResult = { agent_id: "ag1", token: SECRET, token_saved_path: null };
    const { shown, persisted } = takeOneTimeToken(res);
    assert.equal(shown, SECRET);
    assert.equal(persisted, null);
    const s = applyAgents(initialState(), [{ name: "ag1", status: "active", token_prefix: "abcdef12" }]);
    assert.equal(JSON.stringify(s).includes(SECRET), false);
  });
  it("rejects a result with no token instead of inventing one", () => {
    assert.throws(() => takeOneTimeToken({ agent_id: "a", token: "", token_saved_path: null }), /no token/);
  });
});

describe("D3 slices store what they are given", () => {
  it("applyAgents keeps rows and drops empty names", () => {
    const s = applyAgents(initialState(), [
      { name: "a", status: "active", token_prefix: "ab12" },
      { name: "", status: "active", token_prefix: "zz" },
    ]);
    assert.equal(s.agents?.length, 1);
    assert.equal(s.agents?.[0]?.name, "a");
  });
  it("applyGrants keeps agent/project/ops/revoked", () => {
    const s = applyGrants(initialState(), [{ agent: "a", project: "p", ops: ["read", "manage"], revoked: false }]);
    assert.deepEqual(s.grants?.[0]?.ops, ["read", "manage"]);
    assert.equal(s.grants?.[0]?.revoked, false);
  });
  it("applyApprovals keeps the inbox rows", () => {
    const s = applyApprovals(initialState(), [
      { approval_id: "ap1", agent: "a", project: "p", key: "K", status: "pending", expires_at: "2026-09-16T00:00:00Z" },
    ]);
    assert.equal(s.approvals?.length, 1);
    assert.equal(s.approvals?.[0]?.key, "K");
  });
});

describe("lock clears the D3 slices", () => {
  it("applyLock leaves agents, grants and approvals null", () => {
    let s = applyBoot(initialState(), STATUS, PIN);
    s = applyAgents(s, [{ name: "a", status: "active", token_prefix: "ab" }]);
    s = applyGrants(s, [{ agent: "a", project: "p", ops: ["read"], revoked: false }]);
    s = applyApprovals(s, [
      { approval_id: "ap1", agent: "a", project: "p", key: "K", status: "pending", expires_at: "e" },
    ]);
    s = applyProjects(s, [{ name: "p", paths: [] }]);
    s = applyLock();
    assert.equal(s.agents, null);
    assert.equal(s.grants, null);
    assert.equal(s.approvals, null);
    assert.deepEqual(s, initialState());
  });
});

describe("approvalCount never fabricates 0", () => {
  it("null slice ⇒ null; empty ⇒ 0; populated ⇒ length", () => {
    assert.equal(approvalCount(initialState()), null);
    assert.equal(approvalCount(applyApprovals(initialState(), [])), 0);
    assert.equal(
      approvalCount(
        applyApprovals(initialState(), [
          { approval_id: "a", agent: "x", project: "p", key: "k", status: "pending", expires_at: "e" },
          { approval_id: "b", agent: "x", project: "p", key: "k", status: "pending", expires_at: "e" },
        ]),
      ),
      2,
    );
  });
});

describe("approvals poll gate (20 s, approvals-only, visibility-gated)", () => {
  it("runs only when trusted + unlocked + live session + visible", () => {
    assert.equal(approvalsPollEligible("trusted", false, true, true), true);
    assert.equal(approvalsPollEligible("trusted", false, true, false), false);
    assert.equal(approvalsPollEligible("trusted", false, false, true), false);
    assert.equal(approvalsPollEligible("trusted", true, true, true), false);
    assert.equal(approvalsPollEligible("trusted", null, true, true), false);
    assert.equal(approvalsPollEligible("offline", false, true, true), false);
    assert.equal(approvalsPollEligible("boot", false, true, true), false);
  });
});
describe("approval countdown honesty", () => {
  it("future expiry ⇒ positive remaining; past ⇒ expired, never negative", () => {
    const now = Date.parse("2026-09-16T12:00:00Z");
    const future = approvalCountdown("2026-09-16T12:05:00Z", now);
    assert.equal(future.expired, false);
    assert.ok(future.remainingMs > 0);
    assert.match(future.label, /expires in/);
    const past = approvalCountdown("2026-09-16T11:59:00Z", now);
    assert.equal(past.expired, true);
    assert.equal(past.remainingMs, 0);
    assert.equal(past.label, "expired");
  });
  it("unparseable expiry stays honest instead of inventing a number", () => {
    const out = approvalCountdown("not-a-time", 0);
    assert.equal(out.remainingMs, 0);
    assert.match(out.label, /unknown/);
  });
});

describe("grant-diff helpers drive the confirm and consequence notes", () => {
  it("adding any capability widens — including manage alone", () => {
    assert.equal(grantWidens(["read"], ["read", "inject"]), true);
    assert.equal(grantWidens(["read", "inject", "run", "reveal"], ["read", "inject", "run", "reveal", "manage"]), true);
    assert.equal(grantWidens([], ["read"]), true);
  });
  it("removing authority never widens, even to empty", () => {
    assert.equal(grantWidens(["read", "run"], ["read"]), false);
    assert.equal(grantWidens(["read"], []), false);
    assert.equal(grantWidens(["read"], ["read"]), false);
  });
  it("add-plus-remove still widens when anything is added", () => {
    assert.equal(grantWidens(["read", "run"], ["read", "reveal"]), true);
  });
  it("run removal is detected exactly when held-then-dropped", () => {
    assert.equal(grantRunRemoved(["read", "run"], ["read"]), true);
    assert.equal(grantRunRemoved(["read"], ["read"]), false);
    assert.equal(grantRunRemoved([], ["run"]), false);
    assert.equal(grantRunRemoved(["run"], ["run"]), false);
  });
});

describe("grant_set joins ops with a comma in the wrapper", () => {
  it("sends ops as a single comma-separated string via the bridge", async () => {
    const calls: Array<{ cmd: string; args: unknown }> = [];
    const g = globalThis as unknown as {
      window: { __TAURI_INTERNALS__?: { invoke: (cmd: string, args?: unknown) => Promise<unknown> } };
    };
    const hadWindow = "window" in globalThis;
    const prev = (globalThis as unknown as Record<string, unknown>).window;
    (globalThis as unknown as Record<string, unknown>).window = {
      __TAURI_INTERNALS__: {
        invoke: (cmd: string, args?: unknown) => {
          calls.push({ cmd, args });
          return Promise.resolve({ granted: "a→p" });
        },
      },
    };
    try {
      await api.grantSet("a", "p", ["read", "inject"]);
      await api.grantSet("a", "p", []);
    } finally {
      if (hadWindow) (globalThis as unknown as Record<string, unknown>).window = prev;
      else delete (globalThis as unknown as Record<string, unknown>).window;
      void g;
    }
    assert.equal(calls.length, 2);
    assert.equal(calls[0]?.cmd, "grant_set");
    assert.deepEqual(calls[0]?.args, { agent: "a", project: "p", ops: "read,inject" });
    assert.deepEqual(calls[1]?.args, { agent: "a", project: "p", ops: "" });
  });
});

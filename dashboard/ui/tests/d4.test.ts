// D4: reveal-value discipline, leases/runs slices, clipboard policy, lease
// status tones, payload-shape guards, and the frozen command surface.
// Pure functions only — no DOM, no framework.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import * as api from "../api.js";
import { REVEAL_AUTO_HIDE_MS, revealClipboardCopy, revealVisible, takeRevealValue } from "../screens/reveal.js";
import {
  applyActiveProject,
  applyAgents,
  applyApprovals,
  applyBoot,
  applyError,
  applyGrants,
  applyLeases,
  applyLock,
  applyMutationDone,
  applyMutationStart,
  applyOverview,
  applyProjects,
  applyRuns,
  applySecrets,
  applySelectedProject,
  applyUnlockSuccess,
  initialState,
  leaseStatusTone,
  type BrokerStatus,
  type LeaseEntry,
  type OverviewData,
  type PinStatus,
  type RunEntry,
} from "../state.js";

const STATUS: BrokerStatus = { version: 1, created: "c", locked: false, online: true, trusted: true, initialized: true };
const PIN: PinStatus = { pinned: true };
const TRAP = "sv1-reveal-trap-9f8e7d6c5b4a3940313233343536373839abcdef";

function overview(): OverviewData {
  return {
    online: true,
    trusted: true,
    version: 1,
    created: "2026-09-16",
    locked: false,
    session_held: true,
    projects: 1,
    secrets_total: 1,
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
  };
}

function lease(partial: Partial<LeaseEntry> = {}): LeaseEntry {
  return {
    lease_id: "l1",
    lease_prefix: "l1-prefix",
    project: "p",
    ops: ["read"],
    expires_at: "2026-09-17T00:00:00Z",
    expires_in: 60,
    status: "active",
    ...partial,
  };
}

function run(partial: Partial<RunEntry> = {}): RunEntry {
  return {
    run_id: "r1",
    agent: "a",
    project: "p",
    pid: 123,
    started_at: "2026-09-17T00:00:00Z",
    status: "running",
    ...partial,
  };
}

describe("api surface covers the four D4 commands", () => {
  it("API_COMMANDS is exactly the frozen surface and exposes no passthrough", () => {
    // Grown 28 -> 30 in D6 (audit_show / audit_verify).
    assert.equal(api.API_COMMANDS.length, 30);
    assert.ok(api.API_COMMANDS.includes("reveal"));
    assert.ok(api.API_COMMANDS.includes("leases_list"));
    assert.ok(api.API_COMMANDS.includes("lease_revoke"));
    assert.ok(api.API_COMMANDS.includes("runs_list"));
    assert.equal("call" in api, false);
    assert.equal("invoke" in api, false);
    assert.equal("bridge" in api, false);
  });
  it("wrappers send camelCase args over the single bridge", async () => {
    const calls: Array<{ cmd: string; args: unknown }> = [];
    const prev = (globalThis as unknown as Record<string, unknown>).window;
    const hadWindow = "window" in globalThis;
    (globalThis as unknown as Record<string, unknown>).window = {
      __TAURI_INTERNALS__: {
        invoke: (cmd: string, args?: unknown) => {
          calls.push({ cmd, args });
          if (cmd === "reveal") return Promise.resolve({ value: "v" });
          if (cmd === "leases_list") return Promise.resolve({ leases: [] });
          if (cmd === "lease_revoke") return Promise.resolve({ lease_id: "l1", revoked: true });
          return Promise.resolve({ runs: [] });
        },
      },
    };
    try {
      await api.reveal("p", "K");
      await api.leasesList();
      await api.leaseRevoke("l1");
      await api.runsList();
    } finally {
      if (hadWindow) (globalThis as unknown as Record<string, unknown>).window = prev;
      else delete (globalThis as unknown as Record<string, unknown>).window;
    }
    assert.equal(calls.length, 4);
    assert.deepEqual(calls[0], { cmd: "reveal", args: { project: "p", key: "K" } });
    assert.deepEqual(calls[1], { cmd: "leases_list", args: {} });
    assert.deepEqual(calls[2], { cmd: "lease_revoke", args: { leaseId: "l1" } });
    assert.deepEqual(calls[3], { cmd: "runs_list", args: {} });
  });
});

describe("the reveal trap: the value never enters ShellState", () => {
  it("takeRevealValue shows the value and persists nothing", () => {
    const out = takeRevealValue({ value: TRAP });
    assert.equal(out.shown, TRAP);
    assert.equal(out.persisted, null);
  });
  it("no state transition retains the value in any serialization", () => {
    let s = initialState();
    s = applyBoot(s, STATUS, PIN);
    s = applyUnlockSuccess(s, { unlocked: true }, Date.now());
    s = applyOverview(s, overview());
    s = applyProjects(s, [{ name: "p", paths: [] }]);
    s = applySelectedProject(s, "p");
    s = applyActiveProject(s, "p");
    s = applySecrets(s, "p", [{ key: "K", updated: "u" }]);
    s = applyAgents(s, [{ name: "a", status: "active", token_prefix: "ab" }]);
    s = applyGrants(s, [{ agent: "a", project: "p", ops: ["read"], revoked: false }]);
    s = applyApprovals(s, [
      { approval_id: "ap", agent: "a", project: "p", key: "K", status: "pending", expires_at: "e" },
    ]);
    s = applyLeases(s, [lease()]);
    s = applyRuns(s, [run()]);
    s = applyMutationStart(s, "reveal");
    s = applyMutationDone(s);
    s = applyError(s, { code: "E_UNKNOWN", message: "x" });
    // The only call that ever sees the value returns nothing to persist.
    const { shown, persisted } = takeRevealValue({ value: TRAP });
    assert.equal(shown, TRAP);
    assert.equal(persisted, null);
    void shown;
    assert.equal(JSON.stringify(s).includes(TRAP), false);
  });
  it("rejects an empty reveal result instead of showing nothing", () => {
    assert.throws(() => takeRevealValue({ value: "" }), /no value/);
  });
});

describe("reveal auto-hide decision", () => {
  it("the window is fifteen seconds", () => {
    assert.equal(REVEAL_AUTO_HIDE_MS, 15_000);
  });
  it("just-revealed and inside the window stay visible; past it hides", () => {
    const shown = 1_000_000;
    assert.equal(revealVisible(shown, shown, false), true);
    assert.equal(revealVisible(shown, shown + REVEAL_AUTO_HIDE_MS - 1, false), true);
    assert.equal(revealVisible(shown, shown + REVEAL_AUTO_HIDE_MS, false), false);
    assert.equal(revealVisible(shown, shown + 60_000, false), false);
  });
  it("never-revealed or dismissed is hidden", () => {
    assert.equal(revealVisible(null, 1_000_000, false), false);
    assert.equal(revealVisible(1_000_000, 1_000_000, true), false);
  });
});

describe("clipboard policy pins no auto-copy", () => {
  it("a fresh reveal does not copy; only the explicit button does", () => {
    assert.equal(revealClipboardCopy("reveal"), false);
    assert.equal(revealClipboardCopy("explicit"), true);
  });
});

describe("D4 slices store what they are given", () => {
  it("applyLeases keeps prefix/project/ops/expiry/status", () => {
    const s = applyLeases(initialState(), [lease({ lease_id: "l9", ops: ["read", "inject"] })]);
    assert.equal(s.leases?.length, 1);
    assert.equal(s.leases?.[0]?.lease_prefix, "l1-prefix");
    assert.deepEqual(s.leases?.[0]?.ops, ["read", "inject"]);
  });
  it("applyRuns keeps id/agent/project/pid/started/status", () => {
    const s = applyRuns(initialState(), [run({ run_id: "r9", pid: 4242 })]);
    assert.equal(s.runs?.length, 1);
    assert.equal(s.runs?.[0]?.run_id, "r9");
    assert.equal(s.runs?.[0]?.pid, 4242);
  });
  it("applyLock leaves leases and runs null", () => {
    let s = applyBoot(initialState(), STATUS, PIN);
    s = applyLeases(s, [lease()]);
    s = applyRuns(s, [run()]);
    s = applyLock();
    assert.equal(s.leases, null);
    assert.equal(s.runs, null);
    assert.deepEqual(s, initialState());
  });
});

describe("leaseStatusTone keeps the three states visually unambiguous", () => {
  it("maps active/expired/revoked to three distinct tones", () => {
    const active: string = leaseStatusTone("active");
    const expired: string = leaseStatusTone("expired");
    const revoked: string = leaseStatusTone("revoked");
    assert.deepEqual([active, expired, revoked], ["ok", "mute", "bad"]);
    assert.ok(active !== expired && expired !== revoked && active !== revoked);
  });
});

describe("payload-shape guards drop credential-shaped fields", () => {
  it("a lease row carrying lease_credential keeps no such key after applyLeases", () => {
    const smuggled = { ...lease(), lease_credential: "CRED-SHOULD-NEVER-LAND" } as unknown as LeaseEntry;
    const s = applyLeases(initialState(), [smuggled]);
    const text = JSON.stringify(s);
    assert.equal("lease_credential" in (s.leases?.[0] as unknown as Record<string, unknown>), false);
    assert.equal(text.includes("CRED-SHOULD-NEVER-LAND"), false);
  });
  it("a run row carrying argv/env/cwd/executable keeps none after applyRuns", () => {
    const smuggled = {
      ...run(),
      argv: ["--secret", "hunter2"],
      env: { TOKEN: "hunter2" },
      cwd: "/tmp/x",
      executable: "/bin/sh",
    } as unknown as RunEntry;
    const s = applyRuns(initialState(), [smuggled]);
    const row = s.runs?.[0] as unknown as Record<string, unknown>;
    assert.equal("argv" in row, false);
    assert.equal("env" in row, false);
    assert.equal("cwd" in row, false);
    assert.equal("executable" in row, false);
    assert.equal(JSON.stringify(s).includes("hunter2"), false);
  });
});

// D7 state: vault-not-created posture, fatal full-stop, mid-session lock
// escalation, actionable error advice, and near-expiry session on Overview.
// Pure functions only — no DOM, no framework.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import {
  applyError,
  applyLock,
  attentionItems,
  deriveConn,
  errorAdvice,
  fatalStop,
  unlockGateReason,
  initialState,
  VAULT_CORRUPT,
  type BrokerStatus,
  type PinStatus,
} from "../state.js";

const V = 1;
const FP = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

function status(partial: Partial<BrokerStatus> = {}): BrokerStatus {
  return {
    version: V,
    created: "2026-09-16",
    locked: false,
    online: true,
    trusted: true,
    initialized: true,
    fingerprint: FP,
    ...partial,
  };
}
const pin: PinStatus = { pinned: true, fingerprint: FP };
const noPin: PinStatus = { pinned: false };

describe("deriveConn vault-not-created posture", () => {
  it("verified identity with no vault is no-vault", () => {
    assert.equal(deriveConn(status({ initialized: false }), pin), "no-vault");
  });
  it("untrusted outranks no-vault", () => {
    assert.equal(deriveConn(status({ trusted: true, initialized: false }), noPin), "untrusted");
  });
  it("mismatch outranks no-vault", () => {
    assert.equal(deriveConn(status({ trusted: false, initialized: false }), pin), "mismatch");
  });
  it("offline outranks no-vault", () => {
    assert.equal(deriveConn(status({ online: false, initialized: false }), pin), "offline");
  });
  it("initialized vault stays trusted", () => {
    assert.equal(deriveConn(status({ initialized: true }), pin), "trusted");
  });
});

describe("fatal full-stop", () => {
  it("starts null and E_VAULT_CORRUPT sets fatal as well as error", () => {
    assert.equal(initialState().fatal, null);
    const s = applyError(initialState(), { code: "E_VAULT_CORRUPT", message: "integrity check failed" });
    assert.equal(s.error?.code, "E_VAULT_CORRUPT");
    assert.equal(s.fatal?.code, VAULT_CORRUPT);
    assert.equal(fatalStop(s)?.code, "E_VAULT_CORRUPT");
  });
  it("other codes leave fatal alone", () => {
    const s = applyError(initialState(), { code: "E_AUTH", message: "bad passphrase" });
    assert.equal(s.error?.code, "E_AUTH");
    assert.equal(s.fatal, null);
    assert.equal(fatalStop(s), null);
  });
  it("applyLock clears fatal", () => {
    const broken = applyError(initialState(), { code: "E_VAULT_CORRUPT", message: "bad" });
    assert.ok(fatalStop(broken));
    assert.equal(fatalStop(applyLock()), null);
  });
});

describe("mid-session lock escalates immediately", () => {
  it("E_LOCKED flips status.locked so the unlock gate fires on the next render", () => {
    const base = { ...initialState(), status: status({ locked: false }) };
    const s = applyError(base, { code: "E_LOCKED", message: "idle auto-lock" });
    assert.equal(s.status?.locked, true);
    assert.equal(s.error?.code, "E_LOCKED");
  });
  it("no path leaves a stale locked:false behind", () => {
    for (const locked of [true, false]) {
      const s = applyError(
        { ...initialState(), status: status({ locked }) },
        { code: "E_LOCKED", message: "x" },
      );
      assert.equal(s.status?.locked, true);
    }
  });
  it("E_LOCKED without a status slice still records the error", () => {
    const s = applyError(initialState(), { code: "E_LOCKED", message: "x" });
    assert.equal(s.status, null);
    assert.equal(s.error?.code, "E_LOCKED");
  });
});

describe("errorAdvice is one actionable sentence or null", () => {
  const codes = [
    "E_AUTH",
    "E_LOCKED",
    "E_SESSION_EXPIRED",
    "E_BUSY",
    "E_AUDIT_FULL",
    "E_VAULT_CORRUPT",
    "E_PERMISSION",
    "E_HUMAN_REQUIRED",
    "E_PATH_NOT_AUTHORIZED",
    "E_LEASE_EXPIRED",
    "E_VAULT_TOO_LARGE",
    "E_WEAK_PASSPHRASE",
  ];
  for (const code of codes) {
    it(`${code} advises`, () => {
      const advice = errorAdvice(code);
      assert.ok(typeof advice === "string" && advice.length > 0);
    });
  }
  it("unknown codes get no advice", () => {
    assert.equal(errorAdvice("E_UNKNOWN"), null);
    assert.equal(errorAdvice("NOPE"), null);
  });
  it("advice never names a path, promises a retry, or claims security", () => {
    for (const code of codes) {
      const advice = errorAdvice(code) ?? "";
      assert.doesNotMatch(advice, /\//);
      assert.doesNotMatch(advice, /secur/i);
      assert.ok(!/will retry|automatically retried|guarantee/i.test(advice));
    }
  });
});

describe("attentionItems near-expiry session", () => {
  const live = (expiresIn: number, atMs: number) => ({
    ...initialState(),
    session: { present: true, expiresIn },
    unlockedAtMs: atMs,
  });
  it("includes session-about-to-expire with the warning text, routed to Settings", () => {
    const s = live(300, 1_000_000);
    const nowMs = 1_000_000 + 250_000;
    const items = attentionItems(s, nowMs);
    const found = items.find((i) => i.id === "session-about-to-expire");
    assert.ok(found);
    assert.equal(found.route, "#/settings");
    assert.equal(found.tone, "warn");
    assert.ok(found.title.length > 0 && found.detail.length > 0);
  });
  it("omits it with no session or plenty of life left", () => {
    assert.equal(
      attentionItems(initialState(), 1_000_000).some((i) => i.id === "session-about-to-expire"),
      false,
    );
    assert.equal(
      attentionItems(live(300, 1_000_000), 1_000_000).some((i) => i.id === "session-about-to-expire"),
      false,
    );
  });
  it("sits after the limit items without reordering them", () => {
    const s = {
      ...live(300, 1_000_000),
      overview: {
        online: true,
        trusted: true,
        version: 1,
        created: "2026-09-16",
        locked: false,
        session_held: true,
        projects: 1,
        secrets_total: 1,
        secrets_total_exact: true,
        agents_active: 0,
        runs_active: 0,
        approvals_pending: 0,
        leases_active: 0,
        idle_lock_secs: 300,
        idle_in: 120,
        audit_bytes: 90,
        audit_soft_limit: 100,
        audit_hard_limit: 200,
        vault_bytes: 90,
        vault_max_bytes: 100,
      },
    };
    const ids = attentionItems(s, 1_000_000 + 250_000).map((i) => i.id);
    assert.deepEqual(ids, ["audit-near-limit", "vault-near-max", "session-about-to-expire"]);
  });
});

describe("unlock gate reason distinguishes the two causes", () => {
  it("a genuinely locked vault reports locked", () => {
    const s = { ...initialState(), conn: "trusted" as const, status: status({ locked: true }) };
    assert.equal(unlockGateReason(s), "locked");
  });

  it("an unlocked vault with a lapsed session reports session, never locked", () => {
    const s = {
      ...initialState(),
      conn: "trusted" as const,
      status: status({ locked: false }),
      sessionExpired: true,
    };
    assert.equal(unlockGateReason(s), "session");
    // The lock pill and the gate must not disagree: the vault is NOT locked.
    assert.equal(s.status.locked, false);
  });

  it("locked outranks a simultaneously lapsed session", () => {
    const s = {
      ...initialState(),
      conn: "trusted" as const,
      status: status({ locked: true }),
      sessionExpired: true,
    };
    assert.equal(unlockGateReason(s), "locked");
  });
});

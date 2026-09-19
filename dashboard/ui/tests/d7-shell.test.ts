// D7 shell posture contract: fatal full-stop, offline single-explanation,
// session-ticker predicate, global-banner advice, and structured errors.
// Pure state functions only — no DOM, no timers, no framework.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import {
  applyBoot,
  applyError,
  applyLock,
  applyUnlockSuccess,
  errorAdvice,
  fatalStop,
  initialState,
  mapError,
  showSessionCard,
  type BrokerStatus,
  type PinStatus,
} from "../state.js";

const FP = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

function status(partial: Partial<BrokerStatus> = {}): BrokerStatus {
  return {
    version: 1,
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

describe("fatal full-stop outranks every posture", () => {
  it("starts null and only E_VAULT_CORRUPT sets it", () => {
    assert.equal(fatalStop(initialState()), null);
    assert.equal(fatalStop(applyError(initialState(), { code: "E_AUTH", message: "bad" })), null);
    const bad = applyError(initialState(), { code: "E_VAULT_CORRUPT", message: "integrity failed" });
    assert.equal(fatalStop(bad)?.code, "E_VAULT_CORRUPT");
  });
  it("lock clears the full stop", () => {
    const bad = applyError(initialState(), { code: "E_VAULT_CORRUPT", message: "bad" });
    assert.ok(fatalStop(bad));
    assert.equal(fatalStop(applyLock()), null);
  });
});

describe("offline renders from state without fabrication", () => {
  it("derives offline from an unreachable broker", () => {
    const s = applyBoot(initialState(), status({ online: false }), { pinned: false });
    assert.equal(s.conn, "offline");
    assert.equal(showSessionCard(s), false);
  });
});

describe("session ticker predicate only holds when the card can show", () => {
  it("false until a real unlock, true after, false again on lock", () => {
    const booted = applyBoot(initialState(), status({ locked: true }), pin);
    assert.equal(showSessionCard(booted), false);
    const unlocked = applyUnlockSuccess(booted, { unlocked: true }, 1_000);
    assert.equal(showSessionCard(unlocked), true);
    assert.equal(showSessionCard(applyLock()), false);
  });
});

describe("global banner keeps the code and appends advice when present", () => {
  it("known codes advise, unknown codes stay bare", () => {
    assert.ok((errorAdvice("E_LOCKED") ?? "").length > 0);
    assert.equal(errorAdvice("E_UNKNOWN"), null);
  });
  it("local validation errors map through mapError without throwing", () => {
    assert.deepEqual(mapError({ code: "E_INVALID_INPUT", message: "Enter a project name." }), {
      code: "E_INVALID_INPUT",
      message: "Enter a project name.",
    });
  });
});

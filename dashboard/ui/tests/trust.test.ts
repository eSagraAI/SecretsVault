// Error/redaction guards + blocked-posture gate. Pure functions only.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import {
  applyBoot,
  canOfferUnlock,
  initialState,
  mapError,
  redactForLog,
  showSessionCard,
  type BrokerStatus,
  type PinStatus,
} from "../state.js";

const V = 1;
const FP = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

function online(locked: boolean, trusted: boolean): BrokerStatus {
  return { version: V, created: "2026-09-16", locked, online: true, trusted, initialized: true, fingerprint: FP };
}
const offlineStatus: BrokerStatus = { version: V, created: "2026-09-16", locked: true, online: false, trusted: false, initialized: true };
const noPin: PinStatus = { pinned: false };
const pin: PinStatus = { pinned: true, fingerprint: FP };

describe("blocked posture (no pin)", () => {
  it("no pin derives untrusted and offers no unlock gate or session card", () => {
    const s = applyBoot(initialState(), online(true, false), noPin);
    assert.equal(s.conn, "untrusted");
    assert.equal(canOfferUnlock(s), false);
    assert.equal(showSessionCard(s), false);
  });
  it("mismatch also offers no unlock gate", () => {
    const s = applyBoot(initialState(), online(true, false), pin);
    assert.equal(s.conn, "mismatch");
    assert.equal(canOfferUnlock(s), false);
  });
  it("only trusted+locked offers the unlock gate", () => {
    assert.equal(canOfferUnlock(initialState()), false);
    assert.equal(canOfferUnlock(applyBoot(initialState(), offlineStatus, noPin)), false);
    assert.equal(canOfferUnlock(applyBoot(initialState(), online(true, true), pin)), true);
    const unlocked = applyBoot(initialState(), online(false, true), pin);
    assert.equal(canOfferUnlock(unlocked), false);
  });
});

describe("mapError", () => {
  it("passes the backend {code, message} shape through", () => {
    assert.deepEqual(mapError({ code: "E_AUTH", message: "bad passphrase" }), {
      code: "E_AUTH",
      message: "bad passphrase",
    });
    assert.deepEqual(mapError({ code: "E_BROKER_UNTRUSTED", message: "identity changed" }).code, "E_BROKER_UNTRUSTED");
  });
  it("handles raw strings and junk defensively, never throwing", () => {
    assert.deepEqual(mapError("boom"), { code: "E_UNKNOWN", message: "boom" });
    assert.deepEqual(mapError(null), { code: "E_UNKNOWN", message: "Request failed." });
    assert.deepEqual(mapError(undefined), { code: "E_UNKNOWN", message: "Request failed." });
    assert.deepEqual(mapError(42), { code: "E_UNKNOWN", message: "Request failed." });
  });
  it("refuses to render an attacker-shaped code", () => {
    const m = mapError({ code: "<img src=x>", message: "x" });
    assert.equal(m.code, "E_UNKNOWN");
  });
});

describe("redactForLog", () => {
  it("never emits the passphrase or a credential-shaped string", () => {
    const pass = "correct-horse-9-battery";
    const cred = "TRAPCRED-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123";
    const out = redactForLog(`unlock failed for ${pass} carrying ${cred} done`, [pass]);
    assert.ok(!out.includes(pass), "passphrase leaked");
    assert.ok(!out.includes(cred), "credential leaked");
    assert.match(out, /\[redacted\]/);
    assert.match(out, /\[credential\]/);
  });
  it("keeps public identity material readable", () => {
    const out = redactForLog("session 1a2b3c4d touched, fingerprint abcdef0123456789 ok", []);
    assert.ok(out.includes("1a2b3c4d"), "prefix should stay readable");
    assert.ok(out.includes("abcdef0123456789"), "fingerprint should stay readable");
  });
});

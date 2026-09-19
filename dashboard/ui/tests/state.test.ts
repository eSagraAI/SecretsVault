// State-transition coherence: offline → untrusted → trusted → unlocked,
// failed unlock, lock-clears-all, and the session-absent case.
// Pure functions only — no DOM, no framework.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import {
  applyBoot,
  applyError,
  applyLock,
  applyUnlockSuccess,
  deriveConn,
  initialState,
  routeFor,
  sessionText,
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

describe("posture ladder", () => {
  it("offline beats everything", () => {
    assert.equal(deriveConn(offlineStatus, pin), "offline");
  });
  it("no pin means first-contact untrusted", () => {
    assert.equal(deriveConn(online(true, false), noPin), "untrusted");
  });
  it("pin that no longer verifies is a mismatch, never trusted", () => {
    assert.equal(deriveConn(online(true, false), pin), "mismatch");
  });
  it("pin present and verified is trusted", () => {
    assert.equal(deriveConn(online(false, true), pin), "trusted");
  });
  it("full ladder offline -> untrusted -> trusted -> unlocked stays coherent", () => {
    let s = initialState();
    s = applyBoot(s, offlineStatus, noPin);
    assert.equal(s.conn, "offline");
    s = applyBoot(s, online(true, false), noPin);
    assert.equal(s.conn, "untrusted");
    assert.equal(s.status?.locked, true);
    s = applyBoot(s, online(true, true), pin);
    assert.equal(s.conn, "trusted");
    s = applyUnlockSuccess(
      s,
      { unlocked: true, session_prefix: "1a2b3c4d", expires_at: "t", expires_in: 300 },
      1_000,
    );
    assert.equal(s.status?.locked, false);
    assert.equal(s.session.present, true);
    assert.equal(s.session.prefix, "1a2b3c4d");
  });
});

describe("failed unlock", () => {
  it("an E_AUTH failure never moves the state to unlocked", () => {
    let s = { ...applyBoot(initialState(), online(true, true), pin) };
    s = applyError(s, { code: "E_AUTH", message: "bad passphrase" });
    assert.equal(s.status?.locked, true);
    assert.equal(s.session.present, false);
    assert.equal(s.error?.code, "E_AUTH");
  });
});

describe("lock", () => {
  it("clears status, pin, session, health, and error", () => {
    let s = applyBoot(initialState(), online(false, true), pin);
    s = applyUnlockSuccess(s, { unlocked: true, session_prefix: "1a2b3c4d", expires_in: 300 }, 1_000);
    s = { ...s, health: null, error: { code: "E_AUTH", message: "x" } };
    s = applyLock();
    assert.deepEqual(s, initialState());
  });
});

describe("session-absent unlock", () => {
  it("missing session fields mean no session — never fabricated", () => {
    const s0 = applyBoot(initialState(), online(true, true), pin);
    const s = applyUnlockSuccess(s0, { unlocked: true }, 1_000);
    assert.equal(s.status?.locked, false);
    assert.equal(s.session.present, false);
    assert.equal(s.session.prefix, undefined);
    const text = sessionText(s.session, 2_000, s.unlockedAtMs);
    assert.match(text, /no session was seeded/);
  });
  it("a seeded session reports its prefix and remaining time", () => {
    const s0 = applyBoot(initialState(), online(true, true), pin);
    const s = applyUnlockSuccess(s0, { unlocked: true, session_prefix: "1a2b3c4d", expires_in: 300 }, 1_000);
    const text = sessionText(s.session, 31_000, s.unlockedAtMs);
    assert.match(text, /1a2b3c4d/);
    assert.match(text, /270s/);
  });
});

describe("routeFor", () => {
  it("maps the ten hashes and falls back to overview", () => {
    assert.equal(routeFor("#/"), "overview");
    assert.equal(routeFor("#/audit"), "audit");
    assert.equal(routeFor("#/settings"), "settings");
    assert.equal(routeFor("#/nope"), "overview");
    assert.equal(routeFor(""), "overview");
  });
});

describe("showSessionCard (offline-screenshot regression)", () => {
  it("renders no session card unless actually unlocked", () => {
    // boot: nothing known yet
    assert.equal(showSessionCard(initialState()), false);
    // offline: broker unreachable — must not claim any unlock outcome
    assert.equal(showSessionCard(applyBoot(initialState(), offlineStatus, noPin)), false);
    // untrusted: first contact, never unlocked
    assert.equal(showSessionCard(applyBoot(initialState(), online(true, false), noPin)), false);
    // trusted but locked: gate showing, no unlock observed
    assert.equal(showSessionCard(applyBoot(initialState(), online(true, true), pin)), false);
    // trusted + unlocked via a real unlock call: the ONLY card-allowed state
    const unlocked = applyUnlockSuccess(applyBoot(initialState(), online(true, true), pin), { unlocked: true }, 1_000);
    assert.equal(showSessionCard({ ...unlocked, status: { ...unlocked.status!, locked: false } }), true);
    // ...and only there may the no-session text appear
    assert.match(sessionText(unlocked.session, 2_000, unlocked.unlockedAtMs), /no session was seeded/);
  });
});

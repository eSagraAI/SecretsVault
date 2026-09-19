// D6 settings: the anti-fabrication contract. This screen is where invented
// configuration tends to appear, so the pinned field list, the read-only
// marker on every row, the exact action allowlist and the absence of any
// trust/pin-write surface are all asserted here — a fictitious control added
// later breaks a test instead of shipping. Pure functions only, no DOM.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { API_COMMANDS } from "../api.js";
import { SETTINGS_ACTIONS, settingsFields } from "../screens/settings.js";
import { initialState, type ShellState } from "../state.js";

/** The complete configuration surface, in order. Any addition is a contract change. */
const EXPECTED_LABELS = [
  "Wire protocol version",
  "Vault created",
  "Idle auto-lock window",
  "Session sliding TTL",
  "Session absolute ceiling",
  "Audit soft limit",
  "Audit hard limit",
  "Vault max size",
  "Broker fingerprint (pinned)",
  "Broker fingerprint (live probe)",
  "Trust writes",
];

/** A fully-populated shell so no row is accidentally "—" for the wrong reason. */
function populated(): ShellState {
  return {
    ...initialState(),
    conn: "trusted",
    status: { version: 1, created: "2026-09-16T00:00:00Z", locked: false, online: true, trusted: true, initialized: true },
    pin: { pinned: true, fingerprint: "a".repeat(64) },
    session: { present: true, expiresIn: 300, maxExpiresIn: 1800 },
    unlockedAtMs: 1,
    health: {
      locked: false,
      idle_lock_secs: 900,
      idle_in: 100,
      audit_bytes: 1024,
      audit_soft_limit: 1024 * 1024,
      audit_hard_limit: 2 * 1024 * 1024,
      vault_bytes: 2048,
      vault_max_bytes: 4 * 1024 * 1024,
      runs_active: 0,
      leases_active: 0,
      approvals_pending: 0,
    },
    settings: { probedFingerprint: "b".repeat(64), probedAtMs: 2 },
  };
}

const FORBIDDEN = /trust|pin_?write|reset|theme|autostart|tray|sync|provider|telemetry|cloud|keychain|updater/i;

describe("the configuration field list is fixed", () => {
  it("is exactly the pinned rows, in order", () => {
    assert.deepEqual(
      settingsFields(populated()).map((r) => r.label),
      EXPECTED_LABELS,
    );
  });

  it("marks every row read-only at the row level", () => {
    for (const row of settingsFields(populated())) assert.equal(row.readonly, true, row.label);
  });

  it("reports facts, never Boolean-style switch states", () => {
    for (const row of settingsFields(populated())) {
      assert.doesNotMatch(row.value, /^(true|false|on|off)$/i, row.label);
    }
  });
});

describe("absent values are unknown, never fabricated", () => {
  it("an unknown broker value renders as an em dash, not 0 or false", () => {
    const rows = settingsFields(initialState());
    for (const row of rows) {
      assert.notEqual(row.value, "0", row.label);
      assert.notEqual(row.value, "false", row.label);
    }
  });

  it("health-derived limits and the session TTLs are unknown without health/session", () => {
    const byLabel = new Map(settingsFields(initialState()).map((r) => [r.label, r.value]));
    assert.equal(byLabel.get("Idle auto-lock window"), "—");
    assert.equal(byLabel.get("Audit soft limit"), "—");
    assert.equal(byLabel.get("Audit hard limit"), "—");
    assert.equal(byLabel.get("Vault max size"), "—");
    assert.equal(byLabel.get("Session sliding TTL"), "—");
    assert.equal(byLabel.get("Broker fingerprint (pinned)"), "—");
    assert.equal(byLabel.get("Broker fingerprint (live probe)"), "—");
  });

  it("reported values are surfaced verbatim when present", () => {
    const byLabel = new Map(settingsFields(populated()).map((r) => [r.label, r.value]));
    assert.equal(byLabel.get("Wire protocol version"), "1");
    assert.equal(byLabel.get("Idle auto-lock window"), "15 min 0 s");
    assert.equal(byLabel.get("Audit soft limit"), "1.00 MiB");
    assert.equal(byLabel.get("Broker fingerprint (pinned)"), "a".repeat(64));
    assert.equal(byLabel.get("Broker fingerprint (live probe)"), "b".repeat(64));
  });
});

describe("trust is never writable from the dashboard", () => {
  it("the Trust writes row states CLI + TTY only", () => {
    const row = settingsFields(populated()).find((r) => r.label === "Trust writes");
    assert.ok(row);
    assert.match(row.value, /CLI \+ TTY/);
  });

  it("no field offers a dashboard-side trust write, reset or rotation", () => {
    const rows = settingsFields(populated());
    for (const row of rows) {
      // The identity rows legitimately READ fingerprint state; what must never
      // appear is a capability to change it. The Trust writes row is the one
      // that names the CLI/TTY ceremony precisely to declare it absent here.
      const language = /re-?pin|reset|rotate|rotation|change pin|write.{0,6}pin|set.{0,6}pin/i;
      assert.doesNotMatch(row.label, language, row.label);
      if (row.label === "Trust writes") continue;
      assert.doesNotMatch(row.value, language, row.label);
    }
    const trustRow = rows.find((r) => r.label === "Trust writes");
    assert.match(trustRow?.value ?? "", /not available here/);
    // Exactly the two read-only identity rows mention a fingerprint at all.
    const fpRows = rows.filter((r) => /fingerprint/i.test(r.label)).map((r) => r.label);
    assert.deepEqual(fpRows, ["Broker fingerprint (pinned)", "Broker fingerprint (live probe)"]);
  });

  it("the action allowlist is exactly the four real actions", () => {
    assert.deepEqual([...SETTINGS_ACTIONS], ["lock", "refresh", "verify_audit", "probe_fingerprint"]);
  });
});

describe("the invoke surface has no invented capability", () => {
  it("contains no trust, pin-write, reset or unmade-feature command", () => {
    for (const cmd of API_COMMANDS) {
      assert.doesNotMatch(cmd, FORBIDDEN, `forbidden command exposed: ${cmd}`);
    }
  });

  it("is exactly the thirty real commands", () => {
    assert.equal(API_COMMANDS.length, 30);
  });
});

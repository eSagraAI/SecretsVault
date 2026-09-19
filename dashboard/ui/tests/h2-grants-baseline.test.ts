// H2 regression: the grant editor's baseline must be the ACTIVE grant.
// The broker keeps a revoked row and appends a new active one on a re-grant, and
// `grants.list` returns the revoked row first — so a baseline taken from
// `grants.find(pair)` describes an authority the agent does not have, silently
// skips the widening confirmation, and hands the agent the revoked ops back.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import {
  activeGrantOps,
  applyGrants,
  grantRunRemoved,
  grantWidens,
  initialState,
  type GrantEntry,
} from "../state.js";

/** grant run,reveal,inject → revoke → grant read, as the broker reports it. */
const AFTER_REVOKE_THEN_REGRANT: GrantEntry[] = [
  { agent: "bot", project: "acme", ops: ["read", "inject", "run", "reveal"], revoked: true },
  { agent: "bot", project: "acme", ops: ["read"], revoked: false },
];

describe("H2: grant baselines come from active grants only", () => {
  it("reads the live grant, not the revoked row that the broker lists first", () => {
    const s = applyGrants(initialState(), AFTER_REVOKE_THEN_REGRANT);
    assert.deepEqual(activeGrantOps(s, "bot", "acme"), ["read"]);
  });

  it("saving the editor untouched stays exactly read and asks for no confirmation", () => {
    const s = applyGrants(initialState(), AFTER_REVOKE_THEN_REGRANT);
    const saved = activeGrantOps(s, "bot", "acme") ?? [];
    assert.deepEqual(saved, ["read"], "the pre-checked set is the live authority");
    assert.equal(grantWidens(saved, ["read"]), false, "no user change is not a widening");
  });

  it("any widening still requires the human confirmation", () => {
    const s = applyGrants(initialState(), AFTER_REVOKE_THEN_REGRANT);
    const saved = activeGrantOps(s, "bot", "acme") ?? [];
    assert.equal(grantWidens(saved, ["read", "inject"]), true);
    assert.equal(grantWidens(saved, ["read", "run"]), true);
    assert.equal(grantWidens(saved, ["read", "reveal"]), true);
  });

  it("only a LIVE run removal reports the run-termination consequence", () => {
    const withRun = applyGrants(initialState(), [
      { agent: "bot", project: "acme", ops: ["read"], revoked: true },
      { agent: "bot", project: "acme", ops: ["read", "run"], revoked: false },
    ]);
    const live = activeGrantOps(withRun, "bot", "acme") ?? [];
    assert.equal(grantRunRemoved(live, ["read"]), true, "dropping the live run is reported");

    const withoutLiveRun = applyGrants(initialState(), AFTER_REVOKE_THEN_REGRANT);
    const liveOps = activeGrantOps(withoutLiveRun, "bot", "acme") ?? [];
    assert.equal(
      grantRunRemoved(liveOps, ["read"]),
      false,
      "the revoked row's run is not an authority, so there is nothing to terminate",
    );
  });

  it("never invents a baseline for a pair with no active grant", () => {
    const s = applyGrants(initialState(), AFTER_REVOKE_THEN_REGRANT);
    assert.equal(activeGrantOps(s, "nobody", "acme"), null);
    assert.equal(activeGrantOps(s, "bot", "other"), null);
    assert.equal(activeGrantOps(initialState(), "bot", "acme"), null);
  });
});

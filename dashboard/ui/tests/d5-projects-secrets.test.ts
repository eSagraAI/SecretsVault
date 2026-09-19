// D5 projects+secrets: the secret-submit lifecycle invariant, honest
// secret counts, and revoked-grant exclusion. Pure functions only.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { takeSecretSubmit } from "../screens/secrets.js";
import {
  agentsWithAccess,
  applyGrants,
  applySecrets,
  initialState,
  loadedSecretCount,
} from "../state.js";

describe("takeSecretSubmit keeps nothing", () => {
  it("returns the secret_set args with kept always null", () => {
    assert.deepEqual(takeSecretSubmit("api-key", "s3cr3t"), {
      args: { key: "api-key", value: "s3cr3t" },
      kept: null,
    });
  });

  it("throws on an empty key or value instead of submitting", () => {
    assert.throws(() => takeSecretSubmit("", "s3cr3t"), /key and value/);
    assert.throws(() => takeSecretSubmit("api-key", ""), /key and value/);
  });
});

describe("loadedSecretCount honesty", () => {
  it("returns null when the loaded keys belong to a different project", () => {
    const s = applySecrets(initialState(), "web", [{ key: "a", updated: "t" }]);
    assert.equal(loadedSecretCount(s, "api"), null);
  });

  it("returns the count when the project matches", () => {
    const s = applySecrets(initialState(), "web", [
      { key: "a", updated: "t1" },
      { key: "b", updated: "t2" },
    ]);
    assert.equal(loadedSecretCount(s, "web"), 2);
  });
});

describe("agentsWithAccess honesty", () => {
  it("excludes revoked grants", () => {
    const s = applyGrants(initialState(), [
      { agent: "alice", project: "web", ops: ["read"], revoked: false },
      { agent: "mallory", project: "web", ops: ["manage"], revoked: true },
    ]);
    assert.deepEqual(agentsWithAccess(s, "web"), [{ agent: "alice", ops: ["read"] }]);
  });

  it("returns an empty array when grants are null", () => {
    assert.deepEqual(agentsWithAccess(initialState(), "web"), []);
  });
});

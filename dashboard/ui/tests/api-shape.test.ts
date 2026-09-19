// Structural pin on the invoke surface: exactly the frozen thirty commands,
// one wrapper each, and no generic passthrough. Asserts over the declared
// API_COMMANDS list and the module's exports — not a text grep.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import * as api from "../api.js";

describe("api surface", () => {
  it("exposes exactly the thirty frozen commands", () => {
    assert.deepEqual([...api.API_COMMANDS], [
      "get_status",
      "pin_status",
      "probe_fingerprint",
      "unlock",
      "lock",
      "health",
      "overview_refresh",
      "projects_list",
      "project_add",
      "project_remove",
      "project_path_add",
      "project_path_remove",
      "secrets_list",
      "secret_set",
      "secret_delete",
      "agents_list",
      "agent_add",
      "agent_revoke",
      "grants_list",
      "grant_set",
      "grant_revoke",
      "approvals_pending",
      "approval_approve",
      "approval_deny",
      "reveal",
      "leases_list",
      "lease_revoke",
      "runs_list",
      "audit_show",
      "audit_verify",
    ]);
  });
  it("has one wrapper function per command and no generic passthrough", () => {
    const { API_COMMANDS: _list, ...wrappers } = api;
    void _list;
    const names = Object.keys(wrappers).sort();
    const expected = [
      "agentAdd",
      "auditShow",
      "auditVerify",
      "agentRevoke",
      "agentsList",
      "approvalApprove",
      "approvalDeny",
      "approvalsPending",
      "getStatus",
      "grantRevoke",
      "grantSet",
      "grantsList",
      "health",
      "leaseRevoke",
      "leasesList",
      "lock",
      "overviewRefresh",
      "pinStatus",
      "probeFingerprint",
      "projectAdd",
      "projectPathAdd",
      "projectPathRemove",
      "projectRemove",
      "projectsList",
      "reveal",
      "runsList",
      "secretDelete",
      "secretSet",
      "secretsList",
      "unlock",
    ].sort();
    assert.deepEqual(names, expected);
    for (const fn of Object.values(wrappers)) assert.equal(typeof fn, "function");
    assert.equal("call" in api, false);
    assert.equal("invoke" in api, false);
    assert.equal("bridge" in api, false);
  });
});

// The ONLY invoke() callsite in the frontend: one function per command.
// No generic call(op, params) passthrough exists by design (confused-deputy hole).
// Invoked through the Tauri v2 internals bridge, so no @tauri-apps/api dependency.

import type {
  AgentAddResult,
  AgentEntry,
  ApprovalEntry,
  AuditEntry,
  BrokerStatus,
  GrantEntry,
  HealthResponse,
  LeaseEntry,
  OverviewData,
  PinStatus,
  ProjectEntry,
  RevealResult,
  RunEntry,
  SecretMeta,
  UnlockResponse,
} from "./state.js";

declare global {
  interface Window {
    __TAURI_INTERNALS__?: { invoke(cmd: string, args?: unknown): Promise<unknown> };
    __TAURI__?: { invoke(cmd: string, args?: unknown): Promise<unknown> };
  }
}

function bridge(): (cmd: string, args?: unknown) => Promise<unknown> {
  const b = window.__TAURI_INTERNALS__ ?? window.__TAURI__;
  if (!b || typeof b.invoke !== "function") {
    return () => Promise.reject({ code: "OFFLINE", message: "Tauri bridge unavailable (not running inside the app shell?)." });
  }
  return (cmd, args) => b.invoke(cmd, args);
}

function invoke<T>(cmd: ApiCommand, args?: Record<string, unknown>): Promise<T> {
  return bridge()(cmd, args ?? {}) as Promise<T>;
}

// The frozen thirty. Structural assertion in tests/api-shape.test.ts pins this list.
export const API_COMMANDS = [
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
] as const;

export type ApiCommand = (typeof API_COMMANDS)[number];

export function getStatus(): Promise<BrokerStatus> {
  return invoke<BrokerStatus>("get_status");
}

export function pinStatus(): Promise<PinStatus> {
  return invoke<PinStatus>("pin_status");
}

export function probeFingerprint(): Promise<{ fingerprint: string }> {
  return invoke<{ fingerprint: string }>("probe_fingerprint");
}

export function unlock(passphrase: string): Promise<UnlockResponse> {
  return invoke<UnlockResponse>("unlock", { passphrase });
}

export function lock(): Promise<{ locked: boolean }> {
  return invoke("lock");
}

export function health(): Promise<HealthResponse> {
  return invoke<HealthResponse>("health");
}

export function overviewRefresh(): Promise<OverviewData> {
  return invoke<OverviewData>("overview_refresh");
}

export function projectsList(): Promise<{ projects: ProjectEntry[] }> {
  return invoke<{ projects: ProjectEntry[] }>("projects_list");
}

export function projectAdd(name: string, paths: string[]): Promise<{ added: string }> {
  return invoke<{ added: string }>("project_add", { name, paths });
}

export function projectRemove(name: string): Promise<{ removed: string }> {
  return invoke<{ removed: string }>("project_remove", { name });
}

export function projectPathAdd(name: string, path: string): Promise<{ added: string }> {
  return invoke<{ added: string }>("project_path_add", { name, path });
}

export function projectPathRemove(name: string, path: string): Promise<{ removed: string }> {
  return invoke<{ removed: string }>("project_path_remove", { name, path });
}

export function secretsList(project: string): Promise<{ secrets: SecretMeta[] }> {
  return invoke<{ secrets: SecretMeta[] }>("secrets_list", { project });
}

export function secretSet(project: string, key: string, value: string): Promise<{ set: string }> {
  return invoke<{ set: string }>("secret_set", { project, key, value });
}

export function secretDelete(project: string, key: string): Promise<{ deleted: string }> {
  return invoke<{ deleted: string }>("secret_delete", { project, key });
}

export function agentsList(): Promise<{ agents: AgentEntry[] }> {
  return invoke<{ agents: AgentEntry[] }>("agents_list");
}

export function agentAdd(name: string, tokenPath?: string): Promise<AgentAddResult> {
  return invoke<AgentAddResult>("agent_add", tokenPath ? { name, tokenPath } : { name });
}

export function agentRevoke(name: string): Promise<{ revoked: string }> {
  return invoke<{ revoked: string }>("agent_revoke", { name });
}

export function grantsList(): Promise<{ grants: GrantEntry[] }> {
  return invoke<{ grants: GrantEntry[] }>("grants_list");
}

/**
 * The wire asymmetry lives HERE, not in the screens: `grant_set` sends
 * `ops` as a COMMA-SEPARATED STRING ("read,inject") while `grants_list`
 * returns it as an array of lowercase strings.
 */
export function grantSet(agent: string, project: string, ops: string[]): Promise<{ granted: string }> {
  return invoke<{ granted: string }>("grant_set", { agent, project, ops: ops.join(",") });
}

export function grantRevoke(agent: string, project: string): Promise<{ revoked: string }> {
  return invoke<{ revoked: string }>("grant_revoke", { agent, project });
}

export function approvalsPending(): Promise<{ approvals: ApprovalEntry[] }> {
  return invoke<{ approvals: ApprovalEntry[] }>("approvals_pending");
}

export function approvalApprove(approvalId: string): Promise<{ approval_id: string; status: string }> {
  return invoke<{ approval_id: string; status: string }>("approval_approve", { approvalId });
}

export function approvalDeny(approvalId: string): Promise<{ approval_id: string; status: string }> {
  return invoke<{ approval_id: string; status: string }>("approval_deny", { approvalId });
}

export function reveal(project: string, key: string): Promise<RevealResult> {
  return invoke<RevealResult>("reveal", { project, key });
}

export function leasesList(): Promise<{ leases: LeaseEntry[] }> {
  return invoke<{ leases: LeaseEntry[] }>("leases_list");
}

export function leaseRevoke(leaseId: string): Promise<{ lease_id: string; revoked: boolean }> {
  return invoke<{ lease_id: string; revoked: boolean }>("lease_revoke", { leaseId });
}

export function runsList(): Promise<{ runs: RunEntry[] }> {
  return invoke<{ runs: RunEntry[] }>("runs_list");
}

/**
 * One bounded audit page over the real cursor. `tail` is the page size; the
 * broker validates it against 1..=1000 and the backend refuses anything out of
 * range before opening a connection. `beforeSeq` is the previous page's
 * `next_before_seq` — omitted entirely (never sent as null) so the broker sees
 * an absent key and returns the NEWEST page.
 *
 * Every call appends one entry to the log being read: callers MUST NOT poll
 * this.
 */
export function auditShow(
  tail: number,
  beforeSeq?: number,
): Promise<{ entries: AuditEntry[]; next_before_seq?: number | null }> {
  return invoke<{ entries: AuditEntry[]; next_before_seq?: number | null }>(
    "audit_show",
    beforeSeq === undefined ? { tail } : { tail, beforeSeq },
  );
}

/**
 * Walk the on-disk audit chain. Mutates nothing; a structural/HMAC/checkpoint
 * failure arrives as an `E_VAULT_CORRUPT` error, never as a zeroed success.
 */
export function auditVerify(): Promise<{ entries: number; macs_verified: number; macs_null: number }> {
  return invoke<{ entries: number; macs_verified: number; macs_null: number }>("audit_verify");
}

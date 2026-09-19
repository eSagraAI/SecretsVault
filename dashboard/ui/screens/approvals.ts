// Approvals: the HITL inbox over `approvals_pending` / `approval_approve` /
// `approval_deny`. Rows show agent, project, key (a secret NAME — safe),
// status, expiry, and a countdown derived from `expires_at` vs now,
// recomputed on render (honest: expired reads "expired", never negative).
// After approve/deny the list is re-read — rows are never removed
// optimistically. Never auto-approves anything.
//
// The dashboard does NOT claim, display or request the secret value:
// approving allows the agent to claim the value once; the value itself is
// never shown here.

import {
  banner,
  button,
  card,
  el,
  emptyState,
  errorState,
  fieldGrid,
  loadingState,
  pageHeader,
  pill,
  section,
} from "../components.js";
import { approvalCountdown, errorAdvice } from "../state.js";
import type { ApprovalEntry, MappedError, ShellState } from "../state.js";

export interface ApprovalsActions {
  busyAction: string | null;
  onApprove: (id: string) => void;
  onDeny: (id: string) => void;
  onReload: () => void;
  inlineError: MappedError | null;
  /** Decided ids (terminal, from the approve/deny response) with their status. */
  decided: ReadonlyMap<string, string>;
  /**
   * After a reveal approval is approved, navigate to the Secrets screen and
   * open the masked reveal modal for (project, key). Navigation only — it
   * NEVER claims anything: the claim belongs to the requesting agent, and the
   * dashboard never performs it. The human's own reveal is a separate, direct
   * owner action that needs no approval. Never carries the value.
   */
  onReturnToReveal?: (project: string, key: string) => void;
}

function terminalPill(status: string): HTMLElement {
  const lower = status.toLowerCase();
  if (lower === "approved") return pill(status, "ok");
  if (lower === "denied") return pill(status, "bad");
  return pill(status, "warn");
}

function pendingCard(e: ApprovalEntry, a: ApprovalsActions, nowMs: number): HTMLElement {
  const cd = approvalCountdown(e.expires_at, nowMs);
  const c = card(`${e.agent} → ${e.project} / ${e.key}`, {
    subtitle: `Approval ${e.approval_id}`,
    tone: cd.expired ? "bad" : "warn",
    actions: [pill(e.status || "pending", "warn")],
  });
  c.body.append(
    fieldGrid([
      ["Agent", e.agent],
      ["Project", e.project],
      ["Key", e.key],
      ["Remaining", cd.expired ? "expired" : cd.label],
    ]),
  );
  const expiry = el("p", { class: cd.expired ? "expiry expiry-done" : "expiry" }, e.expires_at ? `${cd.label} (${e.expires_at})` : cd.label);
  c.body.append(expiry);
  const busy = a.busyAction === "approval_approve" || a.busyAction === "approval_deny";
  c.footer.append(
    button(busy ? "Working…" : "Approve", {
      variant: "primary",
      disabled: busy,
      onClick: () => a.onApprove(e.approval_id),
    }),
    button(busy ? "Working…" : "Deny", {
      variant: "danger",
      disabled: busy,
      onClick: () => a.onDeny(e.approval_id),
    }),
  );
  return c.root;
}

function decidedCard(e: ApprovalEntry, decided: string, a: ApprovalsActions, nowMs: number): HTMLElement {
  const c = card(`${e.agent} → ${e.project} / ${e.key}`, {
    subtitle: `Approval ${e.approval_id} — decided`,
    actions: [terminalPill(decided)],
  });
  const cd = approvalCountdown(e.expires_at, nowMs);
  c.body.append(
    fieldGrid([
      ["Agent", e.agent],
      ["Project", e.project],
      ["Key", e.key],
      ["Outcome", decided],
      ["Remaining", cd.expired ? "expired" : cd.label],
    ]),
  );
  // Return-to-reveal is NAVIGATION ONLY: after THIS entry was approved, an
  // explicit click switches to the Secrets screen and opens the masked modal.
  // No claim is performed here or there on the agent's behalf — the claim
  // belongs to the requesting agent. The human's own direct reveal is a
  // different action and needs no approval. The value is never shown here.
  if (decided.toLowerCase() === "approved" && a.onReturnToReveal) {
    c.footer.append(button("Go to Secrets", { onClick: () => a.onReturnToReveal?.(e.project, e.key) }));
  }
  return c.root;
}

export function renderApprovals(root: HTMLElement, s: ShellState, a: ApprovalsActions): void {
  root.replaceChildren();
  const reloading = a.busyAction === "approvals_pending";
  const wrap = el("div", { class: "page" });
  wrap.append(
    pageHeader("Approvals", {
      subtitle: "Human-in-the-loop inbox — pending requests first.",
      actions: [
        button(reloading ? "Loading…" : "Reload", {
          disabled: a.busyAction !== null,
          onClick: () => a.onReload(),
        }),
      ],
    }),
  );

  wrap.append(
    banner(
      "info",
      "Approving allows the agent to claim the value once — the value itself is never shown here. Nothing is ever auto-approved.",
    ),
  );
  if (s.sessionExpired) {
    wrap.append(banner("warn", "Your session expired — unlock again before deciding approvals."));
  }
  if (a.inlineError) {
    wrap.append(
      errorState(a.inlineError.message, errorAdvice(a.inlineError.code) ?? "", {
        code: a.inlineError.code,
        retry: [button("Reload", { disabled: a.busyAction !== null, onClick: () => a.onReload() })],
      }),
    );
  }

  const list = s.approvals;
  if (list === null) {
    if (reloading) {
      wrap.append(loadingState("Loading approvals…"));
    } else {
      wrap.append(
        emptyState("Approvals not loaded", "Pending approvals are not loaded yet — press Reload.", {
          icon: "approvals",
          actions: [button("Reload", { disabled: a.busyAction !== null, onClick: () => a.onReload() })],
        }),
      );
    }
    root.append(wrap);
    return;
  }
  if (list.length === 0) {
    wrap.append(
      emptyState(
        a.decided.size > 0 ? "Inbox empty" : "Nothing pending",
        a.decided.size > 0
          ? "Every listed entry was decided and the broker reports nothing pending — press Reload to check for new requests."
          : "The broker reports no approvals awaiting a decision — press Reload to check again.",
        { icon: "approvals" },
      ),
    );
    root.append(wrap);
    return;
  }
  const nowMs = Date.now();
  const pending: ApprovalEntry[] = [];
  const terminal: Array<{ e: ApprovalEntry; decided: string }> = [];
  for (const e of list) {
    const decided = a.decided.get(e.approval_id);
    if (decided !== undefined) terminal.push({ e, decided });
    else pending.push(e);
  }
  if (pending.length > 0) {
    const sec = section("Pending", { subtitle: `${pending.length} awaiting a decision — approve or deny below.` });
    for (const e of pending) sec.body.append(pendingCard(e, a, nowMs));
    wrap.append(sec.root);
  } else {
    wrap.append(
      emptyState("Inbox empty", "Every listed entry was decided and the broker reports nothing pending — press Reload to check for new requests.", { icon: "approvals" }),
    );
  }
  if (terminal.length > 0) {
    const sec = section("Decided", { subtitle: "Terminal entries, kept separate and muted — no further decision needed." });
    for (const { e, decided } of terminal) sec.body.append(decidedCard(e, decided, a, nowMs));
    wrap.append(sec.root);
  }
  root.append(wrap);
}

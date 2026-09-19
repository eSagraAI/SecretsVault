// Leases: read + revoke over `leases_list` / `lease_revoke`. No optimistic
// UI: after a revoke the list is re-read before render. The wire carries no
// agent identity (project + lease_prefix + ops + status + expiry only), so
// none is shown — and no credential material: the prefix is public identity.
// Lease creation is agent-only at the wire and has no form here.

import {
  badge,
  banner,
  button,
  chipList,
  confirmBar,
  el,
  emptyState,
  errorState,
  iconTextButton,
  loadingState,
  pageHeader,
  table,
} from "../components.js";
import {
  approvalCountdown,
  errorAdvice,
  leaseStatusTone,
  type LeaseEntry,
  type MappedError,
  type PendingConfirm,
  type ShellState,
} from "../state.js";

export interface LeasesActions {
  busyAction: string | null;
  pendingConfirm: PendingConfirm | null;
  onRevoke: (leaseId: string) => void;
  onCancelConfirm: () => void;
  onReload: () => void;
  inlineError: MappedError | null;
}

export function renderLeases(root: HTMLElement, s: ShellState, a: LeasesActions): void {
  root.replaceChildren();
  const busy = a.busyAction !== null;
  root.append(
    pageHeader("Leases", {
      actions: [
        iconTextButton("refresh", a.busyAction === "leases_list" ? "Loading…" : "Reload", {
          disabled: busy,
          onClick: () => a.onReload(),
        }),
      ],
    }),
  );

  if (s.sessionExpired) {
    root.append(banner("warn", "Your session expired — unlock again before managing leases."));
  }
  if (a.inlineError) {
    root.append(
      errorState(a.inlineError.message, errorAdvice(a.inlineError.code) ?? "", {
        code: a.inlineError.code,
        retry: [button("Reload", { disabled: busy, onClick: () => a.onReload() })],
      }),
    );
  }
  root.append(
    banner(
      "info",
      "Lease creation is not available in this dashboard milestone — the broker requires agent credentials for lease.create. This screen lists live leases and supports revoke.",
    ),
  );

  const list = s.leases;
  if (list === null) {
    if (a.busyAction === "leases_list") {
      root.append(loadingState("Loading leases…"));
    } else {
      root.append(
        emptyState("Leases not loaded", "Live leases are not loaded yet — press Reload.", {
          icon: "leases",
          actions: [button("Reload", { disabled: busy, onClick: () => a.onReload() })],
        }),
      );
    }
    return;
  }
  if (list.length === 0) {
    root.append(
      emptyState("No leases", "No leases — the broker reports none. Press Reload to check again.", { icon: "leases" }),
    );
    return;
  }
  root.append(leasesTable(list, a));
}

function leasesTable(list: LeaseEntry[], a: LeasesActions): HTMLElement {
  const nowMs = Date.now();
  const rows: HTMLElement[][] = list.map((e) => {
    const prefix = el("span", { class: "mono" }, e.lease_prefix);
    const project = el("span", {}, e.project);
    const ops = chipList(
      e.ops.map((op) => ({ text: op })),
      { empty: "—" },
    );
    const cd = approvalCountdown(e.expires_at, nowMs);
    const ttl = el("span", { class: cd.expired ? "expiry expiry-done" : "expiry" }, cd.label);
    const status = badge(e.status || "unknown", leaseStatusTone(e.status));
    const acts = el("div", { class: "table-actions" });
    const c = a.pendingConfirm;
    if (c && c.kind === "lease" && c.project === e.lease_id) {
      acts.append(
        confirmBar(`Revoke lease ${e.lease_prefix}?`, {
          onConfirm: () => a.onRevoke(e.lease_id),
          onCancel: () => a.onCancelConfirm(),
          busy: a.busyAction === "lease_revoke",
          confirmLabel: a.busyAction === "lease_revoke" ? "Revoking…" : "Confirm revoke",
          danger: true,
        }),
      );
    } else {
      acts.append(
        button("Revoke…", {
          disabled: a.busyAction !== null,
          onClick: () => a.onRevoke(e.lease_id),
        }),
      );
    }
    return [prefix, project, ops, ttl, status, acts];
  });
  return table(["Prefix", "Project", "Ops", "TTL remaining", "Status", "Actions"], rows, {
    dense: true,
    label: "Leases",
  });
}

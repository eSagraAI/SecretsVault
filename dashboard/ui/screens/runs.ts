// Runs: read-only over `runs_list` (one-shot load on route enter plus
// manual Refresh — never polled). No process detail is shown: run id,
// agent, project, pid, start time and status only — never argv/env/cwd.
// Stopping runs is agent-only at the wire and has no button here.

import {
  badge,
  banner,
  button,
  el,
  emptyState,
  errorState,
  iconTextButton,
  loadingState,
  pageHeader,
  table,
} from "../components.js";
import { errorAdvice, fmtRelative, runStatusTone, type MappedError, type RunEntry, type ShellState } from "../state.js";

export interface RunsActions {
  busyAction: string | null;
  onReload: () => void;
  inlineError: MappedError | null;
}

export function renderRuns(root: HTMLElement, s: ShellState, a: RunsActions): void {
  root.replaceChildren();
  const busy = a.busyAction !== null;
  root.append(
    pageHeader("Runs", {
      actions: [
        iconTextButton("refresh", a.busyAction === "runs_list" ? "Loading…" : "Refresh", {
          disabled: busy,
          onClick: () => a.onReload(),
        }),
      ],
    }),
  );

  if (s.sessionExpired) {
    root.append(banner("warn", "Your session expired — unlock again before viewing runs."));
  }
  if (a.inlineError) {
    root.append(
      errorState(a.inlineError.message, errorAdvice(a.inlineError.code) ?? "", {
        code: a.inlineError.code,
        retry: [button("Refresh", { disabled: busy, onClick: () => a.onReload() })],
      }),
    );
  }
  root.append(
    banner(
      "warn",
      "run_with_secrets is not a sandbox — the child process runs with the secrets in its environment and could have exfiltrated them before any stop. The dashboard does not stop runs in this milestone — the broker requires agent credentials for run_signal.",
    ),
  );

  const list = s.runs;
  if (list === null) {
    if (a.busyAction === "runs_list") {
      root.append(loadingState("Loading runs…"));
    } else {
      root.append(
        emptyState("Runs not loaded", "Live runs are not loaded yet — press Refresh.", {
          icon: "runs",
          actions: [button("Refresh", { disabled: busy, onClick: () => a.onReload() })],
        }),
      );
    }
    return;
  }
  if (list.length === 0) {
    root.append(
      emptyState("No runs", "No runs — the broker reports none. Press Refresh to check again.", { icon: "runs" }),
    );
    return;
  }
  root.append(runsTable(list));
}

function runsTable(list: RunEntry[]): HTMLElement {
  const nowMs = Date.now();
  const rows: HTMLElement[][] = list.map((e) => {
    const startedAttrs: Record<string, string> = {};
    if (e.started_at) startedAttrs["title"] = e.started_at;
    const started = el("span", startedAttrs, fmtRelative(e.started_at, nowMs));
    return [
      el("span", { class: "mono" }, e.run_id),
      el("span", {}, e.agent),
      el("span", {}, e.project),
      el("span", {}, String(e.pid)),
      started,
      badge(e.status || "unknown", runStatusTone(e.status)),
    ];
  });
  return table(
    ["Run", "Agent", "Project", { label: "PID", numeric: true }, "Started", "Status"],
    rows,
    { dense: true, label: "Runs" },
  );
}

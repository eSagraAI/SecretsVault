// Settings: the operational picture plus the read-only configuration surface.
// Two rules govern this screen, and both are spec requirements rather than
// taste:
//
//  1. Only real observed values are shown. A field the broker did not report
//     renders "—", never a fabricated 0/false, and a bar is drawn only when
//     BOTH the observed value and its limit are real. A healthy broker nearing
//     a limit stays healthy: limit and session pressure render as warnings,
//     never as errors, because the connection posture owns
//     offline/untrusted/mismatch and nothing here may contradict it.
//
//  2. Nothing here is editable. The core supports no theme, autostart, tray,
//     sync, providers, telemetry, cloud, keychain or updater, and trust is
//     deliberately CLI+TTY only — so there is no such control, and every
//     configuration row is marked read-only at the row level so a reported
//     value can never be mistaken for a disabled switch. The only actions are
//     the four that really exist.

import {
  banner,
  card,
  chip,
  codeBlock,
  el,
  emptyState,
  errorState,
  fieldGrid,
  iconTextButton,
  loadingState,
  meter,
  pageHeader,
  para,
  pill,
  section,
  stat,
  stats,
  toolbar,
} from "../components.js";
import {
  errorAdvice,
  fmtBytes,
  fmtDuration,
  fmtRelative,
  healthWarnings,
  sessionHeld,
  sessionText,
  type MappedError,
  type SettingsField,
  type ShellState,
} from "../state.js";

export interface SettingsActions {
  busyAction: string | null;
  onRefresh: () => void;
  onLock: () => void;
  onVerifyAudit: () => void;
  onProbe: () => void;
  inlineError: MappedError | null;
}

/** The complete, pinned action allowlist: four real operations, nothing else. */
export const SETTINGS_ACTIONS = ["lock", "refresh", "verify_audit", "probe_fingerprint"] as const;

/** Trust as the connection posture sees it. `boot` never reaches this screen. */
function trustLabel(conn: ShellState["conn"]): { label: string; tone: "ok" | "warn" | "bad" | "mute" } {
  switch (conn) {
    case "trusted":
      return { label: "trusted", tone: "ok" };
    case "untrusted":
      return { label: "untrusted — no pin for this socket", tone: "warn" };
    case "mismatch":
      return { label: "pin mismatch — broker identity changed", tone: "bad" };
    case "offline":
      return { label: "offline — daemon unreachable", tone: "bad" };
    default:
      return { label: "unknown", tone: "mute" };
  }
}

const READ_ONLY_NOTE = "not available here — first trust and pin reset are CLI + TTY only";

/**
 * The complete configuration surface, pinned by test. Every value is a
 * reported fact: an unknown value is "—", and no value is a Boolean-style
 * switch state. Adding a setting the core does not support breaks the test
 * rather than shipping silently.
 */
export function settingsFields(s: ShellState): SettingsField[] {
  const h = s.health;
  const created = s.status?.created;
  const row = (label: string, value: string): SettingsField => ({
    label,
    value: value.length > 0 ? value : "—",
    readonly: true,
  });
  const secs = (n: number | undefined): string => (typeof n === "number" ? fmtDuration(n) : "—");
  return [
    row("Wire protocol version", typeof s.status?.version === "number" ? String(s.status.version) : "—"),
    row("Vault created", typeof created === "string" ? created : "—"),
    row("Idle auto-lock window", h === null ? "—" : fmtDuration(h.idle_lock_secs)),
    row("Session sliding TTL", secs(s.session.expiresIn)),
    row("Session absolute ceiling", secs(s.session.maxExpiresIn)),
    row("Audit soft limit", h === null ? "—" : fmtBytes(h.audit_soft_limit)),
    row("Audit hard limit", h === null ? "—" : fmtBytes(h.audit_hard_limit)),
    row("Vault max size", h === null ? "—" : fmtBytes(h.vault_max_bytes)),
    row("Broker fingerprint (pinned)", s.pin?.fingerprint ?? "—"),
    row("Broker fingerprint (live probe)", s.settings.probedFingerprint ?? "—"),
    row("Trust writes", READ_ONLY_NOTE),
  ];
}
function healthSection(s: ShellState, nowMs: number, busyAction: string | null): HTMLElement {
  const sec = section("Health", {
    subtitle: "What the broker actually reports, right now. Nothing here is a verdict it did not send.",
  });
  const trust = trustLabel(s.conn);
  const h = s.health;

  sec.body.append(
    fieldGrid([
      ["Broker", pill(trust.label, trust.tone)],
      ["Vault", s.status === null ? "—" : s.status.locked ? pill("locked", "warn") : pill("unlocked", "ok")],
      [
        "Human session",
        s.status === null || s.status.locked
          ? "—"
          : pill(sessionHeld(s) ? "held" : "not held", sessionHeld(s) ? "ok" : "warn"),
      ],
    ]),
  );
  if (s.status !== null && !s.status.locked) {
    sec.body.append(para(sessionText(s.session, nowMs, s.unlockedAtMs), "muted"));
  }

  const refreshing = busyAction === "settings_refresh";
  if (refreshing && h === null) {
    sec.body.append(loadingState("Reading broker health…"));
    return sec.root;
  }
  if (h === null) {
    sec.body.append(
      emptyState("Health not read yet", "The broker has not reported health yet — press Reload to read it.", {
        icon: "refresh",
      }),
    );
    return sec.root;
  }

  const unknown = (v: number | null): string => (v === null ? "—" : String(v));
  sec.body.append(
    stats([
      stat("Active runs", String(h.runs_active)),
      stat("Active leases", unknown(h.leases_active)),
      stat("Pending approvals", unknown(h.approvals_pending)),
      stat("Idle lock remaining", h.idle_in === null ? "—" : fmtDuration(h.idle_in)),
    ]),
  );
  sec.body.append(
    fieldGrid([
      ["Idle auto-lock window", fmtDuration(h.idle_lock_secs)],
      [
        "Audit log",
        `${fmtBytes(h.audit_bytes)} of ${fmtBytes(h.audit_soft_limit)} (soft) / ${fmtBytes(h.audit_hard_limit)} (hard)`,
      ],
      ["Vault file", `${fmtBytes(h.vault_bytes)} of ${fmtBytes(h.vault_max_bytes)}`],
    ]),
  );
  // Bars appear only where both the observed value and its limit are real;
  // `meter` renders an untoned, empty bar otherwise.
  sec.body.append(meter("Audit log vs hard limit", h.audit_bytes, h.audit_hard_limit));
  sec.body.append(meter("Vault file vs max size", h.vault_bytes, h.vault_max_bytes));

  const warnings = healthWarnings(s, nowMs);
  if (warnings.length > 0) {
    const w = section("Warnings", { subtitle: "Pressure on a healthy broker — nothing here is a failure." });
    for (const item of warnings) {
      const c = card(item.title, { tone: item.tone });
      c.body.append(para(item.detail));
      w.body.append(c.root);
    }
    sec.body.append(w.root);
  }
  return sec.root;
}

function trustSection(s: ShellState, a: SettingsActions, nowMs: number): HTMLElement {
  const sec = section("Trust", {
    subtitle: "Broker identity: what this app pins, and what the broker presents live.",
  });
  const trust = trustLabel(s.conn);
  sec.body.append(fieldGrid([["Trust state", pill(trust.label, trust.tone)]]));

  sec.body.append(para("Pinned fingerprint (what this app trusts):", "lbl"));
  if (s.pin?.fingerprint) sec.body.append(codeBlock(s.pin.fingerprint));
  else sec.body.append(para("No pin exists for this socket.", "muted"));

  sec.body.append(para("Live fingerprint (probed just now, credential-free):", "lbl"));
  if (a.busyAction === "probe_fingerprint" && !s.settings.probedFingerprint) {
    sec.body.append(loadingState("Probing live fingerprint…"));
  } else if (s.settings.probedFingerprint) {
    sec.body.append(codeBlock(s.settings.probedFingerprint));
    sec.body.append(para(`Probed ${fmtRelative(new Date(s.settings.probedAtMs).toISOString(), nowMs)}.`, "muted"));
  } else {
    sec.body.append(para("Not probed yet — press Probe live fingerprint to compare.", "muted"));
  }

  sec.body.append(
    iconTextButton("search", a.busyAction === "probe_fingerprint" ? "Probing…" : "Probe live fingerprint", {
      disabled: a.busyAction !== null,
      onClick: () => a.onProbe(),
    }),
    banner(
      "info",
      "The dashboard never writes, resets or rotates a trust pin. First trust and any pin reset or " +
        "rotation happen at a TTY through the CLI — there is no trust or re-pin control on this screen " +
        "and none will be added.",
    ),
  );
  return sec.root;
}

function configSection(s: ShellState): HTMLElement {
  const sec = section("Configuration", {
    subtitle: "Broker-reported and compile-time values. None of these is editable from the dashboard.",
  });
  for (const row of settingsFields(s)) {
    const line = el("div", { class: "field" });
    line.append(el("span", { class: "field-label" }, row.label));
    const value = el("span", { class: "field-value mono" }, row.value);
    line.append(value, chip("read-only", { tone: "mute" }));
    sec.body.append(line);
  }
  sec.body.append(
    para(
      "The wire protocol version is the broker envelope version, not an application build.",
      "muted",
    ),
  );
  return sec.root;
}

function actionsSection(a: SettingsActions, canLock: boolean): HTMLElement {
  const sec = section("Actions", { subtitle: "Every action here performs a real operation." });
  const busy = a.busyAction !== null;
  sec.body.append(
    toolbar([
      iconTextButton("lock", "Lock", { variant: "danger", disabled: !canLock, onClick: () => a.onLock() }),
      iconTextButton("refresh", a.busyAction === "settings_refresh" ? "Refreshing…" : "Reload", {
        disabled: busy,
        onClick: () => a.onRefresh(),
      }),
      iconTextButton("check", a.busyAction === "audit_verify" ? "Verifying…" : "Verify audit", {
        disabled: busy,
        onClick: () => a.onVerifyAudit(),
      }),
      iconTextButton("search", a.busyAction === "probe_fingerprint" ? "Probing…" : "Probe live fingerprint", {
        disabled: busy,
        onClick: () => a.onProbe(),
      }),
    ]),
  );
  return sec.root;
}

export function renderSettings(root: HTMLElement, s: ShellState, a: SettingsActions): void {
  root.replaceChildren();
  const nowMs = Date.now();
  const busy = a.busyAction !== null;
  root.append(
    pageHeader("Settings", {
      subtitle: "Operational health and read-only configuration — nothing on this screen is editable.",
      actions: [
        iconTextButton("refresh", a.busyAction === "settings_refresh" ? "Refreshing…" : "Reload", {
          disabled: busy,
          onClick: () => a.onRefresh(),
        }),
        iconTextButton("lock", "Lock", {
          variant: "danger",
          disabled: busy || s.conn !== "trusted" || s.status === null || s.status.locked,
          onClick: () => a.onLock(),
        }),
      ],
    }),
  );

  if (s.sessionExpired) {
    root.append(banner("warn", "Your session expired — unlock again before using the privileged actions."));
  }
  // While the posture is already offline, the offline banner below is the ONE
  // rendering of this failure. The transport error that produced the offline
  // posture (a dead daemon's `E_IO`, or the absent bridge's `OFFLINE`) would
  // otherwise paint a full error-state card saying the same thing in different
  // words — observed in D7 as "Tauri bridge unavailable" stacked directly
  // above the offline banner. Offline is not a separate fault to report twice.
  if (a.inlineError !== null && s.conn !== "offline") {
    root.append(
      errorState(a.inlineError.message, errorAdvice(a.inlineError.code) ?? "", { code: a.inlineError.code }),
    );
  }
  if (s.conn === "offline") {
    root.append(
      banner(
        "warn",
        "Broker offline — the operational health fields are unavailable. Read-only configuration and " +
          "fingerprint state are still shown.",
      ),
    );
  }

  root.append(healthSection(s, nowMs, a.busyAction));
  root.append(trustSection(s, a, nowMs));
  root.append(configSection(s));
  const canLock = s.conn === "trusted" && s.status !== null && !s.status.locked;
  root.append(actionsSection(a, canLock));
}

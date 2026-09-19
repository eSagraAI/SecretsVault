// Untrusted (no-pin) blocked panel + mismatch screen + unlock gate.
// Security contract: the dashboard NEVER writes a trust pin. First trust
// happens at a TTY with the real CLI; probe_fingerprint is display only.
// The passphrase lives only in the input element for the duration of one
// submit; it is never stored in state, URL, or storage.

import { banner, button, codeBlock, el, errorState, iconTextButton, para } from "../components.js";
import { errorAdvice, type MappedError, type ShellState } from "../state.js";

export interface UntrustedActions {
  onProbe: () => void;
  onRefresh: () => void;
  busy: boolean;
  probed: string | null;
  probeError: string | null;
}

export function renderUntrusted(root: HTMLElement, a: UntrustedActions): void {
  root.replaceChildren();
  const wrap = el("div", { class: "gate" });
  const cardEl = el("div", { class: "gate-card" });
  cardEl.append(el("h2", {}, "First trust must be made from the CLI"));
  cardEl.append(
    banner(
      "warn",
      "Blocked: this dashboard has no trust pin for the broker. Unlock and all sensitive operations are disabled.",
    ),
    para(
      "The dashboard cannot and will not establish trust. To establish first trust, use a terminal on " +
        "this machine: run `svault trust show` to read the broker fingerprint, compare it with the " +
        "fingerprint shown below, then run any interactive `svault` command and answer the confirmation " +
        "prompt to pin it. Then press Refresh below.",
    ),
    iconTextButton(
      "search",
      a.busy ? "Probing…" : a.probed ? "Probe again" : "Show broker fingerprint",
      { disabled: a.busy, onClick: () => a.onProbe() },
    ),
  );
  if (a.probeError) {
    const code = /^([A-Z][A-Z0-9_]*):/.exec(a.probeError)?.[1];
    const advice = code ? errorAdvice(code) : null;
    cardEl.append(banner("warn", advice ? `${a.probeError} ${advice}` : a.probeError));
  }
  if (a.probed) {
    cardEl.append(para("Broker fingerprint (display only — comparing it here does not establish trust):"));
    cardEl.append(codeBlock(a.probed));
  }
  cardEl.append(para("No passphrase is accepted or sent while untrusted."));
  cardEl.append(
    iconTextButton(
      "refresh",
      a.busy ? "Refreshing…" : "Refresh (re-check for a CLI-made pin)",
      { variant: "primary", disabled: a.busy, onClick: () => a.onRefresh() },
    ),
  );
  wrap.append(cardEl);
  root.append(wrap);
}

export function renderMismatch(root: HTMLElement, s: ShellState): void {
  root.replaceChildren();
  const wrap = el("div", { class: "gate" });
  const cardEl = el("div", { class: "gate-card" });
  cardEl.append(el("h2", {}, "Broker identity mismatch"));
  cardEl.append(
    banner(
      "alarm",
      "SECURITY: the broker's identity has changed. This app's pinned fingerprint no longer matches " +
        "what the broker presents. The app refuses to trust it.",
    ),
    para(
      "Do not proceed. No passphrase will be sent while this screen is shown. There is no re-pin " +
        "button here and none will be added: rotation or reset stays CLI+TTY only. Investigate on " +
        "the broker host (was the broker reinstalled, its identity regenerated, or is something " +
        "intercepting the connection?).",
    ),
  );
  const pinned = s.pin?.fingerprint;
  if (pinned) {
    cardEl.append(para("Pinned fingerprint (what this app trusts):"));
    cardEl.append(codeBlock(pinned));
  }
  wrap.append(cardEl);
  root.append(wrap);
}

export interface UnlockActions {
  onUnlock: (getPassphrase: () => string, clear: () => void) => void;
  busy: boolean;
  failure: string | null;
  /**
   * Which of the two distinct causes put the gate up. They need different
   * words because they are different facts: `locked` means the vault itself
   * is locked (the chrome's lock pill agrees), while `session-expired` means
   * the vault is still unlocked broker-side but this app holds no usable
   * human session, so privileged reads are refused until the human proves
   * themselves again. Saying "Vault is locked" in the second case would
   * contradict the lock pill right above it.
   */
  reason: "locked" | "session-expired";
}

export function renderUnlockGate(root: HTMLElement, a: UnlockActions): void {
  root.replaceChildren();
  const wrap = el("div", { class: "gate" });
  const form = el("form", { class: "gate-card", autocomplete: "off" });
  const expired = a.reason === "session-expired";
  form.append(el("h2", {}, expired ? "No usable human session" : "Vault is locked"));
  form.append(
    para(
      expired
        ? "The vault is still unlocked, but this app holds no usable human session, so closing " +
            "this window will not lock the vault. Enter the vault passphrase to start a new session " +
            "(it is sent to the broker once; this app does not keep it), or run `svault lock` in a terminal."
        : "Enter the vault passphrase to unlock. It is sent to the broker once; this app does not keep it.",
    ),
  );
  if (a.failure) form.append(banner("warn", a.failure));
  form.append(el("label", { class: "field-label", for: "unlock-pass" }, "Passphrase"));
  const input = el("input", {
    id: "unlock-pass",
    class: "input",
    type: "password",
    autocomplete: "current-password",
    placeholder: "Passphrase",
  }) as HTMLInputElement;
  form.append(
    input,
    button(a.busy ? "Unlocking…" : "Unlock", {
      variant: "primary",
      type: "submit",
      disabled: a.busy,
    }),
  );
  if (a.busy) input.disabled = true;
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    a.onUnlock(
      () => input.value,
      () => {
        input.value = "";
      },
    );
  });
  wrap.append(form);
  root.append(wrap);
}

export function renderNoVault(
  root: HTMLElement,
  a: { busy: boolean; inlineError: MappedError | null; onRefresh: () => void },
): void {
  root.replaceChildren();
  const wrap = el("div", { class: "gate" });
  const cardEl = el("div", { class: "gate-card" });
  cardEl.append(el("h2", {}, "Broker reachable, identity verified — no vault exists yet"));
  cardEl.append(
    banner("info", "No vault exists yet on this broker."),
    para(
      "The broker is reachable and its identity is verified against this app's trust pin, " +
        "but no vault has been created on it yet.",
    ),
    para(
      "A vault can only be created at a terminal. In a terminal on this machine, against the same " +
        "socket/daemon, run:",
    ),
    codeBlock("svault init"),
    para(
      "This app cannot create a vault and accepts no passphrase here — vault creation happens only " +
        "through that terminal command.",
    ),
    para("This is not an offline error: the broker answered. Nothing is wrong with the connection."),
  );
  if (a.inlineError !== null) {
    cardEl.append(
      errorState(a.inlineError.message, errorAdvice(a.inlineError.code) ?? "", { code: a.inlineError.code }),
    );
  }
  cardEl.append(
    iconTextButton("refresh", a.busy ? "Refreshing…" : "Refresh (re-check for a created vault)", {
      variant: "primary",
      disabled: a.busy,
      onClick: () => a.onRefresh(),
    }),
  );
  wrap.append(cardEl);
  root.append(wrap);
}

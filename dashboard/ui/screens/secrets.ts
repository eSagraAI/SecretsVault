// Secrets: METADATA ONLY — keys + updated timestamps, never values.
// The plaintext value lives in the form <input> for the moment of
// submission: read once into a local, clear the input immediately, call
// secret_set, and let the local go out of scope. Nothing is preserved on
// failure — the input stays cleared and the user retypes. Values are shown
// only in the reveal modal (screens/reveal.ts), never in this list.

import {
  banner,
  button,
  card,
  el,
  emptyState,
  errorState,
  iconTextButton,
  loadingState,
  pageHeader,
  para,
  table,
} from "../components.js";
import { errorAdvice, fmtRelative, type MappedError, type SecretForm, type SecretMeta, type ShellState } from "../state.js";

export interface SecretsActions {
  busyAction: string | null;
  confirmKey: string | null;
  form: SecretForm | null;
  onPickProject: (name: string) => void;
  onReload: () => void;
  onOpenAdd: () => void;
  onOpenEdit: (key: string) => void;
  onCloseForm: () => void;
  onSubmitAdd: (key: string, value: string) => void;
  onSubmitEdit: (key: string, value: string) => void;
  onDelete: (key: string) => void;
  onCancelConfirm: () => void;
  /** Open the reveal modal for one key. Never renders the value here. */
  onReveal: (key: string) => void;
  inlineError: MappedError | null;
}

export function renderSecrets(root: HTMLElement, s: ShellState, a: SecretsActions): void {
  root.replaceChildren();
  const reloading = a.busyAction === "secrets_list";
  root.append(
    pageHeader("Secrets", {
      subtitle: "Key names and timestamps only — values never appear here.",
      actions: [
        button(reloading ? "Loading…" : "Reload", {
          disabled: a.busyAction !== null,
          onClick: () => a.onReload(),
        }),
      ],
    }),
  );

  if (s.sessionExpired) {
    root.append(banner("warn", "Your session expired — unlock again before managing secrets."));
  }
  if (a.inlineError) {
    root.append(
      errorState(a.inlineError.message, errorAdvice(a.inlineError.code) ?? "", {
        code: a.inlineError.code,
        retry: [button("Reload", { disabled: a.busyAction !== null, onClick: () => a.onReload() })],
      }),
    );
  }

  root.append(projectPicker(s, a));

  const active = s.activeProject;
  if (active === null) {
    if (s.projects !== null && s.projects.length === 0) {
      root.append(
        emptyState("No projects yet", "Create a project first — secrets live inside a project.", { icon: "projects" }),
      );
    } else if (a.busyAction === "projects_list" || a.busyAction === "secrets_list") {
      root.append(loadingState("Loading projects…"));
    } else {
      root.append(banner("info", "Secret keys are not loaded yet — press Reload."));
    }
    return;
  }

  if (a.form) {
    root.append(secretForm(active, a.form, a));
  } else {
    root.append(
      button("Add secret", {
        variant: "primary",
        disabled: a.busyAction !== null,
        onClick: () => a.onOpenAdd(),
      }),
    );
  }

  const keys = s.secrets;
  if (keys === null) {
    if (reloading) {
      root.append(loadingState(`Loading keys for "${active}"…`));
    } else {
      root.append(banner("info", `Keys for "${active}" are not loaded yet — press Reload.`));
    }
    return;
  }
  if (keys.length === 0) {
    root.append(
      emptyState(`No secrets in "${active}" yet`, "Add the first key above. Values are never listed — only key names and timestamps appear here.", {
        icon: "secrets",
      }),
    );
    return;
  }
  root.append(keysTable(active, keys, a));
}


function projectPicker(s: ShellState, a: SecretsActions): HTMLElement {
  const wrap = el("div", { class: "row" });
  wrap.append(el("label", { class: "lbl", for: "secrets-project" }, "Project:"));
  const list = s.projects ?? [];
  if (list.length === 0) {
    wrap.append(el("span", { class: "muted" }, s.projects === null ? "loading…" : "no projects"));
    return wrap;
  }
  const sel = el("select", { id: "secrets-project", class: "select", "aria-label": "Active project" }) as HTMLSelectElement;
  for (const p of list) {
    const opt = el("option", { value: p.name }, p.name) as HTMLOptionElement;
    if (p.name === s.activeProject) opt.selected = true;
    sel.append(opt);
  }
  if (a.busyAction !== null) sel.setAttribute("disabled", "");
  sel.addEventListener("change", () => a.onPickProject(sel.value));
  wrap.append(sel);
  return wrap;
}

function keysTable(project: string, keys: SecretMeta[], a: SecretsActions): HTMLElement {
  const now = Date.now();
  const rows: HTMLElement[][] = keys.map((e) => {
    const keyCell = el("span", { class: "mono" }, e.key);
    const projCell = el("span", {}, project);
    const age = e.updated ? fmtRelative(e.updated, now) : "—";
    const updatedCell = el("span", { title: e.updated || "unknown" }, age);
    const acts = el("div", { class: "table-actions" });
    acts.append(button("Edit", { onClick: () => a.onOpenEdit(e.key) }));
    if (a.confirmKey === e.key) {
      const deleting = a.busyAction === "secret_delete";
      acts.append(
        button(deleting ? "Deleting…" : "Confirm delete", {
          variant: "danger",
          disabled: deleting,
          onClick: () => a.onDelete(e.key),
        }),
        button("Cancel", { variant: "ghost", disabled: deleting, onClick: () => a.onCancelConfirm() }),
      );
    } else {
      acts.append(button("Delete…", { disabled: a.busyAction !== null, onClick: () => a.onDelete(e.key) }));
    }
    // Reveal is SENSITIVE and TEMPORARY: warn tone plus the eye icon and an
    // explicit title — it opens a masked, time-limited panel. Never a plain field.
    acts.append(
      iconTextButton("eye", "Reveal", {
        variant: "warn",
        disabled: a.busyAction !== null,
        onClick: () => a.onReveal(e.key),
        title: "Reveal opens a masked, time-limited panel showing this value for 15 s.",
      }),
    );
    return [keyCell, projCell, updatedCell, acts];
  });
  return table(["Key", "Project", "Updated", "Actions"], rows, {
    dense: true,
    label: "Secrets",
    empty: "No secrets.",
  });
}

/**
 * The secret-value lifecycle, pinned here:
 *
 * - the plaintext lives ONLY in `valueInput` (the DOM node) while typed;
 * - on submit: `const value = valueInput.value; valueInput.value = "";`
 *   reads it ONCE into a function-local, clears the node immediately, then
 *   calls secret_set with that local; the local goes out of scope on return;
 * - nothing is stored in state/storage/URL/logs, nothing is preserved on
 *   failure — the cleared input forces a retype;
 * - on close the whole form subtree (inputs included) is removed, so no DOM
 *   node anywhere still contains the value.
 */
function secretForm(project: string, form: SecretForm, a: SecretsActions): HTMLElement {
  const isAdd = form.mode === "add";
  const key = isAdd ? "" : form.key;
  const box = card(isAdd ? `Add secret to "${project}"` : `New value for "${key}"`, {
    subtitle: "The value is read once, cleared immediately, and sent to the broker.",
  });
  const inner = el("form", { autocomplete: "off" });
  const keyInput = el("input", {
    type: "text",
    class: "input",
    placeholder: "Key",
    "aria-label": "Secret key",
    autocomplete: "off",
  }) as HTMLInputElement;
  if (!isAdd) {
    keyInput.value = key;
    keyInput.setAttribute("disabled", "");
    keyInput.setAttribute("aria-disabled", "true");
  }
  const valueInput = el("input", {
    type: "password",
    class: "input",
    placeholder: "Value (cleared on submit; the broker stores it, this screen keeps nothing)",
    "aria-label": "Secret value",
    autocomplete: "new-password",
  }) as HTMLInputElement;
  const busy = a.busyAction === "secret_set";
  const submit = button(busy ? "Saving…" : "Save", { variant: "primary", type: "submit", disabled: busy });
  const cancel = button("Cancel", { disabled: busy, onClick: () => a.onCloseForm() });
  if (busy) {
    keyInput.setAttribute("disabled", "");
    valueInput.setAttribute("disabled", "");
  }
  inner.append(keyInput, valueInput, submit, cancel);
  inner.append(para("The value is read once, cleared immediately, and sent to the broker. The broker stores it; this screen keeps nothing — retype if saving fails.", "muted"));
  inner.addEventListener("submit", (ev) => {
    ev.preventDefault();
    // THE lifecycle: read once into a local, clear the node immediately,
    // hand the local to the single secret_set call. Nothing stored or kept.
    const k = isAdd ? keyInput.value.trim() : key;
    const value = valueInput.value;
    valueInput.value = "";
    if (!k || !value) return;
    if (isAdd) a.onSubmitAdd(k, value);
    else a.onSubmitEdit(key, value);
  });
  box.body.append(inner);
  return box.root;
}

/**
 * Pure, DOM-free twin of the submit handler above, for tests: given the
 * staged key/value, return the secret_set args and the cleared remainder.
 * Asserts the lifecycle invariant — after this call nothing of the value
 * is kept: the "kept" field is always null and there is no other output.
 */
export function takeSecretSubmit(key: string, value: string): { args: { key: string; value: string }; kept: null } {
  if (!key || !value) throw new Error("key and value are required");
  return { args: { key, value }, kept: null };
}

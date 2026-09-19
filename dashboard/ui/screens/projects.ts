// Projects: broker-backed CRUD over `projects_list` / `project_add` /
// `project_remove` / `project_path_add` / `project_path_remove`.
// No optimistic UI: after any mutation the list is re-read before render.
// No frontend re-validation of broker rules — only an empty-field guard to
// avoid a pointless roundtrip; everything else is the broker's E_* error.

import {
  banner,
  button,
  card,
  chipList,
  confirmBar,
  el,
  emptyState,
  errorState,
  fieldGrid,
  loadingState,
  pageHeader,
  para,
  section,
} from "../components.js";
import {
  agentsWithAccess,
  capabilityTone,
  errorAdvice,
  fmtCount,
  loadedSecretCount,
  projectByName,
  type MappedError,
  type PendingConfirm,
  type ProjectEntry,
  type ProjectTab,
  type ShellState,
} from "../state.js";

export interface ProjectsActions {
  busyAction: string | null;
  pendingConfirm: PendingConfirm | null;
  tab: ProjectTab;
  onTab: (tab: ProjectTab) => void;
  onCreate: (name: string, paths: string[]) => void;
  onRemove: (name: string) => void;
  onPathAdd: (name: string, path: string) => void;
  onPathRemove: (name: string, path: string) => void;
  onSelect: (name: string | null) => void;
  onOpen: (name: string) => void;
  onCancelConfirm: () => void;
  onReload: () => void;
  inlineError: MappedError | null;
}

const TABS: Array<{ id: ProjectTab; label: string }> = [
  { id: "overview", label: "Overview" },
  { id: "secrets", label: "Secrets" },
  { id: "access", label: "Access" },
  { id: "paths", label: "Paths" },
];

function busyNote(busy: boolean): string {
  return busy ? " (working…)" : "";
}

export function renderProjects(root: HTMLElement, s: ShellState, a: ProjectsActions): void {
  root.replaceChildren();
  const reloading = a.busyAction === "projects_list";
  root.append(
    pageHeader("Projects", {
      subtitle: "Select a project to inspect its paths, secrets, and access.",
      actions: [
        button(reloading ? "Loading…" : "Reload", {
          disabled: a.busyAction !== null,
          onClick: () => a.onReload(),
        }),
      ],
    }),
  );

  if (s.sessionExpired) {
    root.append(banner("warn", "Your session expired — unlock again before managing projects."));
  }
  if (a.inlineError) {
    root.append(
      errorState(a.inlineError.message, errorAdvice(a.inlineError.code) ?? "", {
        code: a.inlineError.code,
        retry: [button("Reload", { disabled: a.busyAction !== null, onClick: () => a.onReload() })],
      }),
    );
  }

  root.append(renderCreateDetails(a));

  const list = s.projects;
  if (list === null) {
    if (reloading) {
      root.append(loadingState("Loading projects…"));
    } else {
      root.append(banner("info", "Project list is not loaded yet — press Reload."));
    }
    return;
  }
  if (list.length === 0) {
    root.append(
      emptyState(
        "No projects yet",
        "The broker reports an empty project registry. Create the first project above — a name alone is enough; authorized paths can be added later.",
        { icon: "projects" },
      ),
    );
    return;
  }

  const layout = el("div", { class: "master-detail" });
  layout.append(renderMasterList(list, s, a));
  layout.append(renderDetail(s, a));
  root.append(layout);
}

// Create stays reachable without spending a ShellState field: a <details>
// disclosure holds the same form with the same empty-name guard.
function renderCreateDetails(a: ProjectsActions): HTMLElement {
  const busy = a.busyAction === "project_add";
  const disc = el("details", {});
  disc.append(el("summary", {}, "New project"));
  const form = el("form", { autocomplete: "off" });
  form.append(para("A name alone is enough — authorized paths can be added later.", "muted"));
  const nameInput = el("input", {
    type: "text",
    class: "input",
    placeholder: "Project name",
    "aria-label": "Project name",
  }) as HTMLInputElement;
  const pathsInput = el("input", {
    type: "text",
    class: "input",
    placeholder: "Authorized paths, one per line or comma-separated (optional)",
    "aria-label": "Authorized paths",
  }) as HTMLInputElement;
  const btn = el("button", { type: "submit", class: "btn btn-primary" }, `Create${busyNote(busy)}`);
  if (busy) {
    btn.setAttribute("disabled", "");
    nameInput.setAttribute("disabled", "");
    pathsInput.setAttribute("disabled", "");
  }
  form.append(
    nameInput,
    pathsInput,
    btn,
    para("Names and paths are validated by the broker — its error is shown here if it refuses.", "muted"),
  );
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const name = nameInput.value.trim();
    if (!name) {
      a.onCreate("", []);
      return;
    }
    const paths = pathsInput.value
      .split(/[\n,]/)
      .map((x) => x.trim())
      .filter((x) => x.length > 0);
    a.onCreate(name, paths);
  });
  disc.append(form);
  return disc;
}

function renderMasterList(list: ProjectEntry[], s: ShellState, a: ProjectsActions): HTMLElement {
  const nav = el("div", { class: "master-list", role: "listbox", "aria-label": "Projects" });
  for (const p of list) {
    const selected = s.selectedProject === p.name;
    const item = el(
      "button",
      {
        type: "button",
        class: selected ? "master-item master-item-active" : "master-item",
        role: "option",
        "aria-selected": selected ? "true" : "false",
      },
    );
    item.append(el("span", { class: "truncate" }, p.name));
    item.append(el("span", { class: "muted" }, `${p.paths.length} path${p.paths.length === 1 ? "" : "s"}`));
    item.addEventListener("click", () => a.onSelect(selected ? null : p.name));
    nav.append(item);
  }
  return nav;
}
function renderDetail(s: ShellState, a: ProjectsActions): HTMLElement {
  const detail = el("div", { class: "detail" });
  const sel = s.selectedProject === null ? null : projectByName(s, s.selectedProject);
  if (sel === null) {
    detail.append(
      emptyState("No project selected", "Pick a project on the left to inspect its paths, secrets, and access.", {
        icon: "projects",
      }),
    );
    return detail;
  }
  detail.append(el("h2", {}, sel.name));
  const tabs = el("div", { class: "tabs" });
  const tablist = el("div", { class: "tablist", role: "tablist", "aria-label": "Project detail" });
  for (const t of TABS) {
    const active = a.tab === t.id;
    const tab = el(
      "button",
      {
        type: "button",
        role: "tab",
        class: active ? "tab tab-active" : "tab",
        "aria-selected": active ? "true" : "false",
      },
      t.label,
    );
    tab.addEventListener("click", () => a.onTab(t.id));
    tablist.append(tab);
  }
  tabs.append(tablist);
  const panelEl = el("div", { class: "tabpanel", role: "tabpanel" });
  if (a.tab === "secrets") renderSecretsTab(panelEl, s, sel.name);
  else if (a.tab === "access") renderAccessTab(panelEl, s, sel.name);
  else if (a.tab === "paths") renderPathsTab(panelEl, sel, a);
  else renderOverviewTab(panelEl, s, sel, a);
  tabs.append(panelEl);
  detail.append(tabs);
  return detail;
}

function renderOverviewTab(host: HTMLElement, s: ShellState, p: ProjectEntry, a: ProjectsActions): void {
  host.append(
    fieldGrid([
      ["Name", p.name],
      ["Paths", `${p.paths.length} path${p.paths.length === 1 ? "" : "s"}`],
      ["Loaded secrets", fmtCount(loadedSecretCount(s, p.name))],
    ]),
  );
  const row = el("div", { class: "row" });
  row.append(button("Open (view secrets)", { variant: "primary", onClick: () => a.onOpen(p.name) }));
  host.append(row);
  const danger = card("Danger zone", {
    tone: "bad",
    subtitle: "Destructive actions live here, apart from everything else.",
  });
  danger.body.append(para("Delete removes the project and its registry entry. This cannot be undone.", "muted"));
  const confirm = a.pendingConfirm;
  if (confirm !== null && confirm.kind === "project" && confirm.project === p.name) {
    const deleting = a.busyAction === "project_remove";
    danger.body.append(
      confirmBar(`Delete project "${p.name}"?`, {
        onConfirm: () => a.onRemove(p.name),
        onCancel: () => a.onCancelConfirm(),
        busy: deleting,
        confirmLabel: deleting ? "Deleting…" : "Confirm delete",
        danger: true,
      }),
    );
  } else {
    danger.body.append(
      button("Delete…", {
        variant: "danger",
        disabled: a.busyAction !== null,
        onClick: () => a.onRemove(p.name),
      }),
    );
  }
  host.append(danger.root);
}

function renderSecretsTab(host: HTMLElement, s: ShellState, name: string): void {
  const count = loadedSecretCount(s, name);
  host.append(
    fieldGrid([
      ["Project", name],
      ["Keys", fmtCount(count)],
    ]),
  );
  host.append(
    para(
      count === null
        ? `Key count for "${name}" is not loaded — open the Secrets screen to load it.`
        : `"${name}" holds ${count} key${count === 1 ? "" : "s"}.`,
      "muted",
    ),
  );
  // Navigation only — never a broker call.
  host.append(el("a", { href: "#/secrets" }, `Open ${name} in Secrets`));
}

function renderAccessTab(host: HTMLElement, s: ShellState, name: string): void {
  // Honesty: `grants === null` means the grants list was never read, which is
  // NOT the same as "nobody has access". Never render an unknown as a negative.
  if (s.grants === null) {
    host.append(
      emptyState("Access not loaded", "The grants list has not been read yet — its state is unknown, not empty. Press Load grants to read it.", {
        icon: "grants",
        actions: [el("a", { class: "btn", href: "#/grants" }, "Load grants")],
      }),
    );
    return;
  }
  const rows = agentsWithAccess(s, name);
  if (rows.length === 0) {
    host.append(emptyState("No access", `Nobody holds a grant on "${name}" — grant capabilities from the Grants screen to give an agent access.`, { icon: "agents" }));
  } else {
    host.append(
      fieldGrid(
        rows.map(
          (r): [string, Node] => [r.agent, chipList(r.ops.map((op) => ({ text: op, tone: capabilityTone(op) })))],
        ),
      ),
    );
  }
  // Navigation only — never a broker call.
  host.append(el("a", { href: "#/grants" }, "Manage grants"));
}

function renderPathsTab(host: HTMLElement, p: ProjectEntry, a: ProjectsActions): void {
  const sec = section("Authorized paths", { subtitle: `Paths the broker trusts for "${p.name}".` });
  if (p.paths.length === 0) {
    sec.body.append(emptyState("No authorized paths yet", "Add one below — the broker records it for this project.", { icon: "projects" }));
  } else {
    sec.body.append(chipList(p.paths.map((path) => ({ text: path }))));
  }
  sec.body.append(pathAddRow(p, a));
  sec.body.append(pathRemoveRow(p, a));
  host.append(sec.root);
}

function pathAddRow(p: ProjectEntry, a: ProjectsActions): HTMLElement {
  const busy = a.busyAction === "project_path_add";
  const form = el("form", { class: "pathrow", autocomplete: "off" });
  const input = el("input", {
    type: "text",
    class: "input",
    placeholder: "New authorized path",
    "aria-label": `New authorized path for ${p.name}`,
  }) as HTMLInputElement;
  const btn = el("button", { type: "submit", class: "btn" }, `Add path${busyNote(busy)}`);
  if (busy) {
    btn.setAttribute("disabled", "");
    input.setAttribute("disabled", "");
  }
  form.append(input, btn);
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const path = input.value.trim();
    if (!path) {
      a.onPathAdd(p.name, "");
      return;
    }
    a.onPathAdd(p.name, path);
  });
  return form;
}

function pathRemoveRow(p: ProjectEntry, a: ProjectsActions): HTMLElement {
  const wrap = el("div", { class: "pathrow" });
  const confirm = a.pendingConfirm;
  if (confirm !== null && confirm.kind === "path" && confirm.project === p.name && confirm.extra) {
    const target = confirm.extra;
    const removing = a.busyAction === "project_path_remove";
    wrap.append(
      confirmBar(`Remove "${target}"?`, {
        onConfirm: () => a.onPathRemove(p.name, target),
        onCancel: () => a.onCancelConfirm(),
        busy: removing,
        confirmLabel: removing ? "Removing…" : "Confirm remove",
        danger: true,
      }),
    );
    return wrap;
  }
  if (p.paths.length === 0) return wrap;
  const sel = el("select", {
    class: "select",
    "aria-label": `Authorized path to remove from ${p.name}`,
  }) as HTMLSelectElement;
  for (const path of p.paths) {
    sel.append(el("option", { value: path }, path) as HTMLOptionElement);
  }
  const btn = el("button", { type: "button", class: "btn" }, "Remove path…");
  if (a.busyAction !== null) btn.setAttribute("disabled", "");
  btn.addEventListener("click", () => a.onPathRemove(p.name, sel.value));
  wrap.append(sel, btn);
  return wrap;
}

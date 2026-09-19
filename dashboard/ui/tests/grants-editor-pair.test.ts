// Grants editor: the Agent × Project pair must be a real, visible control.
//
// Why this suite exists: `editorPanel` created the two selects and never put
// them in the DOM, so the editor silently kept whatever the detached elements
// defaulted to (the first option of each list) while showing no target at all.
// With two agents or two projects, "Save grant" then mutated a pair the
// operator could not see and could not change. These tests drive the real app
// module in a real DOM and pin: the selectors exist and are labelled, another
// pair is selectable, the capability row re-syncs to THAT pair's active grant,
// the save target is exactly the pair on screen, widening still confirms, the
// run-removal note survives, and a staged draft never follows a pair change.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { buttonByText, makeEnv, trustedUnlocked, type DomEnv, type Responder } from "./dom-harness.js";

type Pair = { agent: string; project: string; ops: string[]; revoked: boolean };
type SaveCall = { agent: string; project: string; ops: string[] };

const AGENTS = ["alice", "bob"];
const PROJECTS = ["proj-one", "proj-two"];
const WIDE = ["read", "inject", "run", "reveal"];

/** A broker that lists two agents and two projects and records every grant_set. */
function broker(initial: Pair[], saves: SaveCall[]): Responder {
  let grants = initial.map((g) => ({ ...g, ops: [...g.ops] }));
  return (cmd, args) => {
    if (cmd === "grant_set") {
      // The wire contract sends `ops` as a comma-separated string (api.ts).
      const { agent, project, ops } = args as { agent: string; project: string; ops: string };
      const set = ops === "" ? [] : ops.split(",");
      saves.push({ agent, project, ops: set });
      // Broker semantics: the old row is revoked, a new active one is appended.
      grants = grants
        .map((g) => (g.agent === agent && g.project === project ? { ...g, revoked: true } : g))
        .concat([{ agent, project, ops: set, revoked: false }]);
      return { granted: agent };
    }
    if (cmd === "grant_revoke") return { revoked: "ok" };
    if (cmd === "projects_list") {
      return { projects: PROJECTS.map((name) => ({ name, paths: [`/tmp/${name}`] })) };
    }
    if (cmd === "agents_list") {
      return { agents: AGENTS.map((name) => ({ name, status: "active", token_prefix: name.slice(0, 2) })) };
    }
    if (cmd === "grants_list") return { grants: grants.map((g) => ({ ...g, ops: [...g.ops] })) };
    const known = (trustedUnlocked as unknown as Record<string, () => unknown>)[cmd];
    return known ? known() : {};
  };
}

function read<T extends Element>(env: DomEnv, selector: string): T {
  const el = env.doc.querySelector(selector);
  assert.ok(el, `expected ${selector} to be rendered`);
  return el as T;
}

const agentPick = (env: DomEnv): HTMLSelectElement => read(env, 'select[aria-label="Agent"]');
const projectPick = (env: DomEnv): HTMLSelectElement => read(env, 'select[aria-label="Project"]');

/** The capability boxes of the editor form, in DOM order. */
const boxes = (env: DomEnv): HTMLInputElement[] => [
  ...env.doc.querySelectorAll<HTMLInputElement>('form input[type="checkbox"]'),
];

const checkedOps = (env: DomEnv): string[] => boxes(env).filter((b) => b.checked).map((b) => b.value);

function setBox(env: DomEnv, cap: string, on: boolean): void {
  const box = boxes(env).find((b) => b.value === cap);
  assert.ok(box, `the editor offers a ${cap} box`);
  box.checked = on;
  box.dispatchEvent(new env.win.Event("change", { bubbles: true }));
}

/** Pick a pair the way the operator does: a change event on each selector. */
function pick(env: DomEnv, agent: string, project: string): void {
  agentPick(env).value = agent;
  agentPick(env).dispatchEvent(new env.win.Event("change", { bubbles: true }));
  projectPick(env).value = project;
  projectPick(env).dispatchEvent(new env.win.Event("change", { bubbles: true }));
}

function save(env: DomEnv): void {
  const btn = buttonByText(env, "Save grant");
  assert.ok(btn, "the editor offers Save grant");
  env.click(btn);
}

const bodyText = (env: DomEnv): string => env.doc.body.textContent ?? "";

async function openGrants(respond: Responder): Promise<DomEnv> {
  const env = await makeEnv(respond, { hash: "#/grants" });
  await env.settle();
  return env;
}

describe("Grants editor: the agent × project pair is a visible control", () => {
  it("renders exactly the labelled Agent and Project selectors, with the broker's options", async () => {
    const env = await openGrants(broker([], []));
    try {
      const selects = [...env.doc.querySelectorAll("form select")];
      assert.equal(selects.length, 2, "the editor form holds exactly two selectors");
      assert.deepEqual(
        selects.map((s) => s.getAttribute("aria-label")),
        ["Agent", "Project"],
      );
      assert.deepEqual([...agentPick(env).options].map((o) => o.value), AGENTS);
      assert.deepEqual([...projectPick(env).options].map((o) => o.value), PROJECTS);
      assert.ok(agentPick(env).isConnected && projectPick(env).isConnected, "both selectors are in the document");
      assert.equal(agentPick(env).disabled, false, "a loaded agent list leaves the selector usable");
      assert.equal(projectPick(env).disabled, false, "a loaded project list leaves the selector usable");
      assert.deepEqual(
        [...env.doc.querySelectorAll(".form-row .lbl")].map((l) => l.textContent),
        ["Agent", "Project"],
      );
    } finally {
      env.teardown();
    }
  });

  it("lets the operator pick a pair other than the first, and keeps it", async () => {
    const env = await openGrants(
      broker(
        [
          { agent: "alice", project: "proj-one", ops: ["read"], revoked: false },
          { agent: "bob", project: "proj-two", ops: ["read", "run"], revoked: false },
        ],
        [],
      ),
    );
    try {
      assert.equal(agentPick(env).value, "alice", "the default pair is the first option of each list");
      assert.equal(projectPick(env).value, "proj-one");
      pick(env, "bob", "proj-two");
      await env.settle();
      assert.equal(agentPick(env).value, "bob");
      assert.equal(projectPick(env).value, "proj-two");
      assert.deepEqual(checkedOps(env).sort(), ["read", "run"]);
    } finally {
      env.teardown();
    }
  });

  it("re-syncs the capability row to the picked pair's ACTIVE grant only", async () => {
    const env = await openGrants(
      broker(
        [
          { agent: "alice", project: "proj-one", ops: ["read", "run"], revoked: false },
          { agent: "bob", project: "proj-two", ops: WIDE, revoked: true },
          { agent: "bob", project: "proj-two", ops: ["read"], revoked: false },
        ],
        [],
      ),
    );
    try {
      pick(env, "bob", "proj-two");
      await env.settle();
      assert.deepEqual(checkedOps(env), ["read"], "the revoked wide row is not an authority");

      pick(env, "alice", "proj-one");
      await env.settle();
      assert.deepEqual(checkedOps(env).sort(), ["read", "run"], "no baseline is kept from the previous pair");

      pick(env, "bob", "proj-two");
      await env.settle();
      assert.deepEqual(checkedOps(env), ["read"], "and back again, still live-only");
    } finally {
      env.teardown();
    }
  });

  it("keeps `read` as the baseline after wide grant → revoke → grant read", async () => {
    const saves: SaveCall[] = [];
    const env = await openGrants(
      broker(
        [
          { agent: "alice", project: "proj-one", ops: ["read"], revoked: false },
          { agent: "bob", project: "proj-two", ops: WIDE, revoked: true },
          { agent: "bob", project: "proj-two", ops: ["read"], revoked: false },
        ],
        saves,
      ),
    );
    try {
      pick(env, "bob", "proj-two");
      await env.settle();
      assert.deepEqual(checkedOps(env), ["read"]);
      save(env);
      await env.settle();
      assert.deepEqual(saves, [{ agent: "bob", project: "proj-two", ops: ["read"] }]);
      assert.ok(!bodyText(env).includes("Confirm grant:"), "an untouched save is not a widening, so it asks nothing");
    } finally {
      env.teardown();
    }
  });

  it("saves exactly the visible pair — the audit repro leaves the first pair alone", async () => {
    const saves: SaveCall[] = [];
    const env = await openGrants(
      broker(
        [
          { agent: "alice", project: "proj-one", ops: ["read"], revoked: false },
          { agent: "bob", project: "proj-two", ops: ["read", "run"], revoked: false },
        ],
        saves,
      ),
    );
    try {
      pick(env, "bob", "proj-two");
      await env.settle();
      setBox(env, "run", false); // intent: narrow bob → proj-two
      save(env);
      await env.settle();

      assert.deepEqual(saves, [{ agent: "bob", project: "proj-two", ops: ["read"] }]);
      assert.ok(
        !saves.some((c) => c.agent === "alice" || c.project === "proj-one"),
        "no write may land on the pair the operator never selected",
      );
    } finally {
      env.teardown();
    }
  });

  it("requires the confirmation before adding run, reveal or inject", async () => {
    const saves: SaveCall[] = [];
    const env = await openGrants(
      broker(
        [
          { agent: "alice", project: "proj-one", ops: [], revoked: false },
          { agent: "bob", project: "proj-two", ops: ["read"], revoked: false },
        ],
        saves,
      ),
    );
    try {
      for (const cap of ["run", "reveal", "inject"]) {
        pick(env, "bob", "proj-two");
        await env.settle();
        setBox(env, cap, true);
        const expected = checkedOps(env);
        assert.ok(expected.includes(cap), `${cap} is ticked on screen`);
        save(env);
        await env.settle();
        assert.deepEqual(saves, [], `adding ${cap} must not write before the confirmation`);
        assert.ok(bodyText(env).includes("Confirm grant: bob → proj-two"), `the confirmation names the visible pair for ${cap}`);
        assert.ok(bodyText(env).includes(`ADDS authority (${cap})`), `the confirmation names the widened capability ${cap}`);
        env.click(read(env, ".confirm-bar button:last-child"));
        await env.settle();
        assert.deepEqual(saves, [{ agent: "bob", project: "proj-two", ops: expected }], `confirming saves exactly the checked set for ${cap}`);
        // `mutateGrants` re-reads the list; the new active row becomes the baseline.
        saves.length = 0;
      }
    } finally {
      env.teardown();
    }
  });

  it("keeps the run-termination note when `run` is removed from a live grant", async () => {
    const saves: SaveCall[] = [];
    const env = await openGrants(
      broker([{ agent: "bob", project: "proj-two", ops: ["read", "run"], revoked: false }], saves),
    );
    try {
      pick(env, "bob", "proj-two");
      await env.settle();
      const note = read(env, "[data-run-note]");
      assert.equal(note.textContent, "", "no removal yet, so no consequence");

      setBox(env, "run", false);
      assert.match(note.textContent ?? "", /Removing `run` terminates this agent's active runs on this project\./);

      save(env);
      await env.settle();
      assert.deepEqual(saves, [{ agent: "bob", project: "proj-two", ops: ["read"] }]);
    } finally {
      env.teardown();
    }
  });

  it("never applies a staged draft to a pair picked afterwards", async () => {
    const saves: SaveCall[] = [];
    const env = await openGrants(
      broker(
        [
          { agent: "alice", project: "proj-one", ops: ["read", "run"], revoked: false },
          { agent: "bob", project: "proj-two", ops: ["read"], revoked: false },
        ],
        saves,
      ),
    );
    try {
      pick(env, "bob", "proj-two");
      await env.settle();
      setBox(env, "run", true); // widening → parks in the draft
      save(env);
      await env.settle();
      assert.deepEqual(saves, [], "the widening waits for the confirmation");
      assert.ok(bodyText(env).includes("Confirm grant: bob → proj-two"));

      pick(env, "alice", "proj-one");
      await env.settle();

      assert.ok(!bodyText(env).includes("Confirm grant: bob → proj-two"), "the draft for the old pair is dropped");
      assert.deepEqual(saves, [], "dropping the draft writes nothing");
      assert.equal(agentPick(env).value, "alice");
      assert.equal(projectPick(env).value, "proj-one");
      assert.deepEqual(checkedOps(env).sort(), ["read", "run"], "the row follows the newly visible pair");

      save(env);
      await env.settle();
      assert.deepEqual(saves, [{ agent: "alice", project: "proj-one", ops: ["read", "run"] }]);
    } finally {
      env.teardown();
    }
  });

  it("smoke: two agents × two projects stay distinct end to end", async () => {
    const saves: SaveCall[] = [];
    const env = await openGrants(broker([], saves));
    try {
      pick(env, "bob", "proj-two");
      await env.settle();
      assert.deepEqual(checkedOps(env), [], "a pair with no grant starts empty");

      setBox(env, "read", true);
      setBox(env, "run", true);
      save(env);
      await env.settle();
      assert.ok(bodyText(env).includes("Confirm grant: bob → proj-two"), "the first grant is a widening");
      env.click(read(env, ".confirm-bar button:last-child"));
      await env.settle();
      assert.deepEqual(saves, [{ agent: "bob", project: "proj-two", ops: ["read", "run"] }]);

      pick(env, "alice", "proj-one");
      await env.settle();
      assert.deepEqual(checkedOps(env), [], "the other pair is untouched by the previous save");

      setBox(env, "read", true);
      save(env);
      await env.settle();
      assert.ok(bodyText(env).includes("Confirm grant: alice → proj-one"));
      env.click(read(env, ".confirm-bar button:last-child"));
      await env.settle();
      assert.deepEqual(saves, [
        { agent: "bob", project: "proj-two", ops: ["read", "run"] },
        { agent: "alice", project: "proj-one", ops: ["read"] },
      ]);
    } finally {
      env.teardown();
    }
  });
});

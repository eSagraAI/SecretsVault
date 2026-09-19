// H1 regression: a background tick may never destroy what the operator has
// typed. These are real DOM/render tests (jsdom + the real app module and its
// real timers), not state-only tests: the failure this suite pins was invisible
// to a pure-state test, because the state was never wrong — the DOM was.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { buttonByText, fail, makeEnv, trustedUnlocked, type DomEnv, type Responder } from "./dom-harness.js";

const SESSION_TICK_MS = 1000;

/** Every command the app knows, answered as a trusted+unlocked posture. */
function answering(cmd: string): unknown {
  const r = (trustedUnlocked as Record<string, () => unknown>)[cmd];
  return r ? r() : {};
}

/** The live-locked posture: gate up, unlock available; a successful unlock
 * flips the reported lock state, as the real broker does. */
function liveLocked(): Responder {
  let unlocked = false;
  return (cmd) => {
    if (cmd === "unlock") {
      unlocked = true;
      return {
        unlocked: true,
        session_prefix: "deadbeef",
        expires_at: "2026-01-01 00:05:00.000000000 +00:00:00",
        expires_in: 300,
        max_expires_at: "2026-01-01 00:30:00.000000000 +00:00:00",
        max_expires_in: 1800,
      };
    }
    if (cmd === "get_status") {
      return {
        version: 1,
        created: "2026-01-01 00:00:00.000000000 +00:00:00",
        locked: !unlocked,
        online: true,
        trusted: true,
        initialized: true,
        fingerprint: "ab".repeat(32),
      };
    }
    return answering(cmd);
  };
}

/** Unlocked broker-side, but this process holds no session (the common case
 * after a session TTL lapses, or on first launch against a CLI-unlocked vault). */
function noSessionPosture(cmd: string): unknown {
  if (cmd === "health") fail("E_AUTH", "authentication failed");
  if (cmd === "projects_list" || cmd === "agents_list" || cmd === "leases_list") {
    fail("E_SESSION_EXPIRED", "session expired or revoked");
  }
  return answering(cmd);
}

function read<T extends Element>(env: DomEnv, selector: string): T {
  const el = env.doc.querySelector(selector);
  assert.ok(el, `expected ${selector} to be rendered`);
  return el as T;
}

describe("H1: a tick never destroys typed input", () => {
  it("keeps the typed secret value, its node, its focus and its selection across 3 ticks", async () => {
    const env = await makeEnv(answering, { hash: "#/secrets" });
    try {
      const add = buttonByText(env, "Add secret");
      assert.ok(add, "the secrets screen offers Add secret");
      env.click(add);
      await env.settle();

      const key = read<HTMLInputElement>(env, 'input[aria-label="Secret key"]');
      const value = read<HTMLInputElement>(env, 'input[aria-label="Secret value"]');
      env.typeInput(key, "STRIPE_KEY");
      env.typeInput(value, "sk-live-TRAPVALUE");
      value.setSelectionRange(3, 7);
      const focusedBefore = env.doc.activeElement;

      env.advance(SESSION_TICK_MS * 3);
      await env.settle();

      const keyAfter = read<HTMLInputElement>(env, 'input[aria-label="Secret key"]');
      const valueAfter = read<HTMLInputElement>(env, 'input[aria-label="Secret value"]');
      assert.equal(keyAfter, key, "the key input is the same DOM node");
      assert.equal(valueAfter, value, "the value input is the same DOM node");
      assert.equal(keyAfter.value, "STRIPE_KEY");
      assert.equal(valueAfter.value, "sk-live-TRAPVALUE");
      assert.equal(env.doc.activeElement, focusedBefore, "focus stayed in the field");
      assert.deepEqual([valueAfter.selectionStart, valueAfter.selectionEnd], [3, 7], "the selection survived");
    } finally {
      env.teardown();
    }
  });

  it("keeps a passphrase typed into the no-session gate", async () => {
    const env = await makeEnv(noSessionPosture);
    try {
      const pass = read<HTMLInputElement>(env, "#unlock-pass");
      assert.match(env.doc.querySelector(".gate-card h2")?.textContent ?? "", /No usable human session/);
      env.typeInput(pass, "correct horse battery");

      env.advance(SESSION_TICK_MS * 3);
      await env.settle();

      const passAfter = read<HTMLInputElement>(env, "#unlock-pass");
      assert.equal(passAfter, pass, "the gate input is the same DOM node");
      assert.equal(passAfter.value, "correct horse battery");
      assert.equal(env.doc.activeElement, passAfter, "focus stayed in the passphrase field");
    } finally {
      env.teardown();
    }
  });

  it("keeps a typed project name and path", async () => {
    const env = await makeEnv(answering, { hash: "#/projects" });
    try {
      const name = read<HTMLInputElement>(env, 'input[aria-label="Project name"]');
      const paths = read<HTMLInputElement>(env, 'input[aria-label="Authorized paths"]');
      env.typeInput(name, "acme-widgets");
      env.typeInput(paths, "/tmp/work");

      env.advance(SESSION_TICK_MS * 3);
      await env.settle();

      assert.equal(read<HTMLInputElement>(env, 'input[aria-label="Project name"]'), name);
      assert.equal(name.value, "acme-widgets");
      assert.equal(paths.value, "/tmp/work");
    } finally {
      env.teardown();
    }
  });

  it("keeps the reveal modal and its value on screen", async () => {
    const env = await makeEnv(
      (cmd) => {
        if (cmd === "secrets_list") return { secrets: [{ key: "STRIPE_KEY", updated: "2026-01-01T00:00:00Z" }] };
        if (cmd === "reveal") return { value: "sk-live-TRAPVALUE" };
        return answering(cmd);
      },
      { hash: "#/secrets" },
    );
    try {
      const reveal = buttonByText(env, "Reveal");
      assert.ok(reveal, "the key row offers Reveal");
      env.click(reveal);
      await env.settle();
      // The modal asks for the value explicitly; nothing is revealed on open.
      const show = buttonByText(env, "Reveal and show");
      assert.ok(show, "the modal offers Reveal and show");
      env.click(show);
      await env.settle();

      const valueNode = env.doc.querySelector(".reveal-value");
      assert.ok(valueNode, "the reveal modal rendered the value node");
      assert.equal(valueNode.textContent, "sk-live-TRAPVALUE");

      env.advance(SESSION_TICK_MS * 3);
      await env.settle();

      assert.equal(env.doc.querySelector(".reveal-value"), valueNode, "the value node was not rebuilt");
      assert.equal(env.doc.querySelector(".reveal-value")?.textContent, "sk-live-TRAPVALUE");
    } finally {
      env.teardown();
    }
  });

  it("still repaints an untouched screen on a tick", async () => {
    const env = await makeEnv(answering, { hash: "#/secrets" });
    try {
      const before = read(env, ".outlet h1");
      env.advance(SESSION_TICK_MS);
      await env.settle();
      assert.notEqual(read(env, ".outlet h1"), before, "an idle screen is still refreshed by the ticker");
    } finally {
      env.teardown();
    }
  });

  it("keeps the live session countdown ticking", async () => {
    const env = await makeEnv(liveLocked());
    try {
      const pass = read<HTMLInputElement>(env, "#unlock-pass");
      env.typeInput(pass, "correct horse battery");
      const unlock = buttonByText(env, "Unlock");
      assert.ok(unlock, "the gate offers Unlock");
      env.click(unlock);
      await env.settle();

      const first = read(env, '[data-session-live="countdown"]').textContent ?? "";
      env.advance(SESSION_TICK_MS * 3);
      await env.settle();
      const after = read(env, '[data-session-live="countdown"]').textContent ?? "";
      assert.notEqual(after, first, "the countdown advanced while the screen was idle");

      // With the screen edited the ticker must update that node in place
      // instead of repainting the screen around it.
      const outlet = env.doc.querySelector(".outlet");
      assert.ok(outlet);
      outlet.dispatchEvent(new env.win.Event("input", { bubbles: true }));
      const live = read(env, '[data-session-live="countdown"]');
      const before = live.textContent ?? "";
      env.advance(SESSION_TICK_MS * 3);
      await env.settle();
      const afterNode = read(env, '[data-session-live="countdown"]');
      assert.equal(afterNode, live, "the countdown node was updated in place, not rebuilt");
      assert.notEqual(afterNode.textContent, before, "and it kept ticking while the screen was edited");
    } finally {
      env.teardown();
    }
  });
});

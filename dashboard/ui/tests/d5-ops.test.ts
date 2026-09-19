// D5 ops screens: reveal-value discipline (the security invariant), the
// reveal auto-hide window, the explicit-only clipboard policy, and the two
// timing constants. (Placeholder-route narrowing was removed in D6: both of
// its routes, audit and settings, graduated to real screens.)
// Pure functions only — no DOM, no framework.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import {
  REVEAL_AUTO_HIDE_MS,
  REVEAL_CLIPBOARD_CLEAR_MS,
  revealClipboardCopy,
  revealVisible,
  takeRevealValue,
} from "../screens/reveal.js";

const TRAP = "sv1-reveal-trap-9f8e7d6c5b4a3940313233343536373839abcdef";

describe("takeRevealValue shows the value and persists nothing", () => {
  it("returns the value as shown with persisted always null", () => {
    const out = takeRevealValue({ value: TRAP });
    assert.equal(out.shown, TRAP);
    assert.equal(out.persisted, null);
  });
  it("has no other output to stash in state", () => {
    const out = takeRevealValue({ value: TRAP });
    assert.deepEqual(Object.keys(out).sort(), ["persisted", "shown"]);
  });
  it("rejects an empty reveal result instead of showing nothing", () => {
    assert.throws(() => takeRevealValue({ value: "" }), /no value/);
  });
});

describe("revealVisible keeps the 15 s window", () => {
  it("just-revealed and inside the window stay visible", () => {
    const shown = 1_000_000;
    assert.equal(revealVisible(shown, shown, false), true);
    assert.equal(revealVisible(shown, shown + REVEAL_AUTO_HIDE_MS - 1, false), true);
  });
  it("at and past 15 s the value is hidden", () => {
    const shown = 1_000_000;
    assert.equal(revealVisible(shown, shown + REVEAL_AUTO_HIDE_MS, false), false);
    assert.equal(revealVisible(shown, shown + 60_000, false), false);
  });
  it("never-revealed or dismissed is hidden", () => {
    assert.equal(revealVisible(null, 1_000_000, false), false);
    assert.equal(revealVisible(1_000_000, 1_000_000, true), false);
    assert.equal(revealVisible(1_000_000, 1_000_000 + 60_000, true), false);
  });
});

describe("revealClipboardCopy stays explicit-only", () => {
  it("a fresh reveal never copies; only the explicit trigger does", () => {
    assert.equal(revealClipboardCopy("reveal"), false);
    assert.equal(revealClipboardCopy("explicit"), true);
  });
});

describe("reveal timing constants stay pinned", () => {
  it("auto-hide is 15 s and clipboard clear is 30 s", () => {
    assert.equal(REVEAL_AUTO_HIDE_MS, 15_000);
    assert.equal(REVEAL_CLIPBOARD_CLEAR_MS, 30_000);
  });
});

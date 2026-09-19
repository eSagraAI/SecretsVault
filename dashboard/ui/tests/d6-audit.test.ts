// D6 audit screen: the pure helpers behind the audit timeline. The screen
// itself is a DOM renderer (untestable here), so these small functions carry
// the honest-copy rules: counts that pluralise, a summary line that keeps an
// empty log distinct from a filtered-out page, an auth badge labelled in text
// (never colour alone), and verify wording that states what the walk proves
// and what it cannot — never "secure", never a bare "OK". Pure, no DOM.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import {
  auditAuthBadge,
  auditFilterIsActive,
  auditRowCountLabel,
  auditSummary,
  auditVerifyWording,
} from "../screens/audit.js";
import { AUDIT_PAGE_SIZE } from "../state.js";
import type { AuditEntry, AuditFilters, AuditVerifyResult } from "../state.js";

function entry(seq: number): AuditEntry {
  return {
    seq,
    ts: "2026-09-17T12:00:00.000Z",
    actor: "human",
    op: "secret.read",
    keys: ["api-key"],
    decision: "allowed",
    authenticated: true,
  };
}

function entries(from: number, n: number): AuditEntry[] {
  const out: AuditEntry[] = [];
  for (let i = 0; i < n; i++) out.push(entry(from + i));
  return out;
}

function filters(partial: Partial<AuditFilters> = {}): AuditFilters {
  return { actor: "", op: "", project: "", decision: "", ...partial };
}

describe("auditRowCountLabel pluralises honestly", () => {
  it("uses the singular only for exactly one", () => {
    assert.equal(auditRowCountLabel(0), "0 entries");
    assert.equal(auditRowCountLabel(1), "1 entry");
    assert.equal(auditRowCountLabel(50), "50 entries");
  });
});

describe("auditFilterIsActive fires on any narrowed field", () => {
  it("is inactive when every field is empty", () => {
    assert.equal(auditFilterIsActive(filters()), false);
  });
  it("is active when any single field is set", () => {
    assert.equal(auditFilterIsActive(filters({ actor: "ada" })), true);
    assert.equal(auditFilterIsActive(filters({ op: "secret.read" })), true);
    assert.equal(auditFilterIsActive(filters({ project: "web" })), true);
    assert.equal(auditFilterIsActive(filters({ decision: "denied" })), true);
  });
});

describe("auditAuthBadge labels the unauthenticated branch in text", () => {
  it("marks MAC-backed entries authenticated and muted", () => {
    assert.deepEqual(auditAuthBadge(true), { label: "authenticated", tone: "mute" });
  });
  it("marks MAC-less entries unauthenticated in both label and tone, not colour alone", () => {
    const bad = auditAuthBadge(false);
    assert.deepEqual(bad, { label: "unauthenticated", tone: "warn" });
    assert.notEqual(bad.label, auditAuthBadge(true).label);
  });
});

describe("auditSummary states count, range and whether the log continues", () => {
  it("covers a single full page with older entries remaining", () => {
    const line = auditSummary(entries(51, AUDIT_PAGE_SIZE), true);
    assert.match(line, new RegExp(`${AUDIT_PAGE_SIZE} entries`));
    assert.match(line, /seq 51–100/);
    assert.match(line, /Older entries remain\./);
  });
  it("covers a partially loaded set with older entries remaining", () => {
    const line = auditSummary(entries(8, 3), true);
    assert.match(line, /3 entries/);
    assert.match(line, /seq 8–10/);
    assert.match(line, /Older entries remain\./);
  });
  it("says the beginning is reached once the cursor is exhausted", () => {
    const line = auditSummary(entries(1, 5), false);
    assert.match(line, /5 entries/);
    assert.match(line, /seq 1–5/);
    assert.match(line, /Beginning of the log reached\./);
  });
  it("collapses the range for a single entry and stays honest when empty", () => {
    assert.match(auditSummary(entries(7, 1), false), /1 entry loaded \(seq 7\)\./);
    assert.equal(auditSummary([], false), "No entries loaded.");
  });
});

describe("auditVerifyWording stays bounded", () => {
  it("says verification has not been run when there is no report", () => {
    assert.match(auditVerifyWording(null), /has not been run/);
  });
  it("names both what the walk proves and what it cannot prove", () => {
    const r: AuditVerifyResult = { entries: 120, macs_verified: 100, macs_null: 20 };
    const line = auditVerifyWording(r);
    assert.match(line, /120 entries/);
    assert.match(line, /100 MACs verified/);
    assert.match(line, /20 without a MAC/);
    assert.match(line, /internally consistent/);
    assert.match(line, /MAC chain verifies/);
    assert.match(line, /could rewrite/);
    assert.match(line, /undetectable without the key/);
  });
  it("never claims security and never passes a bare OK as a verdict", () => {
    const lines = [auditVerifyWording(null), auditVerifyWording({ entries: 1, macs_verified: 1, macs_null: 0 })];
    for (const line of lines) {
      assert.doesNotMatch(line, /secure/i);
      assert.doesNotMatch(line, /\bOK\b/);
    }
  });
});

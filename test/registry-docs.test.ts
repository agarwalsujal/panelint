/**
 * The registry and docs/RULES.md must not diverge.
 *
 * SARIF `rules[].id` is a public contract: the census directory keys on it and
 * disclosure emails cite it. If a doc and the code disagree, the code is right
 * and the doc is a bug — this file exists to make that impossible to ignore.
 *
 * It parses the rule tables out of docs/RULES.md rather than duplicating them,
 * so there is exactly one place a rule's class, severity and confidence are
 * written down by hand.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { ALL_RULES, RULES_BY_ID } from '../src/rules/registry.js';
import type { AnyRule } from '../src/types.js';

const RULES_MD = readFileSync(new URL('../docs/RULES.md', import.meta.url), 'utf8');

interface DocRow {
  id: string;
  ruleClass: string;
  severity: string;
  confidence: string;
}

/**
 * Pull `| PANE-X-001 | … | CLASS | SEV | CONF |` rows out of the catalog.
 *
 * The tables put the ID first and class/severity/confidence in the last three
 * columns; the columns between them differ per family (one calls it "Check",
 * another "Carrier", another "Signal"), so the parser anchors on the ends.
 */
function parseDocRows(md: string): Map<string, DocRow> {
  const out = new Map<string, DocRow>();
  const rowRe = /^\|\s*`?(PANE-[A-Z]+-\d{3})`?\s*\|(.+)\|\s*$/gm;

  for (const m of md.matchAll(rowRe)) {
    const id = m[1]!;
    const cells = m[2]!.split('|').map((c) => c.replace(/\*\*/g, '').trim());
    if (cells.length < 3) continue;
    const [confidence, severity, ruleClass] = [
      cells[cells.length - 1]!,
      cells[cells.length - 2]!,
      cells[cells.length - 3]!,
    ];
    if (!/^(CERTAIN|HIGH|MEDIUM|LOW)$/.test(confidence)) continue;
    out.set(id, { id, ruleClass, severity, confidence });
  }
  return out;
}

const docRows = parseDocRows(RULES_MD);

describe('docs/RULES.md is parseable at all', () => {
  it('finds rule rows in the catalog', () => {
    // If this fails the rest of the file is vacuously green, which is worse
    // than a red test — it would silently stop checking anything.
    expect(docRows.size).toBeGreaterThan(50);
  });
});

describe('every registered rule matches its documented row', () => {
  const registered = ALL_RULES as AnyRule[];

  it('registers at least one rule', () => {
    expect(registered.length).toBeGreaterThan(0);
  });

  it.each(ALL_RULES.map((r) => [r.id, r] as const))('%s matches RULES.md', (id, rule) => {
    const doc = docRows.get(id);
    expect(doc, `${id} is registered but has no row in docs/RULES.md`).toBeDefined();
    expect(rule.ruleClass, `${id} class`).toBe(doc!.ruleClass);
    expect(rule.severity, `${id} severity`).toBe(doc!.severity);
    expect(rule.confidence, `${id} confidence`).toBe(doc!.confidence);
  });
});

describe('rule IDs are a public contract', () => {
  it('has no duplicate IDs', () => {
    const ids = ALL_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('uses the PANE-FAMILY-NNN shape without exception', () => {
    for (const r of ALL_RULES) expect(r.id).toMatch(/^PANE-[A-Z]+-\d{3}$/);
  });

  it('gives every rule a remediation, a title and a since version', () => {
    for (const r of ALL_RULES) {
      expect(r.title.length, `${r.id} title`).toBeGreaterThan(0);
      expect(r.remediation.length, `${r.id} remediation`).toBeGreaterThan(0);
      expect(r.since, `${r.id} since`).toMatch(/^\d+\.\d+\.\d+$/);
    }
  });

  it('resolves every ID through RULES_BY_ID', () => {
    for (const r of ALL_RULES) expect(RULES_BY_ID.get(r.id)).toBe(r);
  });
});

describe('the classification model is respected', () => {
  it('never claims CERTAIN for a rule whose family reads declared CSS', () => {
    // Panelint does not compute styles, so a declared `display:none` may be
    // overridden by cascade order, specificity, !important, or a media query.
    // CERTAIN is reserved for facts that survive any rendering.
    const cssDependent = ALL_RULES.filter(
      (r) => r.id.startsWith('PANE-HIDDEN-') || r.id.startsWith('PANE-OVERLAY-'),
    );
    for (const r of cssDependent) {
      // PANE-HIDDEN-009 is Unicode, a structural fact about bytes, not CSS.
      if (r.id === 'PANE-HIDDEN-009') continue;
      expect(r.confidence, `${r.id} reads declared CSS and cannot be CERTAIN`).not.toBe('CERTAIN');
    }
  });

  it('marks every PANE-MIMIC rule experimental', () => {
    const mimic = ALL_RULES.filter((r) => r.id.startsWith('PANE-MIMIC-'));
    for (const r of mimic) expect(r.experimental, `${r.id}`).toBe(true);
  });

  it('keeps the four dataflow rules non-gating by confidence', () => {
    // RULES.md: these ship advisory until their false-positive rate is
    // measured. MEDIUM confidence is what makes that true mechanically rather
    // than by intention.
    for (const id of ['PANE-CONTEXT-005', 'PANE-MSG-004', 'PANE-INPUT-004', 'PANE-EXFIL-005']) {
      const rule = RULES_BY_ID.get(id);
      if (!rule) continue;
      expect(['MEDIUM', 'LOW'], `${id} must not be able to gate`).toContain(rule.confidence);
    }
  });
});

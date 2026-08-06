import { describe, it, expect } from 'vitest';
import { dedupeFindings, COLLISION_GROUPS } from '../src/rules/dedup.js';
import type { Finding, Severity, SourceLocation } from '../src/types.js';

/**
 * The cross-rule deduplication pass.
 *
 * docs/RULES.md § PANE-SCHEMA mandates it and states the formula verbatim:
 * "Deduplication is by `(resource, json-pointer)`; higher severity wins." It
 * cannot live inside a rule, because a rule is a pure function that cannot see
 * what another rule found.
 *
 * The invariant every test below defends: dedup may collapse a finding that
 * DESCRIBES THE SAME FACT as a higher-severity one. It may never drop a finding
 * that describes a different fact, and it may never depend on input order.
 */

let seq = 0;

function finding(over: Partial<Finding> = {}): Finding {
  seq++;
  return {
    ruleId: 'PANE-TEST-001',
    ruleClass: 'RISK',
    severity: 'MEDIUM',
    confidence: 'HIGH',
    experimental: false,
    message: 'test finding',
    resourceUri: 'ui://server/view',
    fingerprint: `fp-${seq}`,
    ...over,
  };
}

const at = (line: number, col = 1): SourceLocation => ({ startLine: line, startCol: col });
const ids = (f: Finding[]): string[] => f.map((x) => x.ruleId);

/** Deterministic shuffle, so a failing run is reproducible. */
function shuffle<T>(xs: readonly T[], seedIn: number): T[] {
  const out = [...xs];
  let seed = seedIn;
  for (let i = out.length - 1; i > 0; i--) {
    seed = (seed * 1103515245 + 12345) % 2147483648;
    const j = seed % (i + 1);
    [out[i], out[j]] = [out[j]!, out[i]!];
  }
  return out;
}

describe('documented collision pairs', () => {
  it('suppresses PANE-SCHEMA-003 when PANE-CSP-002 fires on the same pointer', () => {
    // A bare `*` is both malformed and dangerous. The operator needs to know
    // what it DOES, not what shape it has. RULES.md § PANE-SCHEMA, Precedence.
    const csp = finding({
      ruleId: 'PANE-CSP-002',
      severity: 'CRITICAL',
      confidence: 'CERTAIN',
      jsonPointer: '/ui/csp/resourceDomains/0',
    });
    const schema = finding({
      ruleId: 'PANE-SCHEMA-003',
      severity: 'MEDIUM',
      jsonPointer: '/ui/csp/resourceDomains/0',
    });

    const out = dedupeFindings([schema, csp]);
    expect(ids(out.findings)).toEqual(['PANE-CSP-002']);
    expect(out.collapsed).toHaveLength(1);
    expect(out.collapsed[0]!.kept).toBe('PANE-CSP-002');
    expect(out.collapsed[0]!.suppressed.map((s) => s.ruleId)).toEqual(['PANE-SCHEMA-003']);
  });

  it('suppresses PANE-SCHEMA-003 under PANE-CSP-001 too', () => {
    const csp = finding({
      ruleId: 'PANE-CSP-001',
      severity: 'HIGH',
      jsonPointer: '/ui/csp/connectDomains/0',
    });
    const schema = finding({
      ruleId: 'PANE-SCHEMA-003',
      jsonPointer: '/ui/csp/connectDomains/0',
    });
    expect(ids(dedupeFindings([csp, schema]).findings)).toEqual(['PANE-CSP-001']);
  });

  it('keeps PANE-SCHEMA-003 when the CSP finding is on a DIFFERENT pointer', () => {
    const csp = finding({ ruleId: 'PANE-CSP-001', severity: 'HIGH', jsonPointer: '/ui/csp/connectDomains/0' });
    const schema = finding({ ruleId: 'PANE-SCHEMA-003', jsonPointer: '/ui/csp/connectDomains/1' });
    expect(ids(dedupeFindings([csp, schema]).findings).sort()).toEqual([
      'PANE-CSP-001',
      'PANE-SCHEMA-003',
    ]);
  });

  it('collapses PANE-SPEC-008 into PANE-CONTEXT-006 — same _meta.ui.domain field', () => {
    // SPEC-008 is INFO severity, CONTEXT-006 is MEDIUM. Higher severity wins.
    const spec = finding({ ruleId: 'PANE-SPEC-008', severity: 'INFO', ruleClass: 'SPEC', jsonPointer: '/ui/domain' });
    const ctx = finding({ ruleId: 'PANE-CONTEXT-006', severity: 'MEDIUM', ruleClass: 'INFO', jsonPointer: '/ui/domain' });
    expect(ids(dedupeFindings([spec, ctx]).findings)).toEqual(['PANE-CONTEXT-006']);
  });

  it('collapses PANE-SANDBOX-006 into PANE-INPUT-003 — the same clipboard call', () => {
    const input = finding({ ruleId: 'PANE-INPUT-003', severity: 'HIGH', location: at(12, 5) });
    const sandbox = finding({ ruleId: 'PANE-SANDBOX-006', severity: 'MEDIUM', location: at(12, 5) });
    const out = dedupeFindings([sandbox, input]);
    expect(ids(out.findings)).toEqual(['PANE-INPUT-003']);
    expect(out.collapsed[0]!.suppressed.map((s) => s.ruleId)).toEqual(['PANE-SANDBOX-006']);
  });
});

describe('the .sr-only recipe — one node, three PANE-HIDDEN rules', () => {
  const hidden = (id: string, severity: Severity): Finding =>
    finding({ ruleId: id, severity, location: at(40, 3), message: `${id} fired` });

  it('collapses to the highest-severity carrier', () => {
    const out = dedupeFindings([
      hidden('PANE-HIDDEN-014', 'MEDIUM'),
      hidden('PANE-HIDDEN-005', 'HIGH'),
      hidden('PANE-HIDDEN-006', 'MEDIUM'),
    ]);
    expect(ids(out.findings)).toEqual(['PANE-HIDDEN-005']);
  });

  it('lists the suppressed rules as additional carriers in the surviving message', () => {
    const out = dedupeFindings([
      hidden('PANE-HIDDEN-005', 'MEDIUM'),
      hidden('PANE-HIDDEN-006', 'MEDIUM'),
      hidden('PANE-HIDDEN-014', 'MEDIUM'),
    ]);
    expect(out.findings).toHaveLength(1);
    const message = out.findings[0]!.message;
    expect(message).toContain('PANE-HIDDEN-006');
    expect(message).toContain('PANE-HIDDEN-014');
    expect(message).toContain('carrier');
  });

  it('does not mutate the input findings', () => {
    const a = hidden('PANE-HIDDEN-005', 'HIGH');
    const b = hidden('PANE-HIDDEN-006', 'MEDIUM');
    dedupeFindings([a, b]);
    expect(a.message).toBe('PANE-HIDDEN-005 fired');
  });

  it('keeps carriers found on DIFFERENT nodes', () => {
    const out = dedupeFindings([
      finding({ ruleId: 'PANE-HIDDEN-005', location: at(40) }),
      finding({ ruleId: 'PANE-HIDDEN-006', location: at(90) }),
    ]);
    expect(out.findings).toHaveLength(2);
  });
});

describe('what dedup must never do', () => {
  it('never collapses two rules that are not a documented collision', () => {
    // Same node, genuinely different facts: an off-origin form action and a
    // hidden-text carrier are both worth reporting.
    const out = dedupeFindings([
      finding({ ruleId: 'PANE-EXFIL-001', severity: 'HIGH', location: at(7) }),
      finding({ ruleId: 'PANE-HIDDEN-005', severity: 'MEDIUM', location: at(7) }),
    ]);
    expect(out.findings).toHaveLength(2);
    expect(out.collapsed).toHaveLength(0);
  });

  it('never collapses across resources', () => {
    const out = dedupeFindings([
      finding({ ruleId: 'PANE-CSP-002', severity: 'CRITICAL', resourceUri: 'ui://a/x', jsonPointer: '/ui/csp' }),
      finding({ ruleId: 'PANE-SCHEMA-003', resourceUri: 'ui://b/x', jsonPointer: '/ui/csp' }),
    ]);
    expect(out.findings).toHaveLength(2);
  });

  it('keeps findings that carry no site at all — no pointer, no location', () => {
    const out = dedupeFindings([
      finding({ ruleId: 'PANE-CSP-002', severity: 'CRITICAL', message: 'a' }),
      finding({ ruleId: 'PANE-SCHEMA-003', message: 'b' }),
    ]);
    expect(out.findings).toHaveLength(2);
  });

  it('collapses byte-identical duplicates of one rule', () => {
    const a = finding({ ruleId: 'PANE-CSP-001', fingerprint: 'same', jsonPointer: '/ui/csp/connectDomains/0' });
    const b = finding({ ruleId: 'PANE-CSP-001', fingerprint: 'same', jsonPointer: '/ui/csp/connectDomains/0' });
    const out = dedupeFindings([a, b]);
    expect(out.findings).toHaveLength(1);
    expect(out.collapsed[0]!.reason).toBe('IDENTICAL');
  });

  it('keeps two findings from one rule at one site when the messages differ', () => {
    // Same fingerprint, different fact. Dropping one loses information.
    const a = finding({ ruleId: 'PANE-HIDDEN-014', fingerprint: 'same', message: 'text-indent', location: at(3) });
    const b = finding({ ruleId: 'PANE-HIDDEN-014', fingerprint: 'same', message: 'color-transparent', location: at(3) });
    expect(dedupeFindings([a, b]).findings).toHaveLength(2);
  });
});

describe('determinism', () => {
  const corpus: Finding[] = [
    finding({ ruleId: 'PANE-CSP-002', severity: 'CRITICAL', jsonPointer: '/ui/csp/resourceDomains/0' }),
    finding({ ruleId: 'PANE-SCHEMA-003', jsonPointer: '/ui/csp/resourceDomains/0' }),
    finding({ ruleId: 'PANE-HIDDEN-005', severity: 'MEDIUM', location: at(40, 3) }),
    finding({ ruleId: 'PANE-HIDDEN-006', severity: 'MEDIUM', location: at(40, 3) }),
    finding({ ruleId: 'PANE-HIDDEN-014', severity: 'MEDIUM', location: at(40, 3) }),
    finding({ ruleId: 'PANE-EXFIL-001', severity: 'HIGH', location: at(7) }),
    finding({ ruleId: 'PANE-INPUT-003', severity: 'HIGH', location: at(12, 5), resourceUri: 'ui://server/other' }),
    finding({ ruleId: 'PANE-SANDBOX-006', location: at(12, 5), resourceUri: 'ui://server/other' }),
  ];

  it('produces the same output for every input permutation', () => {
    const baseline = dedupeFindings(corpus);
    for (const seed of [1, 7, 13, 99, 4242]) {
      const out = dedupeFindings(shuffle(corpus, seed));
      expect(ids(out.findings)).toEqual(ids(baseline.findings));
      expect(out.findings.map((f) => f.fingerprint)).toEqual(
        baseline.findings.map((f) => f.fingerprint),
      );
      expect(out.collapsed).toEqual(baseline.collapsed);
    }
  });

  it('logs every collapse so the count is auditable', () => {
    const out = dedupeFindings(corpus);
    const suppressedCount = out.collapsed.reduce((n, c) => n + c.suppressed.length, 0);
    expect(out.findings.length + suppressedCount).toBe(corpus.length);
  });
});

describe('the collision table itself', () => {
  it('names every documented pair from RULES.md', () => {
    const flat = COLLISION_GROUPS.flatMap((g) => g.ruleIds);
    for (const id of [
      'PANE-CSP-001',
      'PANE-CSP-002',
      'PANE-SCHEMA-003',
      'PANE-SPEC-008',
      'PANE-CONTEXT-006',
      'PANE-INPUT-003',
      'PANE-SANDBOX-006',
      'PANE-HIDDEN-005',
      'PANE-HIDDEN-006',
      'PANE-HIDDEN-014',
    ]) {
      expect(flat).toContain(id);
    }
  });

  it('never lists one rule in two groups — the winner would depend on scan order', () => {
    const flat = COLLISION_GROUPS.flatMap((g) => g.ruleIds);
    expect(new Set(flat).size).toBe(flat.length);
  });
});

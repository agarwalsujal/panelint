import { describe, it, expect } from 'vitest';
import { isGating, selectExitCode, meetsSeverity } from '../src/exit.js';
import type { Finding } from '../src/types.js';

/**
 * The gate formula, verbatim from docs/RULES.md and restated in docs/DESIGN.md §4:
 *
 *   confidence ∈ { CERTAIN, HIGH }  ∧  class ≠ INFO  ∧  ¬experimental  ∧  severity ≥ --fail-on
 *
 * Three documents once specified three different gates. This file is the
 * specification for isGating(), one test per clause, so that cannot recur.
 */

const finding = (over: Partial<Finding> = {}): Finding => ({
  ruleId: 'PANE-TEST-001',
  ruleClass: 'RISK',
  severity: 'HIGH',
  confidence: 'CERTAIN',
  experimental: false,
  message: 'test finding',
  resourceUri: 'ui://server/view',
  fingerprint: 'deadbeef',
  ...over,
});

describe('isGating — one assertion per clause of the formula', () => {
  it('gates a CERTAIN, non-INFO, non-experimental finding at the threshold', () => {
    expect(isGating(finding(), 'HIGH')).toBe(true);
  });

  it('gates at HIGH confidence too — the set is { CERTAIN, HIGH }', () => {
    expect(isGating(finding({ confidence: 'HIGH' }), 'HIGH')).toBe(true);
  });

  it('never gates on MEDIUM confidence, whatever the severity', () => {
    // PANE-CONTEXT-005 is CRITICAL/MEDIUM. The crown-jewel rule is advisory
    // until its false-positive rate is measured. RULES.md § Gate eligibility.
    expect(isGating(finding({ confidence: 'MEDIUM', severity: 'CRITICAL' }), 'INFO')).toBe(false);
  });

  it('never gates on LOW confidence', () => {
    expect(isGating(finding({ confidence: 'LOW', severity: 'CRITICAL' }), 'INFO')).toBe(false);
  });

  it('never gates an INFO-class finding — capability disclosure is not a defect', () => {
    // PANE-CONTEXT-001 is INFO/HIGH. Gating on it would make a capability
    // disclosure fail a build, contradicting GOALS.md N1.
    expect(isGating(finding({ ruleClass: 'INFO', severity: 'HIGH' }), 'HIGH')).toBe(false);
  });

  it('never gates an experimental rule, at any severity or threshold', () => {
    // The whole PANE-MIMIC family is permanently non-gating while experimental.
    expect(isGating(finding({ experimental: true, severity: 'CRITICAL' }), 'INFO')).toBe(false);
  });

  it('does not gate below the threshold', () => {
    expect(isGating(finding({ severity: 'MEDIUM' }), 'HIGH')).toBe(false);
  });

  it('gates above the threshold', () => {
    expect(isGating(finding({ severity: 'CRITICAL' }), 'HIGH')).toBe(true);
  });

  it('gates SPEC and SCHEMA classes identically to RISK', () => {
    expect(isGating(finding({ ruleClass: 'SPEC' }), 'HIGH')).toBe(true);
    expect(isGating(finding({ ruleClass: 'SCHEMA' }), 'HIGH')).toBe(true);
  });
});

describe('meetsSeverity — the ordering the threshold uses', () => {
  it('orders CRITICAL > HIGH > MEDIUM > LOW > INFO', () => {
    expect(meetsSeverity('CRITICAL', 'HIGH')).toBe(true);
    expect(meetsSeverity('HIGH', 'HIGH')).toBe(true);
    expect(meetsSeverity('MEDIUM', 'HIGH')).toBe(false);
    expect(meetsSeverity('INFO', 'LOW')).toBe(false);
    expect(meetsSeverity('LOW', 'INFO')).toBe(true);
  });
});

describe('selectExitCode — DESIGN.md §4', () => {
  it('exits 0 when all resources scanned and nothing gates', () => {
    expect(selectExitCode([finding({ severity: 'LOW' })], [], 'HIGH', 'fail')).toBe(0);
  });

  it('exits 1 on a finding at or above the threshold', () => {
    expect(selectExitCode([finding()], [], 'HIGH', 'fail')).toBe(1);
  });

  it('exits 2 on a scan error under the default --on-error=fail', () => {
    // Code 0 requires that ALL resources scanned successfully. Silently
    // under-reporting when 3 of 10 resources failed to parse is the failure
    // mode this replaced.
    expect(selectExitCode([], [{ code: 'PARSE_FAILED', message: 'x' }], 'HIGH', 'fail')).toBe(2);
  });

  it('does not exit 2 for a scan error under --on-error=warn', () => {
    expect(selectExitCode([], [{ code: 'PARSE_FAILED', message: 'x' }], 'HIGH', 'warn')).toBe(0);
  });

  it('prefers 2 over 1 when there is both an error and a gating finding', () => {
    expect(selectExitCode([finding()], [{ code: 'PARSE_FAILED', message: 'x' }], 'HIGH', 'fail')).toBe(2);
  });

  it('exits 0 on an empty scan — never a silent pass, but not a failure either', () => {
    expect(selectExitCode([], [], 'HIGH', 'fail')).toBe(0);
  });
});

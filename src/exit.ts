/**
 * Gate eligibility and exit codes.
 *
 * This file is the implementation of one formula, and nothing else belongs in
 * it. Earlier revisions of the project's own documents specified three
 * different gates across two files; the formula is restated verbatim below and
 * transcribed clause by clause so that test/gate.test.ts maps 1:1 onto source.
 *
 *   confidence ∈ { CERTAIN, HIGH }  ∧  class ≠ INFO  ∧  ¬experimental  ∧  severity ≥ --fail-on
 *
 * Do not widen it. A CI gate that fires on a heuristic gets disabled, and then
 * nothing is checked.
 */

import { SEVERITY_ORDER, type Finding, type Severity, type ScanError } from './types.js';

/** True when `severity` is at or above `threshold`. */
export function meetsSeverity(severity: Severity, threshold: Severity): boolean {
  return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[threshold];
}

/**
 * Does this finding fail the build?
 *
 * All four clauses must hold. Each is a named boolean rather than a fused
 * expression, because the named version is the one a reviewer can check against
 * the formula without reading it twice.
 */
export function isGating(finding: Finding, failOn: Severity): boolean {
  // Never gate on a heuristic. PANE-CONTEXT-005 is CRITICAL/MEDIUM and cannot
  // gate; the crown-jewel rule stays advisory until its FP rate is measured.
  const confidenceIsHardEnough =
    finding.confidence === 'CERTAIN' || finding.confidence === 'HIGH';

  // Capability disclosure is not a defect. PANE-CONTEXT-001 is INFO/HIGH.
  const classIsNotInfo = finding.ruleClass !== 'INFO';

  // Experimental never gates, at any severity. The whole PANE-MIMIC family.
  const isNotExperimental = !finding.experimental;

  const severityMeetsThreshold = meetsSeverity(finding.severity, failOn);

  return (
    confidenceIsHardEnough &&
    classIsNotInfo &&
    isNotExperimental &&
    severityMeetsThreshold
  );
}

export type ExitCode = 0 | 1 | 2;

export type OnError = 'fail' | 'warn';

/**
 * Exit code selection, per docs/DESIGN.md §4.
 *
 *   0 — all resources scanned successfully AND no findings at or above --fail-on
 *   1 — findings at or above threshold
 *   2 — scan error: could not reach server, malformed input, or a limit exceeded
 *
 * Code 0 requires that *all* resources scanned successfully. The alternative
 * was a choice between silently under-reporting when 3 of 10 resources failed
 * to parse, and blocking CI on one bad resource; `--on-error` selects between
 * them instead of the design picking one.
 *
 * Scanning zero resources is exit 0 with an explicit diagnostic — never a
 * silent pass, but not a failure either. The diagnostic is the caller's job to
 * surface; this function only chooses the code.
 */
export function selectExitCode(
  findings: Finding[],
  errors: ScanError[],
  failOn: Severity,
  onError: OnError,
): ExitCode {
  if (onError === 'fail' && errors.length > 0) return 2;
  if (findings.some((f) => isGating(f, failOn))) return 1;
  return 0;
}

/** The findings that actually gate, for the report's summary line. */
export function gatingFindings(findings: Finding[], failOn: Severity): Finding[] {
  return findings.filter((f) => isGating(f, failOn));
}

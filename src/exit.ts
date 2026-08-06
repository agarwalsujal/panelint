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

import {
  SEVERITY_ORDER,
  type Finding,
  type Severity,
  type ScanError,
  type ScanDiagnostic,
} from './types.js';

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
  diagnostics: readonly ScanDiagnostic[] = [],
): ExitCode {
  if (onError === 'fail' && errors.length > 0) return 2;
  // A limit stopped the scan before it saw everything, so "0 findings" is not
  // an absence of findings — it is an absence of analysis.
  //
  // `INPUT_DEGRADED` is here for the same reason and was missing: a resource
  // whose style index could not be built ran every CSS rule against an empty
  // cascade, and one whose scripts did not collect ran every JS rule against an
  // empty list. Both reported "0 findings" at exit 0. Measured —
  // `<style>@media screen{.s{opacity:0}</style>` (browsers auto-close at EOF,
  // postcss does not) suppressed a CRITICAL finding that way.
  if (onError === 'fail' && scanWasTruncated(diagnostics)) return 2;
  if (findings.some((f) => isGating(f, failOn))) return 1;
  return 0;
}

/**
 * Did a limit stop this scan from seeing everything?
 *
 * Every `LIMIT_EXCEEDED` in the tree is a `ScanDiagnostic`, and `selectExitCode`
 * used to branch on `errors` alone — so a truncated scan exited 0 with "0
 * findings reported", indistinguishable from a clean one. DESIGN.md §4 had
 * always specified the opposite: "2 — scan error: could not reach server,
 * malformed input, **or a limit exceeded**".
 *
 * That made truncation a silencing primitive an attacker chooses. Measured: a
 * 2 MB comment appended to a hostile app made a CRITICAL form-action finding
 * vanish at exit 0, and 600 `<div>` strings inside an HTML comment tripped the
 * nesting ceiling on markup that nests three levels deep. It is also not
 * theoretical in aggregate — 60 of 391 repositories in the first census run hit
 * a limit, and 56 of those reported zero findings while counting as clean.
 */
export function scanWasTruncated(diagnostics: readonly ScanDiagnostic[]): boolean {
  return diagnostics.some((d) => d.code === 'LIMIT_EXCEEDED' || d.code === 'INPUT_DEGRADED');
}

/** The findings that actually gate, for the report's summary line. */
export function gatingFindings(findings: Finding[], failOn: Severity): Finding[] {
  return findings.filter((f) => isGating(f, failOn));
}

/**
 * Resource-exhaustion ceilings.
 *
 * Panelint parses hostile input by design, over a live connection, as a
 * security tool. docs/THREAT-MODEL.md §4 dismissed resource exhaustion as
 * "the spec defers it to hosts" — that reasoning is about the *host*, and was
 * silently applied to the scanner too. It does not apply here.
 *
 * Every limit lives in this file, is fixed for a given build, and produces a
 * LIMIT_EXCEEDED diagnostic rather than a crash or a silent pass.
 *
 * **There is deliberately no flag to move one**, and the diagnostics must not
 * offer one. `ruleEngineFingerprint` hashes the rule set and the pinned
 * dependency versions; it does not hash the ceilings, and neither the report
 * header nor SARIF records them. A default is still pinned, because the
 * Panelint version is inside that fingerprint — change a default and the
 * fingerprint changes with it. An operator-settable ceiling would be pinned by
 * nothing, so two reports carrying the same fingerprint and the same
 * contentHash could describe different amounts of analysis. The census
 * directory keys on exactly those two fields.
 *
 * The remedy for a ceiling that is genuinely too low is therefore a measured
 * default and a version bump, which gives every operator the same answer, and
 * not a dial that gives each one a different answer the report cannot show.
 *
 * `resolveLimits` still takes overrides for library embedders, who are the
 * operator and are not publishing into the directory. The CLI passes none.
 */

import type { Limits, ScanDiagnostic } from './types.js';

export const DEFAULT_LIMITS: Readonly<Limits> = Object.freeze({
  /** `resources/read` is uncapped by the SDK. */
  maxResourceBytes: 8 * 1024 * 1024,
  /** Recursive walkers blow the stack. */
  maxDomNodes: 100_000,
  /** Selector matching is O(rules × nodes); 50k × 20k is 10⁹ `is()` calls. */
  maxCssRules: 20_000,
  /** A hard ceiling independent of the two above. */
  selectorMatchBudget: 5_000_000,
  perResourceMs: 5_000,
  maxTotalResources: 500,
  /** Deeply nested HTML overflows recursive rules. */
  maxNestingDepth: 500,
  /** PANE-HIDDEN-010 must not decode an 80 MB data URI. */
  base64DecodeCap: 256 * 1024,
  /** acorn on a multi-megabyte minified bundle is not worth the wall clock. */
  maxScriptBytes: 2 * 1024 * 1024,
  /**
   * Evidence is quoted into CI logs and into SARIF. A hidden-text finding must
   * not reproduce the injection payload in full (DESIGN.md §10, log hygiene).
   */
  maxEvidenceChars: 120,
  /**
   * `domains x elements` is the cost of the PANE-EXFIL and PANE-CSP families,
   * and a server picks both factors. No limit key covered `_meta` at all.
   *
   * The ceiling is generous against real declarations: the largest
   * `connectDomains` in the 391-repository census is well under 100.
   */
  maxMetaDomains: 256,
});

export const LIMIT_KEYS = Object.keys(DEFAULT_LIMITS) as Array<keyof Limits>;

/**
 * Apply programmatic overrides over the defaults.
 *
 * Reachable from the library API, never from a flag — the CLI calls this with
 * no argument on every path, for the reason in this file's header.
 *
 * A non-positive override is rejected rather than accepted, because "0" reads
 * as "unlimited" to a user and as "reject everything" to the code — and either
 * reading turns a limit into a way to disable a limit.
 */
export function resolveLimits(overrides: Partial<Limits> = {}): Limits {
  const out: Limits = { ...DEFAULT_LIMITS };
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) continue;
    if (!LIMIT_KEYS.includes(key as keyof Limits)) {
      throw new Error(`Unknown limit: ${key}. Known limits: ${LIMIT_KEYS.join(', ')}`);
    }
    if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
      throw new Error(`Limit ${key} must be a positive finite number, got ${String(value)}`);
    }
    out[key as keyof Limits] = value;
  }
  return out;
}

/**
 * Compare an observed value against a limit.
 *
 * Returns a diagnostic when exceeded and null when respected. It never throws:
 * a limit being hit is a fact about the scan that the report has to carry, not
 * an error that unwinds it.
 */
export function checkLimit(
  key: keyof Limits,
  observed: number,
  limits: Limits,
  resourceUri?: string,
): ScanDiagnostic | null {
  const ceiling = limits[key];
  if (observed <= ceiling) return null;
  return {
    code: 'LIMIT_EXCEEDED',
    message: `${key} exceeded: ${observed} > ${ceiling}`,
    ...(resourceUri ? { resourceUri } : {}),
    detail:
      'Analysis of this resource is incomplete, so a zero-finding result for it is an ' +
      'absence of analysis rather than an absence of findings. This ceiling is fixed for ' +
      'this build and cannot be changed from the command line. Under the default ' +
      '--on-error fail the scan exits 2.',
  };
}

/** A wall-clock budget for one resource. */
export class Deadline {
  private readonly end: number;
  constructor(ms: number, private readonly now: () => number = Date.now) {
    this.end = now() + ms;
  }
  get expired(): boolean {
    return this.now() >= this.end;
  }
  get remainingMs(): number {
    return Math.max(0, this.end - this.now());
  }
}

/**
 * A spend-down counter for the selector-match budget.
 *
 * css-select is O(rules × nodes) and the two individual caps do not bound their
 * product, so this is checked independently of both.
 */
export class Budget {
  private spent = 0;
  constructor(private readonly ceiling: number) {}
  spend(n = 1): void {
    this.spent += n;
  }
  get exhausted(): boolean {
    return this.spent > this.ceiling;
  }
  get used(): number {
    return this.spent;
  }
}

/**
 * Resource-exhaustion ceilings.
 *
 * Panelint parses hostile input by design, over a live connection, as a
 * security tool. docs/THREAT-MODEL.md §4 dismissed resource exhaustion as
 * "the spec defers it to hosts" — that reasoning is about the *host*, and was
 * silently applied to the scanner too. It does not apply here.
 *
 * Every limit lives in this file, is overridable by flag, and produces a
 * LIMIT_EXCEEDED diagnostic rather than a crash or a silent pass.
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
});

export const LIMIT_KEYS = Object.keys(DEFAULT_LIMITS) as Array<keyof Limits>;

/**
 * Apply flag overrides over the defaults.
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
      throw new Error(`Unknown limit: ${key}`);
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
      'Analysis of this resource is incomplete. Raise the limit with the ' +
      `corresponding --${kebab(key)} flag if the input is trusted.`,
  };
}

function kebab(s: string): string {
  return s.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`);
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

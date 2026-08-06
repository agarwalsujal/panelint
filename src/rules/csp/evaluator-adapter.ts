/**
 * The `csp_evaluator` boundary.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * ⚠ THE API TRAP. Read this before changing anything below.
 *
 *   CspEvaluator.evaluate(parsedCspChecks?, effectiveCspChecks?)
 *
 * The FIRST argument ADDS checks. Only the SECOND replaces `DEFAULT_CHECKS`.
 * So `evaluate(CURATED)` leaves the default list running — and measured against
 * `csp_evaluator@1.1.8`, the default list produces two findings on the spec's
 * MANDATED default policy:
 *
 *   severity 10 (HIGH)   type 301  script-src 'unsafe-inline'
 *   severity 50 (MEDIUM) type 305  script-src 'self'
 *
 * `'unsafe-inline'` is MANDATED by SEP-1865 because raw HTML resources have no
 * build step (SPEC-REFERENCE.md §3.1), and `checkScriptAllowlistBypass`
 * unconditionally flags any `'self'` in `script-src`, which the mandated policy
 * contains. Either finding fires on every conformant server in the ecosystem.
 * That is the fatal false positive GOALS.md G2 rates "Fatal", delivered by the
 * dependency adopted to prevent it.
 *
 * The correct call is `evaluate(undefined, CURATED_CHECKS)`.
 * test/rules-csp.test.ts asserts both halves: that the wrong call produces two
 * findings, and that the right one produces zero.
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Two further constraints, both from DESIGN.md §3.3:
 *
 * - `csp_evaluator` **cannot** implement PANE-CSP-001/002/003. Its wildcard and
 *   bypass checks iterate `DIRECTIVES_CAUSING_XSS` only — `connect-src` and
 *   `frame-src` are absent, so `connectDomains: ["*"]` produces zero findings
 *   from it. Those rules are Panelint's own code, in `domains.ts`.
 * - It takes a serialized policy **string** and Panelint holds four arrays, so
 *   the policy has to be SYNTHESIZED. The exact policy a host builds from a
 *   non-empty `_meta.ui.csp` is not specified anywhere. That synthesis is an
 *   ASSUMPTION, and `CSP_SYNTHESIS_ASSUMPTION` is attached to every finding in
 *   this family rather than presenting it as a fact about the host.
 *
 * PANE-CSP-007 deep-imports the JSONP and Angular allowlist DATA rather than
 * calling the check that wraps them, so a finding about `resourceDomains` does
 * not carry a description that says "script-src".
 */

import { CspParser } from 'csp_evaluator/dist/parser.js';
import { CspEvaluator } from 'csp_evaluator/dist/evaluator.js';
import {
  checkSrcHttp,
  checkIpSource,
  checkPlainUrlSchemes,
} from 'csp_evaluator/dist/checks/security_checks.js';
import { Type as CspFindingType, type Finding as CspFinding } from 'csp_evaluator/dist/finding.js';
import { URLS as JSONP_BYPASS_URLS } from 'csp_evaluator/dist/allowlist_bypasses/jsonp.js';
import { URLS as ANGULAR_BYPASS_URLS } from 'csp_evaluator/dist/allowlist_bypasses/angular.js';
import { matchWildcardUrls } from 'csp_evaluator/dist/utils.js';

import type { UIResourceCsp } from '../../types.js';
import { RESOURCE_DOMAIN_DIRECTIVES } from '../../parse/meta.js';
import { CSP_ARRAYS, entriesOf, type CspArrayName, type DomainEntry } from './domains.js';

type CheckerFunction = (csp: never) => CspFinding[];

/**
 * The only checks Panelint runs.
 *
 * Measured: zero findings on the mandated default policy AND on the policy
 * constructed from an empty `csp`. Adding a check to this list requires a
 * reference-corpus run — see CONTRIBUTING.md.
 */
export const CURATED_CHECKS: readonly CheckerFunction[] = Object.freeze([
  checkSrcHttp,
  checkIpSource,
  checkPlainUrlSchemes,
] as unknown as CheckerFunction[]);

/**
 * Checks that fire on conformant code. Never add these back.
 *
 * The guard below is a hard failure at module load rather than a comment,
 * because "no rule may flag `'unsafe-inline'`" is the single most likely way to
 * ship a scanner that is instantly discredited (SPEC-REFERENCE.md §3.1).
 */
export const FORBIDDEN_CHECKS: readonly string[] = Object.freeze([
  'checkScriptUnsafeInline',
  'checkScriptAllowlistBypass',
  'checkWildcards',
  'checkMissingDirectives',
]);

for (const check of CURATED_CHECKS) {
  if (FORBIDDEN_CHECKS.includes(check.name)) {
    throw new Error(
      `csp_evaluator check ${check.name} fires on the spec-mandated default policy and ` +
        'must never be in CURATED_CHECKS. See docs/DESIGN.md §3.3.',
    );
  }
}

/**
 * Finding types that describe the mandated policy rather than a server's choice.
 *
 * Belt and braces over the curated list: even if a future `csp_evaluator`
 * release moved one of these into `checkSrcHttp`, it could not reach a report.
 */
const FORBIDDEN_FINDING_TYPES: ReadonlySet<number> = new Set<number>([
  CspFindingType.SCRIPT_UNSAFE_INLINE,
  CspFindingType.STYLE_UNSAFE_INLINE,
  CspFindingType.SCRIPT_UNSAFE_HASHES,
  CspFindingType.SCRIPT_ALLOWLIST_BYPASS,
]);

// ---------------------------------------------------------------------------
// Policy synthesis
// ---------------------------------------------------------------------------

/**
 * The restrictive default, applied when `ui.csp` is omitted.
 *
 * Verbatim from `apps.mdx` L275–284 via SPEC-REFERENCE.md §3.1. Note what is
 * absent: `form-action`, `base-uri` and `object-src`. See RULES.md § PANE-EXFIL.
 */
export const MANDATED_DEFAULT_POLICY =
  "default-src 'none'; " +
  "script-src 'self' 'unsafe-inline'; " +
  "style-src 'self' 'unsafe-inline'; " +
  "img-src 'self' data:; " +
  "media-src 'self' data:; " +
  "connect-src 'none';";

/** Which `_meta.ui.csp` array feeds which directive, and what the base sources are. */
const CONSTRUCTION: ReadonlyArray<{
  directive: string;
  base: string[];
  from?: CspArrayName;
  /** Used when `from` is absent or empty. */
  fallback?: string[];
}> = Object.freeze([
  { directive: 'default-src', base: ["'none'"] },
  { directive: 'script-src', base: ["'self'", "'unsafe-inline'"], from: 'resourceDomains' },
  { directive: 'style-src', base: ["'self'", "'unsafe-inline'"], from: 'resourceDomains' },
  { directive: 'connect-src', base: ["'self'"], from: 'connectDomains' },
  { directive: 'img-src', base: ["'self'", 'data:'], from: 'resourceDomains' },
  { directive: 'font-src', base: ["'self'"], from: 'resourceDomains' },
  { directive: 'media-src', base: ["'self'", 'data:'], from: 'resourceDomains' },
  { directive: 'frame-src', base: [], from: 'frameDomains', fallback: ["'none'"] },
  { directive: 'object-src', base: ["'none'"] },
  { directive: 'base-uri', base: [], from: 'baseUriDomains', fallback: ["'self'"] },
]);

export interface SynthesizedPolicy {
  policy: string;
  /**
   * directive → the declared entries that contributed to it.
   *
   * This is what makes the fan-out collapsible: `resourceDomains` feeds five
   * directives, so one declared domain produces up to five raw findings that
   * have to collapse back to `(array, index)`.
   */
  provenance: ReadonlyMap<string, DomainEntry[]>;
}

/**
 * Build the policy a host would construct.
 *
 * `apps.mdx` L1733–1744, restated in RULES.md § The finding that reorganized
 * this catalog. `form-action` is deliberately NOT synthesized: it appears zero
 * times in the entire ext-apps repository, and inventing it here would hide the
 * gap the PANE-EXFIL family exists to report.
 */
export function synthesizePolicy(csp: UIResourceCsp | null | undefined): SynthesizedPolicy {
  if (csp === null || csp === undefined) {
    return { policy: MANDATED_DEFAULT_POLICY, provenance: new Map() };
  }

  const provenance = new Map<string, DomainEntry[]>();
  const parts: string[] = [];

  for (const rule of CONSTRUCTION) {
    const contributed = rule.from ? entriesOf(csp, rule.from) : [];
    const values = [...rule.base, ...contributed.map((e) => e.value)];
    if (values.length === 0 && rule.fallback) values.push(...rule.fallback);
    if (contributed.length > 0) provenance.set(rule.directive, contributed);
    parts.push(`${rule.directive} ${values.join(' ')}`.trim());
  }

  return { policy: `${parts.join('; ')};`, provenance };
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

export interface CollapsedFinding {
  array: CspArrayName;
  index: number;
  value: string;
  /** `csp_evaluator`'s numeric `Type`. */
  type: number;
  /** Every directive the raw findings arrived on, for evidence. */
  directives: string[];
}

export interface AdapterResult {
  policy: string;
  /** Raw `csp_evaluator` findings, after the forbidden-type filter. */
  raw: CspFinding[];
  /** Collapsed back to `(array, index)` — one per declared entry per finding type. */
  collapsed: CollapsedFinding[];
}

/**
 * Run the curated checks over the synthesized policy.
 *
 * Note which of the three curated checks currently has a consuming rule:
 * `checkPlainUrlSchemes` corroborates PANE-CSP-002/004 (a bare scheme in
 * `script-src` / `base-uri`). `checkSrcHttp` and `checkIpSource` have no owning
 * rule ID in the PANE-CSP table — an `http://` origin or a raw IP source is a
 * malformed-origin observation, whose natural home is `PANE-SCHEMA-003`. They
 * are surfaced here rather than dropped, but no PANE-CSP rule reports them, and
 * inventing a fourteenth ID for them would violate the rule-ID contract.
 */
export function evaluateDeclaredCsp(csp: UIResourceCsp | null | undefined): AdapterResult {
  const { policy, provenance } = synthesizePolicy(csp);

  let raw: CspFinding[] = [];
  try {
    const parsed = new CspParser(policy).csp;
    // The second argument REPLACES DEFAULT_CHECKS. The first would merely add.
    raw = new CspEvaluator(parsed).evaluate(undefined, CURATED_CHECKS as never);
  } catch {
    // A policy string Panelint synthesized should always parse, but a hostile
    // domain entry could still surprise the parser. Declining is correct;
    // throwing out of a rule is not.
    return { policy, raw: [], collapsed: [] };
  }

  raw = raw.filter((f) => !FORBIDDEN_FINDING_TYPES.has(f.type as number));

  const byEntry = new Map<string, CollapsedFinding>();
  for (const finding of raw) {
    const contributors = provenance.get(finding.directive) ?? [];
    const value = (finding.value ?? '').trim().toLowerCase();
    for (const entry of contributors) {
      if (entry.value.trim().toLowerCase() !== value) continue;
      const key = `${entry.array} ${entry.index} ${finding.type}`;
      const existing = byEntry.get(key);
      if (existing) {
        if (!existing.directives.includes(finding.directive)) existing.directives.push(finding.directive);
      } else {
        byEntry.set(key, {
          array: entry.array,
          index: entry.index,
          value: entry.value,
          type: finding.type as number,
          directives: [finding.directive],
        });
      }
    }
  }

  return { policy, raw, collapsed: [...byEntry.values()] };
}

/** Collapsed findings of one type, for one array. */
export function collapsedOfType(
  result: AdapterResult,
  array: CspArrayName,
  type: number,
): CollapsedFinding[] {
  return result.collapsed.filter((c) => c.array === array && c.type === type);
}

export { CspFindingType };

/** The five directives one `resourceDomains` entry opens. Re-exported for messages. */
export const RESOURCE_FAN_OUT: readonly string[] = RESOURCE_DOMAIN_DIRECTIVES;

/** Every array name, so a caller does not re-derive the list. */
export const ALL_CSP_ARRAYS = CSP_ARRAYS;

// ---------------------------------------------------------------------------
// Allowlist bypass data — PANE-CSP-007
// ---------------------------------------------------------------------------

/**
 * Match a declared source expression against a bypass allowlist.
 *
 * `matchWildcardUrls` substitutes a placeholder label for `*` and then parses
 * with `new URL()`, so a scheme-free or malformed entry throws. Declining on a
 * throw is correct: PANE-CSP-007 is `MEDIUM` confidence and must not become a
 * crash vector for a hostile `_meta`.
 */
function matchBypassList(source: string, list: readonly string[]): string | null {
  const trimmed = String(source ?? '').trim();
  if (!trimmed || trimmed.startsWith("'")) return null;
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) || trimmed.startsWith('//')
    ? trimmed
    : `https://${trimmed}`;
  try {
    const hit = matchWildcardUrls(withScheme, list as string[]);
    return hit ? hit.href : null;
  } catch {
    return null;
  }
}

/** A known JSONP endpoint reachable through this source expression, or null. */
export function jsonpBypassFor(source: string): string | null {
  return matchBypassList(source, JSONP_BYPASS_URLS);
}

/** A known hosted AngularJS copy reachable through this source expression, or null. */
export function angularBypassFor(source: string): string | null {
  return matchBypassList(source, ANGULAR_BYPASS_URLS);
}

export { JSONP_BYPASS_URLS, ANGULAR_BYPASS_URLS };

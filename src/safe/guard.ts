/**
 * Containment for third-party calls that recurse, and pre-parse input gates.
 *
 * Measured against the pinned versions, all four of these crash or hang on
 * input a hostile repo can trivially produce:
 *
 *   parse5 on nested <div>s      25 KB → 67 ms · 100 KB → 982 ms · 200 KB → 3.9 s
 *                                 Cost is O(depth²), not O(bytes). The 8 MB byte
 *                                 cap and the 100 k node cap both pass.
 *   acorn-walk on `a+a+a…`×5000  RangeError (acorn itself parses it fine)
 *   domutils.textContent          RangeError on a deep tree
 *   css-select compile on
 *     :not(:not(:not(…)))×5000    RangeError — one rule, one selector, so the
 *                                 20 k CSS-rule cap never fires
 *
 * Two consequences drive this file:
 *
 *   1. `maxNestingDepth` CANNOT be enforced after parsing, because the crash
 *      and the cost both happen during the parse. It has to be estimated from
 *      the raw bytes first. That is `estimateNestingDepth`.
 *
 *   2. A `RangeError` escaping to the top level is a truncated report at best.
 *      Every third-party call that recurses goes through `contained`.
 *
 * Panelint's own traversals are iterative with an explicit stack (see
 * parse/html.ts). One recursive helper reintroduces the crash, so that is a
 * hard rule rather than a preference.
 */

import type { ScanDiagnostic } from '../types.js';

export type Contained<T> = { ok: true; value: T } | { ok: false; reason: 'RANGE_ERROR' | 'THREW' };

/**
 * Run a third-party call that may recurse without bound.
 *
 * A RangeError becomes a result, not an exception. Any other throw is also
 * contained — a rule that cannot evaluate must degrade to "undecided", never
 * take the scan down with it.
 */
export function contained<T>(fn: () => T): Contained<T> {
  try {
    return { ok: true, value: fn() };
  } catch (e) {
    if (e instanceof RangeError) return { ok: false, reason: 'RANGE_ERROR' };
    return { ok: false, reason: 'THREW' };
  }
}

/** `contained`, with a fallback value instead of a result object. */
export function containedOr<T>(fn: () => T, fallback: T): T {
  const r = contained(fn);
  return r.ok ? r.value : fallback;
}

export function limitDiagnostic(
  what: string,
  detail: string,
  resourceUri?: string,
): ScanDiagnostic {
  return {
    code: 'LIMIT_EXCEEDED',
    message: `${what} exceeded a safety ceiling; analysis of this input is incomplete.`,
    ...(resourceUri ? { resourceUri } : {}),
    detail,
  };
}

/** HTML elements that never open a nesting level. */
const VOID_ELEMENTS = new Set([
  'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link',
  'meta', 'param', 'source', 'track', 'wbr',
]);

/**
 * Estimate maximum tag nesting depth from raw bytes, before parse5 sees them.
 *
 * This is deliberately an over-approximation done with a cheap scan: it counts
 * opening tags that are not void and not self-closing, and decrements on
 * closing tags. It does not model implied end tags, so a document full of
 * unclosed `<p>` reads deeper than it parses. That direction is the safe one —
 * refusing a pathological input costs a diagnostic, while accepting it costs
 * seconds of CPU per resource and, at depth, a crash inside a dependency.
 */
export function estimateNestingDepth(html: string, ceiling: number): { depth: number; exceeded: boolean } {
  let depth = 0;
  let max = 0;
  // The attribute body is bounded. Unbounded `[^>]*` before a required `>`
  // rescans to end-of-string at every `<` when no `>` follows, and every one of
  // those scans fails — clean O(n²) in the one function that runs BEFORE every
  // other control, on raw attacker bytes, synchronously, with no deadline.
  //
  // Measured on `"<a".repeat(n)`: 100 KB → 2.3 s, 200 KB → 8.7 s, 400 KB → 38 s.
  // At the 8 MB maxResourceBytes ceiling that is roughly four hours for a single
  // resource, and the depth early-out never fires because no tag ever completes.
  // A tag whose attributes exceed this bound is not a tag worth counting.
  const tagRe = /<\s*(\/?)\s*([a-zA-Z][a-zA-Z0-9-]*)([^>]{0,4096})>/g;

  let m: RegExpExecArray | null;
  while ((m = tagRe.exec(html)) !== null) {
    const closing = m[1] === '/';
    const name = m[2]!.toLowerCase();
    const rest = m[3] ?? '';

    if (closing) {
      if (depth > 0) depth--;
      continue;
    }
    if (VOID_ELEMENTS.has(name) || rest.trimEnd().endsWith('/')) continue;

    depth++;
    if (depth > max) {
      max = depth;
      // Bail out as soon as the answer is decided. On a 200 KB bomb this
      // returns in microseconds instead of scanning the whole string.
      if (max > ceiling) return { depth: max, exceeded: true };
    }
  }

  return { depth: max, exceeded: max > ceiling };
}

/**
 * Reject a selector that is cheap to write and expensive to compile.
 *
 * `:not(:not(:not(…)))` nested 5000 deep is a single rule with a single
 * selector, so neither the CSS-rule cap nor the node count sees it, and
 * css-select blows the stack while compiling. `:has()` is a separate problem:
 * it makes matching O(subtree) per candidate node, which the `rules × nodes`
 * cost model underestimates — that one is handled by spending the match budget
 * inside the match loop rather than by precomputing a product.
 */
export const MAX_SELECTOR_LENGTH = 2_000;
export const MAX_SELECTOR_FUNCTIONAL_DEPTH = 16;

export function selectorIsTractable(selector: string): boolean {
  if (selector.length > MAX_SELECTOR_LENGTH) return false;

  let depth = 0;
  let max = 0;
  for (const ch of selector) {
    if (ch === '(') {
      depth++;
      if (depth > max) max = depth;
      if (max > MAX_SELECTOR_FUNCTIONAL_DEPTH) return false;
    } else if (ch === ')') {
      if (depth > 0) depth--;
    }
  }
  return true;
}

/**
 * Strict base64 validation.
 *
 * `Buffer.from(s, 'base64')` silently ignores invalid characters, accepts the
 * URL-safe alphabet, and tolerates missing padding — so two distinct `blob`
 * strings can decode to identical bytes and produce an identical contentHash.
 * That hash is what the drift re-scan uses to conclude "nothing changed", so
 * the ambiguity is not acceptable in the one field the census keys on.
 */
export function isStrictBase64(s: string): boolean {
  if (s.length % 4 !== 0) return false;
  return /^[A-Za-z0-9+/]*={0,2}$/.test(s);
}

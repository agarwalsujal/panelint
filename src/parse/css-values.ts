/**
 * Declared values that do not say what they mean.
 *
 * Every carrier in `rules/shared/carriers.ts` reads a declared string and
 * compares it to a literal — `display` to `none`, `opacity` to a number. A
 * value written through a substitution function matches none of those literals,
 * so `opacity:var(--o)` produced NO carrier at all, with `:root{--o:0}` two
 * lines above it. Every engine has substituted custom properties at
 * computed-value time since 2016. Measured before this module existed: three
 * gate-eligible findings went to zero at exit 0, with no diagnostic and
 * `undecided: 0`.
 *
 * "The value is written indirectly" is not "there is no such declaration", and
 * the difference between those two readings is a gate bypass the scanned party
 * chooses.
 *
 * ## Additive, like everything else that reads the cascade
 *
 * `style-index.ts` returns EVERY declaration of a property, winner or not,
 * because resolution is additive-only: a declaration that lost the cascade may
 * still raise a finding and must never suppress one. That is what keeps
 * `@layer` from being a one-line evasion of the whole PANE-HIDDEN family.
 *
 * The first version of this module broke that. It collapsed the candidate set
 * to ONE value — the last that happened to resolve — with no specificity, no
 * `!important`, and no layer ordering. Three evasions came straight back
 * (`#a{--o:0}.x{--o:1}`, `!important` inversion, `@layer` reordering), and the
 * mirror case invented a finding on conformant code. So this returns the SET of
 * values a custom property could take, and a carrier fires if ANY member
 * matches. Over-reporting here is bounded by the same scaling the family
 * already applies; under-reporting is a silent pass.
 *
 * It is deliberately NOT a CSS value evaluator. `calc()` arithmetic, `env()`,
 * `attr()` and the comparison functions are reported as unevaluable rather than
 * guessed at.
 */

import type { Element } from 'domhandler';
import type { StyleIndexLike } from '../types.js';

/**
 * A value function that defers the real value.
 *
 * The leading `(?:^|[^\w-])` keeps `--my-var-calc: 0` and property names ending
 * in one of these words from matching. A backslash anywhere is treated as
 * deferral too: `\76 ar(--o)` is the ident `var` to a CSS tokenizer, and
 * un-escaping identifiers here to find out is not worth it — "cannot read this"
 * is the safe answer and the caller turns it into an undecided node.
 */
const SUBSTITUTION_FN = /(?:^|[^\w-])(?:var|calc|env|attr|min|max|clamp)\s*\(|\\/i;

/** `var(--name)` or `var(--name, fallback)` as the ENTIRE value. */
const VAR_ONLY = /^var\(\s*(--[\w-]+)\s*(?:,([\s\S]*))?\)$/i;

/** Depth cap for `var(--a)` → `var(--b)` → … chains, including cycles. */
const MAX_DEPTH = 8;

/**
 * Total candidate expansions per top-level resolution.
 *
 * Without it the walk is `candidates ^ depth`: a file declaring one custom
 * property 14 times, at 1.9 KB, took **137 seconds** and blew through
 * `perResourceMs` 27 times over — the cooperative deadline cannot interrupt a
 * synchronous recursion, which is the same class of defect the `:has()` cost
 * model exists to refuse before the first call.
 */
const MAX_STEPS = 2_000;

/** Distinct values one property is allowed to resolve to before we stop. */
const MAX_RESULTS = 8;

export function hasSubstitution(value: string): boolean {
  return SUBSTITUTION_FN.test(value);
}

/** Strip CSS comments, which are removed at tokenization. `var(/**\/--o)`. */
function stripComments(value: string): string {
  return value.includes('/*') ? value.replace(/\/\*[\s\S]*?\*\//g, '') : value;
}

function parentElement(el: Element): Element | null {
  const p = (el as unknown as { parent?: unknown }).parent as Element | undefined;
  return p && typeof (p as { tagName?: string }).tagName === 'string' ? p : null;
}

interface Walk {
  steps: number;
}

/**
 * Every literal a declared value could resolve to.
 *
 * An empty array means unevaluable — an unknown variable with no fallback, a
 * cycle, arithmetic, or a budget stop — and every caller must treat that as
 * "undecided", never as "no such value".
 */
export function resolveDeclaredValues(
  el: Element,
  styles: StyleIndexLike,
  raw: string,
  depth = 0,
  walk: Walk = { steps: 0 },
): string[] {
  const value = stripComments(raw).trim();
  if (!hasSubstitution(value)) return [value];
  if (depth >= MAX_DEPTH) return [];

  const m = VAR_ONLY.exec(value);
  if (!m) return [];

  const name = m[1]!;
  const fallback = m[2];

  const out: string[] = [];
  const seen = new Set<string>();
  const take = (v: string): void => {
    if (seen.has(v)) return;
    seen.add(v);
    out.push(v);
  };

  // EVERY candidate on EVERY ancestor. Custom properties inherit, and the
  // hostile pattern declares them on `:root`, so this walks up rather than
  // asking about the node alone.
  for (let node: Element | null = el; node; node = parentElement(node)) {
    for (const d of styles.candidatesFor(node, name)) {
      if (++walk.steps > MAX_STEPS) return out;
      for (const r of resolveDeclaredValues(el, styles, d.value, depth + 1, walk)) {
        take(r);
        if (out.length >= MAX_RESULTS) return out;
      }
    }
  }

  // A fallback is only used when the property resolves to nothing at all,
  // which is what the CSS spec says and what a browser does.
  if (out.length === 0 && fallback !== undefined) {
    for (const r of resolveDeclaredValues(el, styles, fallback, depth + 1, walk)) take(r);
  }
  return out;
}

/** Single-value convenience for callers that only need "did this reduce?". */
export function resolveDeclaredValue(
  el: Element,
  styles: StyleIndexLike,
  raw: string,
): string | null {
  const all = resolveDeclaredValues(el, styles, raw);
  return all.length > 0 ? all[0]! : null;
}

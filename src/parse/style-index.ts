/**
 * CSS → a node-indexed style index.
 *
 * The missing middle in the v1 design: parse5 gives a tree with no querying,
 * postcss gives declarations with no selector matching. Three stages —
 *
 *   1. Collect  — <style> blocks and style= attributes into postcss roots.
 *   2. Classify — postcss-selector-parser drops pseudo-elements and marks
 *                 stateful pseudo-classes non-applying. An unsupported selector
 *                 is skipped, never fatal.
 *   3. Match    — css-select binds selectors to nodes; conflicts resolve by
 *                 (origin, !important, specificity, source order).
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * ⚠ Resolution may RAISE a finding. It may never SUPPRESS one.
 *
 * The moment stage 3 can decide a declaration *loses*, every gap in the cascade
 * model becomes a bypass the attacker gets to pick. `@layer` is the cheapest one:
 *
 *     @layer a, b;
 *     @layer b { .x { opacity: 0 } }
 *     @layer a { .x { opacity: 1 } }
 *
 * Layer order outranks source order, and inside a layer `!important` inverts
 * layer precedence. A resolver ordering by (origin, !important, specificity,
 * source order) concludes opacity:1, reports nothing, and the browser renders
 * the text invisible. @scope, @supports, @container and revert-layer each reach
 * the same result by a different route.
 *
 * So the API is split in two, and the split is load-bearing:
 *
 *   declaredStyle(node)        the resolved winner. For evidence, and for rules
 *                              that genuinely need "the" value (PANE-OVERLAY's
 *                              z-index). Never use it to decide something is
 *                              NOT hidden.
 *   candidatesFor(node, prop)  EVERY declaration that applies, winner or not.
 *                              This is what the PANE-HIDDEN family asks, and
 *                              asking it is why @layer cannot evade the family.
 *
 * A cascade gap then costs a missed detection rather than a targeted evasion —
 * and by SECURITY.md §1 the second is a reportable vulnerability in Panelint,
 * not a documented limitation.
 * ─────────────────────────────────────────────────────────────────────────────
 */

import postcss, { type Root, type Rule as PostcssRule, type Declaration, type AtRule } from 'postcss';
import selectorParser from 'postcss-selector-parser';
import { selectorSpecificity } from '@csstools/selector-specificity';
import { is as cssIs } from 'css-select';
import { Element, type Document, type AnyNode } from 'domhandler';
import { allElements, attr, attrLocations, selectAll } from './html.js';
import { selectorIsTractable } from '../safe/guard.js';
import { checkLimit, Budget } from '../limits.js';
import type { DeclaredValue, Limits, ScanDiagnostic, SourceLocation, StyleIndexLike } from '../types.js';

/**
 * At-rules whose effect on the cascade this resolver does NOT model.
 *
 * A node reached only through one of these is marked undecided. Undecided is
 * not clean — it is counted in diagnostics and surfaced in the report footer.
 *
 * `@media` and `@supports` differ here: a `@media` block's declarations apply in
 * some viewport, which is a state we are willing to treat as applying. A
 * `@supports` block's applicability depends on the engine, and its ordering
 * interacts with layers, so it is not modelled.
 */
const UNMODELLED_AT_RULES = new Set(['layer', 'scope', 'container', 'supports']);

/**
 * Pseudo-classes css-select answers, and answers DIFFERENTLY from a browser.
 *
 * The dangerous case is not the selector that throws — a throw is caught and
 * reported. It is the selector css-select evaluates confidently and gets wrong,
 * because nothing anywhere signals a problem.
 *
 * `:read-write` is the measured one. Selectors 4 defines it as matching any
 * element that is user-alterable, so a plain `<input>` with neither `readonly`
 * nor `disabled` matches in every browser. css-select returns false. That makes
 *
 *     <style>.s:read-write{opacity:0}</style>
 *     <input class="s" autocomplete="cc-number">
 *
 * a hidden autofill target that binds no declaration at all — PANE-INPUT-001
 * (CRITICAL, gate-eligible) never fires, exit 0, and unlike the `:defined`
 * case there is no exception to catch.
 *
 * A selector using one of these is treated as unevaluable rather than trusted.
 */
const MISMODELLED_PSEUDO = new Set(['read-write', 'read-only']);

/** Pseudo-classes describing a transient state, not the resting render. */
const STATEFUL_PSEUDO = new Set([
  'hover',
  'focus',
  'focus-visible',
  'focus-within',
  'active',
  'visited',
  'target',
  'checked',
  'default',
  'indeterminate',
  'placeholder-shown',
  'autofill',
  'user-invalid',
]);

interface StyleRule {
  selector: string;
  /** css-select-safe form of the selector, pseudo-elements stripped. */
  matchSelector: string;
  decls: Array<{ prop: string; value: string; important: boolean; location?: SourceLocation }>;
  specificity: { a: number; b: number; c: number };
  order: number;
  /** Names of unmodelled at-rules this rule sits inside. */
  unmodelledAtRules: string[];
}

export interface StyleIndex extends StyleIndexLike {
  diagnostics: ScanDiagnostic[];
}

export function buildStyleIndex(dom: Document, limits: Limits, resourceUri?: string): StyleIndex {
  const diagnostics: ScanDiagnostic[] = [];
  const rules: StyleRule[] = [];
  const undecidedReasonSet = new Set<string>();
  /** Selectors postcss-selector-parser could not parse. Surfaced in stage 3. */
  const unparsedSelectors: Array<{ selector: string; why: string }> = [];
  let order = 0;
  let truncated = false;

  // ── Stage 1: collect ────────────────────────────────────────────────────
  for (const styleEl of selectAll('style', dom)) {
    const css = styleEl.children
      .map((c) => (c.type === 'text' ? (c as unknown as { data: string }).data : ''))
      .join('');
    if (!css.trim()) continue;

    let root: Root;
    try {
      root = postcss.parse(css);
    } catch {
      // A stylesheet that does not parse is a diagnostic, not a crash. The
      // browser will do its own error recovery; we simply cannot model it.
      diagnostics.push({
        code: 'PARSE_FAILED',
        message: 'A <style> block could not be parsed; its declarations are not bound to nodes.',
        ...(resourceUri ? { resourceUri } : {}),
      });
      continue;
    }

    const baseLine = styleEl.sourceCodeLocation?.startTag?.endLine ?? 1;

    walkRules(root, [], (rule, atRuleStack, composedSelector) => {
      if (truncated) return;
      if (rules.length >= limits.maxCssRules) {
        if (!truncated) {
          truncated = true;
          const d = checkLimit('maxCssRules', rules.length + 1, limits, resourceUri);
          if (d) diagnostics.push(d);
        }
        return;
      }

      const unmodelled = atRuleStack.filter((n) => UNMODELLED_AT_RULES.has(n));
      for (const name of unmodelled) {
        undecidedReasonSet.add(
          `@${name} affects cascade order in a way this resolver does not model; ` +
            'affected nodes are marked undecided.',
        );
      }

      const decls: StyleRule['decls'] = [];
      rule.each((node) => {
        if (node.type !== 'decl') return;
        const d = node as Declaration;
        decls.push({
          prop: d.prop.toLowerCase().trim(),
          value: d.value.trim(),
          important: Boolean(d.important),
          location: declLocation(d, baseLine),
        });
      });
      if (decls.length === 0) return;

      // ── Stage 2: classify ────────────────────────────────────────────────
      // The COMPOSED selector, not `rule.selector` — for a nested rule those
      // differ, and using the raw one binds `.s` where the sheet said `body .s`.
      for (const single of splitSelectorList(composedSelector)) {
        const classified = classifySelector(single);
        // A selector that failed to PARSE is not a selector that does not
        // apply. Stage 3 never sees it, so it is recorded here or nowhere.
        if (classified.failed) {
          unparsedSelectors.push({
            selector: single,
            why: classified.mismodelled
              ? `css-select models :${classified.mismodelled} differently from a browser`
              : 'the selector parser could not read it',
          });
        }
        if (!classified.applies) continue;
        rules.push({
          selector: single,
          matchSelector: classified.matchSelector,
          decls,
          specificity: classified.specificity,
          order: order++,
          unmodelledAtRules: unmodelled,
        });
      }
    });
  }

  // ── Stage 3: match ──────────────────────────────────────────────────────
  const budget = new Budget(limits.selectorMatchBudget);
  const byNode = new Map<Element, DeclaredValue[]>();
  const undecidedNodes = new Set<Element>();
  const elements = allElements(dom);
  const sizes = subtreeSizes(elements);
  let maxSubtree = 1;
  for (const s of sizes.values()) if (s > maxSubtree) maxSubtree = s;

  /**
   * Every declaration this selector carries is now missing from
   * `candidatesFor`, and no cheap analysis says which nodes it would have
   * matched. Per this file's doctrine a cascade gap must cost a missed
   * detection rather than a targeted evasion, so the whole document goes
   * undecided rather than silently reading as "no such declaration".
   */
  function skipSelector(selector: string, why: string): void {
    for (const el of elements) undecidedNodes.add(el);
    undecidedReasonSet.add(
      `a selector was not matched (${why}), so declarations it carries are absent from the cascade`,
    );
    diagnostics.push({
      code: 'SELECTOR_SKIPPED',
      message: `Selector skipped (${why}); CSS-dependent rules see an incomplete cascade.`,
      ...(resourceUri ? { resourceUri } : {}),
      detail:
        `Selector: ${selector.slice(0, 120)}${selector.length > 120 ? '…' : ''}. ` +
        'Every node is marked undecided, because which nodes it would have matched is unknown.',
    });
  }

  // Stage 2 could not report these: `elements` did not exist yet.
  for (const { selector, why } of unparsedSelectors) skipSelector(selector, why);

  for (const rule of rules) {
    // `selectorIsTractable` shipped from 0.1.0 with ZERO call sites. It is the
    // gate for `:not(:not(…))`-style selectors that are cheap to write and blow
    // the stack inside css-select while compiling — one rule, one selector, so
    // neither the CSS-rule cap nor the node count ever sees them.
    if (!selectorIsTractable(rule.matchSelector)) {
      skipSelector(rule.matchSelector, 'too long or too deeply nested to compile safely');
      continue;
    }

    // ── The cost model ────────────────────────────────────────────────────
    // Refused BEFORE the first call, not billed after it: one `cssIs` call on
    // the measured bomb took 12.7 s on its own, so nothing checked between
    // calls can bound this.
    const hasDepth = hasDescendantDepth(rule.matchSelector);
    if (hasDepth > 0) {
      const worst = selectorCost(maxSubtree, hasDepth) * Math.max(1, elements.length);
      if (worst > limits.selectorMatchBudget) {
        skipSelector(
          rule.matchSelector,
          `matching it against this document could cost ~${worst.toExponential(1)} units, over the ` +
            'selector-match budget',
        );
        continue;
      }
    }

    let threw = false;
    for (const el of elements) {
      budget.spend(selectorCost(sizes.get(el) ?? 1, hasDepth));
      if (budget.exhausted) break;
      let matches = false;
      try {
        matches = cssIs(el as AnyNode, rule.matchSelector);
      } catch {
        // An unsupported selector is skipped, never fatal — but never silently
        // either. Swallowing this made unmodellable CSS read as no CSS, which
        // is the benign-looking direction and the one an attacker chooses.
        threw = true;
        break;
      }
      if (!matches) continue;

      if (rule.unmodelledAtRules.length > 0) undecidedNodes.add(el);

      const bucket = byNode.get(el) ?? [];
      for (const d of rule.decls) {
        bucket.push({
          value: d.value,
          important: d.important,
          origin: 'sheet',
          ...(d.location ? { location: d.location } : {}),
          selector: rule.selector,
          // Carried privately for resolution; not part of DeclaredValue.
          ...({ __prop: d.prop, __spec: rule.specificity, __order: rule.order } as object),
        } as DeclaredValue);
      }
      byNode.set(el, bucket);
    }

    if (threw) skipSelector(rule.matchSelector, 'css-select could not evaluate it');
    if (budget.exhausted) break;
  }

  if (budget.exhausted) {
    const d = checkLimit('selectorMatchBudget', budget.used, limits, resourceUri);
    if (d) diagnostics.push(d);
    // The budget stopping the match loop leaves every remaining rule unmatched.
    // Without this the index reports a complete cascade built from a prefix of
    // the stylesheet, which is a rule-suppression primitive: an attacker front-
    // loads expensive selectors and the declaration that would have been found
    // is simply never looked at.
    for (const el of elements) undecidedNodes.add(el);
    undecidedReasonSet.add(
      'the selector-match budget was exhausted, so an unknown suffix of the stylesheet never matched',
    );
  }

  // Inline style= attributes. Highest origin precedence, always applying.
  for (const el of elements) {
    const inline = attr(el, 'style');
    if (!inline) continue;
    let root: Root;
    try {
      root = postcss.parse(`*{${inline}}`);
    } catch {
      // ── Why this is not a `continue` ──────────────────────────────────────
      // CSS Syntax 3 §4.3.2 ends an unterminated comment at EOF, and an
      // unterminated string at EOF is a parse error that still returns the
      // string token — so a browser APPLIES the declarations that precede the
      // break. postcss throws instead, and swallowing that made
      //
      //     <input autocomplete="cc-number" style="opacity:0;/*">
      //
      // read as an element with no inline style at all: PANE-INPUT-001
      // (CRITICAL, gate-eligible) did not fire, exit 0, no diagnostic.
      //
      // Recovery re-parses the prefix up to the last complete declaration,
      // which is what the browser keeps. Binding those is widening, and
      // widening is safe here by this module's design: `candidatesFor` is
      // additive, so a recovered declaration can raise a finding and can never
      // suppress one. The node is marked undecided either way, because what
      // follows the break was not modelled.
      const cut = inline.lastIndexOf(';');
      let recovered: Root | null = null;
      if (cut > 0) {
        try {
          recovered = postcss.parse(`*{${inline.slice(0, cut)}}`);
        } catch {
          recovered = null;
        }
      }

      undecidedNodes.add(el);
      undecidedReasonSet.add(
        'an inline `style=` attribute could not be fully parsed, so declarations after the ' +
          'break are absent from the cascade',
      );
      diagnostics.push({
        code: 'PARSE_FAILED',
        message: recovered
          ? 'An inline `style=` attribute was truncated by a parse error; the declarations before ' +
            'it were recovered and the node is undecided.'
          : 'An inline `style=` attribute could not be parsed; the node is undecided.',
        ...(resourceUri ? { resourceUri } : {}),
      });

      if (!recovered) continue;
      root = recovered;
    }
    const loc = attrLocations(el)?.['style'];
    const bucket = byNode.get(el) ?? [];
    root.walkDecls((d) => {
      bucket.push({
        value: d.value.trim(),
        important: Boolean(d.important),
        origin: 'inline',
        ...(loc ? { location: { startLine: loc.startLine, startCol: loc.startCol } } : {}),
        selector: 'style=',
        ...({ __prop: d.prop.toLowerCase().trim(), __spec: { a: 1, b: 0, c: 0 }, __order: Number.MAX_SAFE_INTEGER } as object),
      } as DeclaredValue);
    });
    byNode.set(el, bucket);
  }

  const allDecls = rules.flatMap((r) =>
    r.decls.map((d) => ({
      selector: r.selector,
      prop: d.prop,
      value: d.value,
      ...(d.location ? { location: d.location } : {}),
    })),
  );

  return {
    diagnostics,

    declaredStyle(node: Element): Map<string, DeclaredValue> {
      const bucket = byNode.get(node) ?? [];
      const winners = new Map<string, DeclaredValue>();
      for (const cand of bucket) {
        const prop = propOf(cand);
        const current = winners.get(prop);
        if (!current || wins(cand, current)) winners.set(prop, cand);
      }
      return winners;
    },

    candidatesFor(node: Element, prop: string): DeclaredValue[] {
      const want = prop.toLowerCase();
      return (byNode.get(node) ?? []).filter((d) => propOf(d) === want);
    },

    isUndecided(node: Element): boolean {
      return undecidedNodes.has(node);
    },

    undecidedReasons(): string[] {
      return [...undecidedReasonSet];
    },

    allDeclarations() {
      return allDecls;
    },
  };
}

/**
 * What one `is()` call against this selector can cost, in budget units.
 *
 * `Budget` is a count of calls, and the cost model behind `selectorMatchBudget`
 * assumed every call costs the same. `:has()` breaks that assumption by a
 * factor of the document size: css-select re-enters the matcher over the
 * candidate's entire subtree, so one call can do as much work as a whole
 * ordinary rule. A combinator is milder — it walks ancestors or previous
 * siblings — and is charged linearly.
 *
 * The charge is a worst case. The real cost of a `:has()` call is the size of
 * that node's subtree, which is only knowable after walking it, and a budget
 * that bills after the fact does not bound anything.
 */
export function hasDescendantDepth(selector: string): number {
  // The argument of every `:has()`, at any nesting depth, including when it is
  // wrapped in `:not()` / `:is()` / `:where()` — measured, a wrapper does not
  // reduce the cost at all.
  let worst = 0;
  let i = selector.indexOf(':has(');
  while (i !== -1) {
    let depth = 0;
    let j = i + ':has('.length;
    const start = j;
    for (; j < selector.length; j++) {
      const ch = selector[j];
      if (ch === '(') depth++;
      else if (ch === ')') {
        if (depth === 0) break;
        depth--;
      }
    }
    const arg = selector.slice(start, j);
    // Only DESCENDANT combinators are superlinear. Measured on a 300-deep
    // chain: `div:has(div div div span)` 3628 ms, `div:has(> div span)` 5 ms,
    // `div:has(div > span)` 3 ms. Child and sibling combinators are cheap.
    const stripped = arg.replace(/\s*[>+~]\s*/g, '');
    const descendants = stripped.trim().match(/\s+/g)?.length ?? 0;
    if (descendants > worst) worst = descendants;
    i = selector.indexOf(':has(', i + 1);
  }
  return worst;
}

/**
 * What one `is()` call against this selector can cost, in budget units.
 *
 * `Budget` counted CALLS, and a call is not a unit of work. The first version
 * of this function charged `1 + hasCount x N`, which is ADDITIVE where the
 * measured cost is MULTIPLICATIVE — so it never tripped. Measured against a
 * 490-deep `<div>` chain, one CSS rule, `div:has(div div div span)`:
 *
 *   before this model   45,555 ms, zero diagnostics, exit 0
 *
 * Growth is ~O(subtree^(1+d)) where d is the number of descendant combinators
 * inside the `:has()`. One single `cssIs` call in that document took 12.7 s, so
 * a cooperative deadline checked between calls cannot bound it either — the
 * charge has to be computed and refused BEFORE the call.
 *
 * The charge uses this node's real subtree size rather than the document size,
 * which is what keeps ordinary markup from being skipped: on real HTML the sum
 * of subtree sizes is about `N x average depth`, so `.card:has(.badge)` over
 * 20,000 nodes costs ~300k units against a 5,000,000 ceiling and matches
 * normally.
 */
export function selectorCost(subtreeSize: number, hasDepth: number): number {
  const base = Math.max(1, subtreeSize);
  if (hasDepth === 0 && base === 1) return 1;
  const raw = Math.pow(base, 1 + hasDepth);
  // Saturate. A 490-node subtree with three descendant combinators is 5.7e10,
  // and an Infinity or a precision loss here would silently disable the bound.
  return Number.isFinite(raw) ? Math.min(raw, Number.MAX_SAFE_INTEGER) : Number.MAX_SAFE_INTEGER;
}

/**
 * Subtree size per element, in one O(N) pass.
 *
 * `allElements` yields document order, in which a node always precedes its
 * descendants, so iterating in REVERSE guarantees every child is already
 * computed when its parent is reached.
 */
function subtreeSizes(elements: Element[]): Map<Element, number> {
  const size = new Map<Element, number>();
  for (let i = elements.length - 1; i >= 0; i--) {
    const el = elements[i]!;
    let total = 1;
    const stack: AnyNode[] = [...(el.children ?? [])];
    while (stack.length > 0) {
      const node = stack.pop()!;
      if (node instanceof Element) {
        total += size.get(node) ?? 1;
      } else {
        // A `<template>`'s content hangs off a `root` node, which is not an
        // Element. Descend through it so template content is counted.
        const kids = (node as { children?: AnyNode[] }).children;
        if (kids) stack.push(...kids);
      }
    }
    size.set(el, total);
  }
  return size;
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

function propOf(d: DeclaredValue): string {
  return (d as unknown as { __prop: string }).__prop;
}

function specOf(d: DeclaredValue): { a: number; b: number; c: number } {
  return (d as unknown as { __spec: { a: number; b: number; c: number } }).__spec;
}

function orderOf(d: DeclaredValue): number {
  return (d as unknown as { __order: number }).__order;
}

/**
 * Does `a` beat `b`?
 *
 * Order: !important, then origin (inline over sheet), then specificity, then
 * source order. This decides only which value is *reported as the winner*. It
 * never removes a candidate — see the header note.
 */
function wins(a: DeclaredValue, b: DeclaredValue): boolean {
  if (a.important !== b.important) return a.important;
  if (a.origin !== b.origin) return a.origin === 'inline';
  const sa = specOf(a);
  const sb = specOf(b);
  if (sa.a !== sb.a) return sa.a > sb.a;
  if (sa.b !== sb.b) return sa.b > sb.b;
  if (sa.c !== sb.c) return sa.c > sb.c;
  return orderOf(a) >= orderOf(b);
}

// ---------------------------------------------------------------------------
// Collection and classification helpers
// ---------------------------------------------------------------------------

type RuleVisitor = (rule: PostcssRule, atRuleStack: string[], selector: string) => void;

/**
 * Compose a nested selector against its parent.
 *
 * CSS Nesting has shipped in Chrome, Safari and Firefox since 2023, and this
 * walker did not descend into it at all: `rule.each` at the collection site
 * only looks at `decl` children, and `walkRules` recursed into at-rules only.
 * So `body { .s { opacity: 0 } }` bound nothing, produced no diagnostic, and
 * every CSS-dependent rule read the document as carrying no such declaration —
 * a one-line, entirely silent bypass of the PANE-HIDDEN and PANE-INPUT
 * families.
 *
 * `&` is substituted where present; otherwise the relationship is descendant.
 * A parent that is a selector LIST is wrapped in `:is()` so the composition
 * cannot change which nodes match.
 */
function composeNested(parent: string, child: string): string {
  const safeParent = parent.includes(',') ? `:is(${parent})` : parent;
  if (child.includes('&')) return child.replace(/&/g, safeParent);
  return `${safeParent} ${child}`;
}

function walkRules(
  container: Root | AtRule | PostcssRule,
  atRuleStack: string[],
  visit: RuleVisitor,
  parentSelector: string | null = null,
): void {
  container.each((node) => {
    if (node.type === 'rule') {
      const rule = node as PostcssRule;
      const selector =
        parentSelector === null
          ? rule.selector
          : composeNested(parentSelector, rule.selector);
      visit(rule, atRuleStack, selector);
      // Descend. A nested rule is a `rule` child of a `rule`, which is exactly
      // what this walker used to drop on the floor.
      walkRules(rule, atRuleStack, visit, selector);
    } else if (node.type === 'atrule') {
      const at = node as AtRule;
      visit_atrule(at, atRuleStack, visit, parentSelector);
    }
  });
}

function visit_atrule(
  at: AtRule,
  atRuleStack: string[],
  visit: RuleVisitor,
  parentSelector: string | null,
): void {
  const name = at.name.toLowerCase();
  // `@layer a, b;` with no body only declares order. It still means layers are
  // in play, so any rule in this sheet may be reordered — but we can only mark
  // the nodes we actually bind, so the marker rides on the rules inside layers.
  if (!at.nodes) return;
  walkRules(at, [...atRuleStack, name], visit, parentSelector);
}

function declLocation(d: Declaration, baseLine: number): SourceLocation | undefined {
  const s = d.source?.start;
  if (!s) return undefined;
  return {
    // postcss lines are 1-based within the <style> text; offset to document lines.
    startLine: baseLine + s.line - 1,
    startCol: s.column,
  };
}

/** Split a selector list on top-level commas, respecting parens and strings. */
function splitSelectorList(selector: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let quote: string | null = null;
  let current = '';
  for (const ch of selector) {
    if (quote) {
      current += ch;
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      current += ch;
      continue;
    }
    if (ch === '(' || ch === '[') depth++;
    if (ch === ')' || ch === ']') depth--;
    if (ch === ',' && depth === 0) {
      if (current.trim()) out.push(current.trim());
      current = '';
      continue;
    }
    current += ch;
  }
  if (current.trim()) out.push(current.trim());
  return out;
}

interface Classified {
  applies: boolean;
  matchSelector: string;
  specificity: { a: number; b: number; c: number };
  /**
   * True when the selector could not be PARSED, as opposed to parsing fine and
   * legitimately not applying at rest.
   *
   * Both used to return `applies: false` and stage 2 dropped them identically,
   * so a selector the parser choked on was indistinguishable from a
   * `::before`. That made unmodellable CSS read as no CSS — which is the
   * benign-looking direction, and therefore the one an attacker picks.
   */
  failed?: boolean;
  /** The pseudo-class css-select models differently from a browser, if any. */
  mismodelled?: string;
}

/**
 * Classify one simple selector.
 *
 * Returns `applies: false` for anything describing a transient state or a
 * generated box: a `:hover` rule is not the resting render, and a `::before`
 * rule styles a pseudo-element rather than the node it originates from. Binding
 * either to the node would report plainly visible text as hidden.
 */
/**
 * How many `:not()` wrappers enclose this node.
 *
 * A stateful pseudo-class describes a state the resting document is not in, so
 * `.x:hover { display: none }` does not hide anything at rest. **Negated, it
 * inverts**: `:not(:hover)` is TRUE at rest, so `.x:not(:hover){display:none}`
 * hides the element in the rendered document.
 *
 * Treating a negated stateful pseudo the same as a positive one dropped the
 * whole declaration from the index, silently. Measured: `.s{display:none}` on
 * text-bearing content produced PANE-HIDDEN-001; `.s:not(:hover){display:none}`
 * produced zero findings, zero undecided, exit 0 — and the same held for
 * `:focus`, `:target`, `:visited`, `:active` across every hiding declaration in
 * the family. Thirteen characters disabled the product's highest-value rule
 * class, which by SECURITY.md §1 is a reportable vulnerability in Panelint
 * rather than a documented limitation.
 *
 * Parity, not presence: `:not(:not(:hover))` is `:hover` again and must stay
 * excluded.
 */
function negationDepth(node: { parent?: unknown }): number {
  let depth = 0;
  let current = node.parent as { type?: string; value?: string; parent?: unknown } | undefined;
  while (current) {
    if (current.type === 'pseudo' && current.value?.replace(/^::?/, '').toLowerCase() === 'not') {
      depth += 1;
    }
    current = current.parent as typeof current;
  }
  return depth;
}

interface ParserNode {
  type?: string;
  value?: string;
  nodes?: ParserNode[];
  parent?: ParserNode;
  remove?: () => void;
}

/** The nearest enclosing `:not()` pseudo, skipping the Selector nodes between. */
function nearestNegation(node: { parent?: unknown }): ParserNode | null {
  let current = node.parent as ParserNode | undefined;
  while (current) {
    if (current.type === 'pseudo' && current.value?.replace(/^::?/, '').toLowerCase() === 'not') {
      return current;
    }
    current = current.parent;
  }
  return null;
}

/**
 * Does this `:not()` contain nothing but stateful pseudo-classes?
 *
 * Only then is dropping it equivalent at rest. `:not(.a:hover)` also constrains
 * by class, so removing it would widen the match by more than the state.
 */
function allStateful(negation: ParserNode): boolean {
  const selectors = negation.nodes ?? [];
  if (selectors.length === 0) return false;
  return selectors.every((sel) => {
    const parts = sel.nodes ?? [];
    return (
      parts.length > 0 &&
      parts.every(
        (p) =>
          p.type === 'pseudo' &&
          STATEFUL_PSEUDO.has(String(p.value).replace(/^::?/, '').toLowerCase()),
      )
    );
  });
}

function classifySelector(selector: string): Classified {
  let applies = true;
  let matchSelector = selector;
  let mismodelled: string | null = null;

  try {
    const processed = selectorParser((root) => {
      /** `:not()` wrappers to delete once the walk finishes. */
      const dropNegations: { remove: () => void }[] = [];

      root.walk((node) => {
        if (node.type === 'pseudo') {
          const name = node.value.replace(/^::?/, '').toLowerCase();
          if (node.value.startsWith('::')) {
            applies = false;
            return;
          }
          // css-select answers this one, and answers it wrong. Trusting the
          // answer is the silent-pass direction, so the selector is unevaluable.
          if (MISMODELLED_PSEUDO.has(name)) {
            mismodelled = name;
            return;
          }
          if (STATEFUL_PSEUDO.has(name)) {
            if (negationDepth(node) % 2 === 0) {
              applies = false;
              return;
            }
            // Negated, so it holds at rest and the declaration applies. The
            // selector still has to be one css-select can evaluate: it knows
            // `:hover` (and answers false) but THROWS on `:focus`,
            // `:focus-visible`, `:target` and the rest — and that throw is
            // swallowed by the match loop, which is why `:not(:focus)` was
            // silent even after classification was fixed.
            //
            // Dropping a `:not()` whose contents are entirely stateful widens
            // the match to exactly the set it selects at rest. Widening is safe
            // by this module's design — candidatesFor() is additive and a
            // resolved declaration may add a finding, never remove one.
            // The `:not` is not the direct parent — postcss-selector-parser
            // puts a Selector node between them — so walk up to it.
            const negation = nearestNegation(node);
            if (negation && typeof negation.remove === 'function' && allStateful(negation)) {
              dropNegations.push(negation as { remove: () => void });
            }
          }
        }
      });

      for (const negation of dropNegations) {
        try {
          negation.remove();
        } catch {
          // Leave the selector as-is; the match loop still handles a throw.
        }
      }
    }).processSync(selector);
    matchSelector = processed;
  } catch {
    // An unsupported selector is skipped, never fatal — but the caller has to
    // be able to tell this from a selector that parsed and does not apply.
    return {
      applies: false,
      failed: true,
      matchSelector: selector,
      specificity: { a: 0, b: 0, c: 0 },
    };
  }

  let specificity = { a: 0, b: 0, c: 0 };
  try {
    const ast = selectorParser().astSync(selector);
    const first = ast.nodes[0];
    if (first) specificity = selectorSpecificity(first as never);
  } catch {
    /* keep the zero specificity */
  }

  if (mismodelled !== null) {
    return { applies: false, failed: true, mismodelled, matchSelector, specificity };
  }
  return { applies, matchSelector, specificity };
}

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

    walkRules(root, [], (rule, atRuleStack) => {
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
      for (const single of splitSelectorList(rule.selector)) {
        const classified = classifySelector(single);
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

  for (const rule of rules) {
    for (const el of elements) {
      budget.spend();
      if (budget.exhausted) break;
      let matches = false;
      try {
        matches = cssIs(el as AnyNode, rule.matchSelector);
      } catch {
        // An unsupported selector is skipped, never fatal.
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
    if (budget.exhausted) break;
  }

  if (budget.exhausted) {
    const d = checkLimit('selectorMatchBudget', budget.used, limits, resourceUri);
    if (d) diagnostics.push(d);
  }

  // Inline style= attributes. Highest origin precedence, always applying.
  for (const el of elements) {
    const inline = attr(el, 'style');
    if (!inline) continue;
    let root: Root;
    try {
      root = postcss.parse(`*{${inline}}`);
    } catch {
      continue;
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

function walkRules(
  container: Root | AtRule,
  atRuleStack: string[],
  visit: (rule: PostcssRule, atRuleStack: string[]) => void,
): void {
  container.each((node) => {
    if (node.type === 'rule') {
      visit(node as PostcssRule, atRuleStack);
    } else if (node.type === 'atrule') {
      const at = node as AtRule;
      visit_atrule(at, atRuleStack, visit);
    }
  });
}

function visit_atrule(
  at: AtRule,
  atRuleStack: string[],
  visit: (rule: PostcssRule, atRuleStack: string[]) => void,
): void {
  const name = at.name.toLowerCase();
  // `@layer a, b;` with no body only declares order. It still means layers are
  // in play, so any rule in this sheet may be reordered — but we can only mark
  // the nodes we actually bind, so the marker rides on the rules inside layers.
  if (!at.nodes) return;
  walkRules(at, [...atRuleStack, name], visit);
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
}

/**
 * Classify one simple selector.
 *
 * Returns `applies: false` for anything describing a transient state or a
 * generated box: a `:hover` rule is not the resting render, and a `::before`
 * rule styles a pseudo-element rather than the node it originates from. Binding
 * either to the node would report plainly visible text as hidden.
 */
function classifySelector(selector: string): Classified {
  let applies = true;
  let matchSelector = selector;

  try {
    const processed = selectorParser((root) => {
      root.walk((node) => {
        if (node.type === 'pseudo') {
          const name = node.value.replace(/^::?/, '').toLowerCase();
          if (node.value.startsWith('::')) {
            applies = false;
            return;
          }
          if (STATEFUL_PSEUDO.has(name)) {
            applies = false;
          }
        }
      });
    }).processSync(selector);
    matchSelector = processed;
  } catch {
    // An unsupported selector is skipped, never fatal.
    return { applies: false, matchSelector: selector, specificity: { a: 0, b: 0, c: 0 } };
  }

  let specificity = { a: 0, b: 0, c: 0 };
  try {
    const ast = selectorParser().astSync(selector);
    const first = ast.nodes[0];
    if (first) specificity = selectorSpecificity(first as never);
  } catch {
    /* keep the zero specificity */
  }

  return { applies, matchSelector, specificity };
}

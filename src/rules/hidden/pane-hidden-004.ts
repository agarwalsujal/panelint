/**
 * PANE-HIDDEN-004 — declared text colour ≈ declared background.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * This rule declines to answer far more often than it answers, and that is the
 * design.
 *
 * SPEC-REFERENCE §3.6: the host **deliberately supplies apps with its own
 * colours** through a fixed set of CSS custom properties
 * (`--color-text-primary`, `--color-background-primary`, …) so that apps blend
 * in. `culori.parse('var(--color-text-primary)')` is `undefined`. So is
 * `currentColor`, and so is `color-mix(...)`.
 *
 * Every one of those, and every node with no resolvable ancestor background,
 * produces an `undecided` note and NO finding. In particular an undeclared
 * background is **never** defaulted to white — that single assumption would fire
 * this rule on every dark-theme app in the ecosystem.
 *
 * `var()` is resolved only when the custom property is statically declared in
 * the same document. That is a declared value, so it does not break the
 * no-computed-styles discipline.
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * The threshold is 1.5:1, not the WCAG 4.5:1 body-text ratio. docs/RULES.md
 * names "WCAG contrast below threshold" without fixing the number, and 4.5:1
 * would turn this into an accessibility linter that fires on every muted caption
 * and every disabled control. 1.5:1 means "indistinguishable", which is what the
 * carrier actually is.
 */

import { Element, type AnyNode } from 'domhandler';
import { parse as parseColor, wcagContrast } from 'culori';
import type { Finding, RuleContext, RuleResult, StyleIndexLike, UndecidedNote } from '../../types.js';
import { defineRule, makeFinding, structuralPath, excerpt, undecided, NON_RENDERED_TAGS } from '../shared/helpers.js';
import { allElements, ancestors, locationOf } from '../../parse/html.js';
import { childNodes, collapse, isNonRendered, meta, nodeData, scaleFor, valuesOf } from './common.js';

const RULE = meta({
  id: 'PANE-HIDDEN-004',
  severity: 'HIGH',
  confidence: 'MEDIUM',
  title: 'Declared text colour is indistinguishable from the declared background',
  cwe: 'CWE-451',
  remediation: 'Give the text a colour that contrasts with its background, or remove the text.',
});

/** Contrast at or below this reads as "the same colour", not "hard to read". */
const INDISTINGUISHABLE = 1.5;

/** A cap so a pathological document cannot fill the report with undecided notes. */
const MAX_UNDECIDED = 40;

const UNRESOLVABLE_TOKENS = /\b(currentcolor|color-mix|light-dark|inherit|initial|unset|revert|revert-layer)\b/;

type Rgb = { mode: string };

/** Custom properties declared anywhere in the document's stylesheets. */
function customProperties(styles: StyleIndexLike): Map<string, string> {
  const out = new Map<string, string>();
  for (const d of styles.allDeclarations()) {
    if (d.prop.startsWith('--')) out.set(d.prop, d.value.trim());
  }
  return out;
}

/**
 * Resolve a declared colour value, or null when Panelint cannot know it.
 *
 * Null is not "no colour" — it is "decline to answer", and every caller turns it
 * into an undecided note rather than into a default.
 */
function resolve(value: string, props: Map<string, string>, depth = 0): Rgb | null {
  const v = value.trim().toLowerCase();
  if (!v || depth > 4) return null;
  if (UNRESOLVABLE_TOKENS.test(v)) return null;

  const varMatch = /^var\(\s*(--[\w-]+)/.exec(v);
  if (varMatch) {
    // A fallback inside var() is NOT used. In an MCP App the host supplies these
    // properties at runtime, so the fallback is the branch that does not happen.
    const declared = props.get(varMatch[1]!);
    if (declared === undefined) return null;
    return resolve(declared, props, depth + 1);
  }
  if (v.includes('var(')) return null;

  const parsed = parseColor(v);
  if (!parsed) return null;
  // Partial transparency would need compositing, which is a computed style.
  const alpha = (parsed as { alpha?: number }).alpha;
  if (alpha !== undefined && alpha < 1) return null;
  return parsed as Rgb;
}

/** Pull a colour out of a `background` shorthand, refusing when an image is involved. */
function backgroundColorToken(value: string): string | null {
  const v = value.trim();
  // A colour token is a handful of characters. A `background` value longer than
  // this carries no colour worth resolving, and refusing it early keeps the
  // tokenizer below off a pathological run of input: `[a-z-]+\(` used to
  // backtrack across a long run of `-` looking for a `(` that never came
  // (200 KB of dashes → 19s). Anchoring the function branch to a leading letter
  // (below) removes the backtracking; this cap bounds the work regardless.
  if (v.length > 4096) return null;
  if (/url\(|gradient\(/i.test(v)) return null;
  const tokens = v.match(/(#[0-9a-f]{3,8}|[a-z][a-z-]*\([^()]*(?:\([^()]*\)[^()]*)*\)|[a-z]+)/gi) ?? [];
  for (const t of tokens) {
    if (/^(no-repeat|repeat|repeat-x|repeat-y|fixed|scroll|local|center|top|bottom|left|right|cover|contain|border-box|padding-box|content-box|space|round)$/i.test(t)) {
      continue;
    }
    return t;
  }
  return null;
}

/** The nearest self-or-ancestor that declares a background, and its raw value. */
function nearestBackground(
  el: Element,
  styles: StyleIndexLike,
): { owner: Element; value: string } | null {
  for (const node of [el, ...ancestors(el)]) {
    const direct = valuesOf(node, styles, 'background-color');
    if (direct.length > 0) return { owner: node, value: direct[direct.length - 1]! };
    const shorthand = valuesOf(node, styles, 'background');
    if (shorthand.length > 0) {
      const last = shorthand[shorthand.length - 1]!;
      // A background image is present: the effective backdrop is not a colour,
      // so hand back the raw value and let `resolve` decline.
      return { owner: node, value: backgroundColorToken(last) ?? last };
    }
  }
  return null;
}

/** Text that keeps this node's colour — a descendant with its own colour is excluded. */
function textAtThisColour(el: Element, styles: StyleIndexLike): string {
  let out = '';
  const walk = (node: AnyNode) => {
    if (node instanceof Element) {
      if (NON_RENDERED_TAGS.has(node.tagName.toLowerCase())) return;
      if (valuesOf(node, styles, 'color').length > 0) return;
    }
    if (node.type === 'text') out += nodeData(node);
    for (const c of childNodes(node)) walk(c);
  };
  for (const c of childNodes(el)) walk(c);
  return out;
}

export const paneHidden004 = defineRule({
  ...RULE,
  requires: ['content'],
  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];
    const notes: UndecidedNote[] = [];
    const props = customProperties(ctx.styles);

    const decline = (el: Element, reason: string) => {
      if (notes.length >= MAX_UNDECIDED) return;
      notes.push(undecided(ctx, RULE, reason, locationOf(el)));
    };

    for (const el of allElements(ctx.dom)) {
      if (isNonRendered(el)) continue;

      const colours = valuesOf(el, ctx.styles, 'color');
      if (colours.length === 0) continue;

      const text = collapse(textAtThisColour(el, ctx.styles));
      if (text.length === 0) continue;

      const bg = nearestBackground(el, ctx.styles);
      if (!bg) {
        // NEVER default an undeclared background to white.
        decline(el, `<${el.tagName}> declares a text colour but no ancestor declares a background; contrast cannot be evaluated without computing styles.`);
        continue;
      }
      const bgColour = resolve(bg.value, props);
      if (!bgColour) {
        decline(el, `background value "${bg.value}" is not statically resolvable (host-supplied custom property, currentColor, color-mix(), or an image).`);
        continue;
      }

      let worst: { ratio: number; declared: string } | null = null;
      let anyResolved = false;
      for (const declared of colours) {
        const fg = resolve(declared, props);
        if (!fg) continue;
        anyResolved = true;
        const ratio = wcagContrast(fg as never, bgColour as never);
        if (!worst || ratio < worst.ratio) worst = { ratio, declared };
      }

      if (!anyResolved) {
        decline(el, `text colour "${colours[0]}" is not statically resolvable; the host supplies its own colours through CSS custom properties (SPEC-REFERENCE §3.6).`);
        continue;
      }
      if (!worst || worst.ratio > INDISTINGUISHABLE) continue;

      const scaled = scaleFor(el, text, ctx.styles, RULE.severity);
      findings.push(
        makeFinding({
          ctx,
          rule: RULE,
          severity: scaled.severity,
          message:
            `<${el.tagName}> declares color:${worst.declared} against background ${bg.value} — ` +
            `contrast ${worst.ratio.toFixed(2)}:1, below the ${INDISTINGUISHABLE}:1 indistinguishable threshold; ${scaled.rationale}.`,
          evidence: excerpt(text),
          location: locationOf(el),
          path: structuralPath(el),
        }),
      );
    }

    return notes.length > 0 ? { findings, undecided: notes } : { findings };
  },
});

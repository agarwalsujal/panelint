/**
 * PANE-SPEC-004 — parser-differential constructs.
 *
 * ── Why this rule was rewritten from its catalog row ─────────────────────────
 * `PANE-SPEC-004` previously read *"content parses as an HTML5 document."* The
 * HTML5 parsing algorithm **never fails** — every byte sequence is a valid
 * document (regression-locked in test/parse.test.ts), so the rule could not
 * fire. The useful version is the one it was replaced with: constructs whose
 * ERROR RECOVERY differs between parsers. Those are the mXSS substrate. What a
 * sanitizer decides is inside `<svg>` and what the browser decides is inside
 * `<svg>` are different trees, and the payload lives in the gap.
 *
 * ── What is NOT checked, and why ─────────────────────────────────────────────
 * The catalog row lists "`</script` inside a script string". **There is no such
 * check here, deliberately.** `"<\/script>"` is the STANDARD and CORRECT way to
 * embed that text in a script — every parser treats the backslash form
 * identically, so it is not a differential at all. A regex for `</script` flags
 * the one construct authors reliably get right. An UNescaped `</script` inside a
 * script string genuinely does end the element, but it does so in every parser,
 * so again there is no divergence to report; whatever follows is ordinary markup
 * and is covered by the rest of the catalog.
 *
 * ── The three signals ────────────────────────────────────────────────────────
 * 1. An unclosed `<template>` / `<svg>` / `<math>`.
 * 2. A foreign-content nesting error. Both fall out of one predicate — see
 *    below — and are distinguished only for the message.
 * 3. Nesting deeper than a threshold no hand-authored document approaches.
 *
 * ── Why "no matched end tag" is the right predicate, measured ────────────────
 * parse5 records `sourceCodeLocation.endTag` only when it MATCHED an end tag.
 * Measured against parse5 8.0.1 with the htmlparser2 tree adapter:
 *
 *   <svg><circle/>                     svg endTag absent   — genuinely unclosed
 *   <svg><p>x</p></svg>                svg endTag absent   — <p> breaks OUT of
 *                                      foreign content and becomes a SIBLING of
 *                                      <svg>; the `</svg>` in the source is
 *                                      never matched
 *   <math><div>x</div></math>          math endTag absent  — same mechanism
 *   <svg><title>t</title></svg>        endTag present      — integration point
 *   <svg><style>…</style><path/></svg> endTag present      — foreign content
 *   <svg viewBox=…/>                   endTag absent       — SELF-CLOSED, legal
 *
 * The self-closing case is why the predicate also inspects the start tag: `/>`
 * is legal in foreign content and produces no end tag by construction. An
 * implementation that skips that exclusion flags correct documents.
 *
 * Realistic icon SVG, `<svg><style>`, `<svg><script>`, `<svg><a><use>`,
 * `<svg><text><tspan>`, nested `<svg>`, and `<template>` holding a `<tr>` were
 * all measured clean.
 */

import { defineRule, makeFinding, excerpt } from '../shared/helpers.js';
import { locationOf, walkElements } from '../../parse/html.js';
import type { Element, Finding, RuleContext, RuleResult } from '../../types.js';

/** Elements whose unmatched end tag means the tree and the source disagree. */
const DIFFERENTIAL_TAGS = new Set(['template', 'svg', 'math']);

/**
 * Depth at which parsers stop agreeing.
 *
 * Deliberately far above anything hand-authored or emitted by a templating
 * library — real documents sit under 40 — so this clause costs nothing in false
 * positives. Engines diverge in how they handle very deep trees (some flatten,
 * some abort, some recurse until the stack goes), and a document that reaches
 * this depth is not describing a user interface.
 *
 * Separate from `limits.maxNestingDepth`, which is a resource-exhaustion ceiling
 * for the scanner and produces a LIMIT_EXCEEDED diagnostic, not a finding.
 */
export const PARSER_DIFFERENTIAL_DEPTH = 200;

/** Reporting ceiling, so a generated document cannot flood a report. */
const MAX_REPORTED = 25;

interface TagLocation {
  startOffset: number;
  endOffset: number;
}

interface ElementLocation {
  startTag?: TagLocation;
  endTag?: TagLocation;
  startOffset?: number;
  endOffset?: number;
}

/**
 * parse5 populates `startTag` and `endTag` under `sourceCodeLocation`, but the
 * htmlparser2 adapter's `TagSourceCodeLocation` type does not declare them. The
 * data is present — measured, and asserted in test/rules-spec.test.ts — so the
 * cast lives here once rather than at each call site, matching the pattern
 * `parse/html.ts` already uses for `attrs`.
 */
function elementLocation(el: Element): ElementLocation | undefined {
  return el.sourceCodeLocation as unknown as ElementLocation | undefined;
}

/** Was the start tag written in the self-closing form legal in foreign content? */
function isSelfClosed(el: Element, rawSource: string): boolean {
  const start = elementLocation(el)?.startTag;
  if (!start) return false;
  return rawSource.slice(start.startOffset, start.endOffset).trimEnd().endsWith('/>');
}

export interface DifferentialHit {
  el: Element;
  tag: string;
  /** `nesting` when an end tag exists in the source but the parser could not
   *  match it; `unclosed` when there is none at all. */
  kind: 'nesting' | 'unclosed';
  evidence: string;
}

/** Every `<template>`/`<svg>`/`<math>` whose source and tree nesting disagree. */
export function findDifferentials(ctx: RuleContext): DifferentialHit[] {
  const hits: DifferentialHit[] = [];

  walkElements(ctx.dom, (el) => {
    const tag = el.tagName;
    if (!DIFFERENTIAL_TAGS.has(tag)) return;

    const loc = elementLocation(el);
    // A synthesized element (no source location) cannot be compared against the
    // source. Nothing to say about it.
    if (!loc?.startTag) return;
    if (loc.endTag) return;
    if (isSelfClosed(el, ctx.rawSource)) return;

    const after = loc.endOffset ?? loc.startTag.endOffset;
    const kind: DifferentialHit['kind'] = ctx.rawSource
      .slice(after)
      .toLowerCase()
      .includes(`</${tag}`)
      ? 'nesting'
      : 'unclosed';

    hits.push({
      el,
      tag,
      kind,
      evidence: excerpt(ctx.rawSource.slice(loc.startTag.startOffset, loc.startTag.endOffset)),
    });
  });

  return hits;
}

/** Deepest element nesting in the tree, template content included. */
export function maxElementDepth(ctx: RuleContext): number {
  let max = 0;
  walkElements(ctx.dom, (_el, depth) => {
    if (depth > max) max = depth;
  });
  return max;
}

export const paneSpec004 = defineRule({
  id: 'PANE-SPEC-004',
  ruleClass: 'RISK',
  severity: 'MEDIUM',
  confidence: 'HIGH',
  title: 'Content contains a parser-differential construct',
  specRef: 'RULES.md § PANE-SPEC — PANE-SPEC-004 was vacuous and is replaced',
  cwe: 'CWE-436',
  remediation:
    'Close the element explicitly, and keep HTML elements out of <svg>/<math> except through an ' +
    'integration point (<foreignObject>, <desc>, <title>, <mtext>, <annotation-xml>). Two ' +
    'parsers that recover differently from this markup build two different trees, and content ' +
    'sanitized against one tree can execute against the other.',
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['content'],

  check(ctx): RuleResult {
    const findings: Finding[] = [];

    const hits = findDifferentials(ctx);
    for (const hit of hits.slice(0, MAX_REPORTED)) {
      const message =
        hit.kind === 'nesting'
          ? `<${hit.tag}> has an end tag in the source that the parser could not match: the ` +
            `parsed tree does not nest the way the source reads. Parsers that recover ` +
            `differently here build different trees, which is the mXSS substrate.`
          : `<${hit.tag}> is never closed. Where the element ends — and therefore what is ` +
            `inside it — depends on the parser's recovery, not on the document.`;

      findings.push(
        makeFinding({
          ctx,
          rule: paneSpec004,
          message,
          evidence: hit.evidence,
          ...(locationOf(hit.el) ? { location: locationOf(hit.el)! } : {}),
          path: `${hit.tag}@${elementLocation(hit.el)?.startTag?.startOffset ?? 0}`,
        }),
      );
    }

    if (hits.length > MAX_REPORTED) {
      ctx.diagnostic(
        'LIMIT_EXCEEDED',
        `PANE-SPEC-004 reported ${MAX_REPORTED} of ${hits.length} parser-differential constructs`,
        'The report is truncated. The resource contains more of these than a report can usefully carry.',
      );
    }

    const depth = maxElementDepth(ctx);
    if (depth > PARSER_DIFFERENTIAL_DEPTH) {
      findings.push(
        makeFinding({
          ctx,
          rule: paneSpec004,
          message:
            `Element nesting reaches a depth of ${depth}, past the ${PARSER_DIFFERENTIAL_DEPTH} ` +
            `threshold at which parsers stop agreeing on the tree. No hand-authored interface ` +
            `nests this deeply.`,
          path: 'depth',
        }),
      );
    }

    return { findings };
  },
});

/**
 * PANE-HIDDEN-014 — consolidated CSS carriers.
 *
 * Every carrier kind carriers.ts reports that is not already owned by another
 * rule in this file's family: `hidden`/`inert` attributes, `content-
 * visibility:hidden`, `text-indent:-9999px`, `transform:scale(0)`/
 * `translate(-99999px)`, a sub-pixel `width`/`height` with
 * `overflow:hidden`, `filter:opacity(0)`, `color:transparent` /
 * `-webkit-text-fill-color:transparent`, and `<details>` without `open`.
 * `display:none`/`visibility:hidden` (-001), `opacity:0` (-002),
 * `font-size:0` (-003), off-screen offsets (-005), and clip/1px collapse
 * (-006) are each that other rule's business and are excluded here so the two
 * never double-report the same declaration under two IDs.
 *
 * `<details>` without `open` is the one carrier here with an overwhelmingly
 * common legitimate use — every closed FAQ accordion trips it — so it routes
 * through `demoteIfWidget`, which recognises the `<details>` tag itself
 * (common.ts's `widgetShaped`) and caps the severity at LOW unless the text
 * is imperative.
 */

import type { CarrierKind } from '../shared/carriers.js';
import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding, structuralPath, excerpt } from '../shared/helpers.js';
import { carriersOn } from '../shared/carriers.js';
import { allElements, locationOf } from '../../parse/html.js';
import { collapse, demoteIfWidget, isNonRendered, meta, renderedText, scaleFor } from './common.js';

const RULE = meta({
  id: 'PANE-HIDDEN-014',
  severity: 'MEDIUM',
  confidence: 'HIGH',
  title: 'Text concealed by a consolidated CSS or attribute carrier',
  cwe: 'CWE-451',
  remediation:
    'Remove the text, or render it. If this is a disclosure widget hidden at rest, keep the ' +
    'content short and give it the role or class that says so.',
});

/**
 * Kinds owned by this rule. `display-none`, `visibility-hidden`,
 * `opacity-zero`, `font-size-zero`, `offscreen`, `clipped` and `aria-hidden`
 * belong to -001/-002/-003/-005/-006/-008 respectively and are deliberately
 * excluded.
 */
const CONSOLIDATED_KINDS = new Set<CarrierKind>([
  'hidden-attr',
  'inert',
  'content-visibility',
  'text-indent',
  'transform-collapsed',
  'zero-size',
  'filter-opacity',
  'color-transparent',
  'details-closed',
]);

export const paneHidden014 = defineRule({
  ...RULE,
  requires: ['content'],
  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];

    for (const el of allElements(ctx.dom)) {
      if (isNonRendered(el)) continue;

      const carriers = carriersOn(el, ctx.styles).filter((c) => CONSOLIDATED_KINDS.has(c.kind));
      if (carriers.length === 0) continue;

      const text = collapse(renderedText(el));
      if (text.length === 0) continue;

      const scaled = demoteIfWidget(el, text, scaleFor(el, text, ctx.styles, RULE.severity));

      findings.push(
        makeFinding({
          ctx,
          rule: RULE,
          severity: scaled.severity,
          message:
            `<${el.tagName}> carries ${text.length} characters of text and is concealed by ` +
            `${carriers.map((c) => c.evidence).join(', ')} — ${scaled.rationale}.`,
          evidence: excerpt(text),
          location: locationOf(el),
          path: structuralPath(el),
        }),
      );
    }

    return { findings };
  },
});

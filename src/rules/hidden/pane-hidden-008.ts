/**
 * PANE-HIDDEN-008 — `aria-hidden="true"` wrapping substantial text.
 *
 * `aria-hidden="true"` on a decorative glyph is the dominant legitimate use and
 * is universal — `<span aria-hidden="true">×</span>` appears in every close
 * button ever written. Firing on it would make this rule pure noise.
 *
 * So the rule needs *substantial* text, which docs/RULES.md says in words and
 * this file makes a number. The floor is bypassed by imperative second-person
 * phrasing, because a 30-character "SYSTEM: ignore prior rules" is exactly the
 * payload the family exists to find, and a glyph is never phrased that way.
 */

import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding, structuralPath, excerpt } from '../shared/helpers.js';
import { carriersOn } from '../shared/carriers.js';
import { hasImperativePhrasing } from '../shared/scale.js';
import { allElements, locationOf } from '../../parse/html.js';
import { collapse, isNonRendered, meta, renderedText, scaleFor } from './common.js';

const RULE = meta({
  id: 'PANE-HIDDEN-008',
  severity: 'MEDIUM',
  confidence: 'HIGH',
  title: 'aria-hidden="true" wrapping substantial text',
  cwe: 'CWE-451',
  remediation:
    'aria-hidden removes content from the accessibility tree but not from the DOM. ' +
    'Remove the text, or drop the attribute if the text is meant to be read.',
});

/** Shorter than this is a glyph, an icon label, or a separator — not a payload. */
const SUBSTANTIAL = 25;

export const paneHidden008 = defineRule({
  ...RULE,
  requires: ['content'],
  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];

    for (const el of allElements(ctx.dom)) {
      if (isNonRendered(el)) continue;
      if (!carriersOn(el, ctx.styles).some((c) => c.kind === 'aria-hidden')) continue;

      const text = collapse(renderedText(el));
      if (text.length < SUBSTANTIAL && !hasImperativePhrasing(text)) continue;

      const scaled = scaleFor(el, text, ctx.styles, RULE.severity);

      findings.push(
        makeFinding({
          ctx,
          rule: RULE,
          severity: scaled.severity,
          message:
            `<${el.tagName} aria-hidden="true"> wraps ${text.length} characters that stay in the ` +
            `DOM while being removed from the accessibility tree — ${scaled.rationale}.`,
          evidence: excerpt(text),
          location: locationOf(el),
          path: structuralPath(el),
        }),
      );
    }

    return { findings };
  },
});

/**
 * PANE-HIDDEN-001 — `display:none` / `visibility:hidden` on a text-bearing element.
 *
 * The plainest carrier in the family, and the one with the most legitimate
 * traffic. Two false-positive controls are load-bearing:
 *
 *   1. Non-rendered elements are excluded outright. A `<style>` block is 100%
 *      "hidden text" and says nothing about anything.
 *   2. Tab panels, dropdowns, modals and accordions are hidden at rest by
 *      design. They are demoted, never suppressed.
 */

import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding, structuralPath, excerpt } from '../shared/helpers.js';
import { carriersOn } from '../shared/carriers.js';
import { allElements, locationOf } from '../../parse/html.js';
import {
  collapse, demoteIfWidget, isNonRendered, meta, renderedText, scaleFor,
} from './common.js';

const RULE = meta({
  id: 'PANE-HIDDEN-001',
  severity: 'MEDIUM',
  confidence: 'HIGH',
  title: 'Text-bearing element hidden by display:none or visibility:hidden',
  cwe: 'CWE-451',
  remediation:
    'Remove the text, or render it. If it is a disclosure widget hidden at rest, ' +
    'give it the role or class that says so, and keep the content short.',
});

export const paneHidden001 = defineRule({
  ...RULE,
  requires: ['content'],
  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];

    for (const el of allElements(ctx.dom)) {
      if (isNonRendered(el)) continue;

      const carriers = carriersOn(el, ctx.styles).filter(
        (c) => c.kind === 'display-none' || c.kind === 'visibility-hidden',
      );
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
            `<${el.tagName}> carries ${text.length} characters of text and is hidden by ` +
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

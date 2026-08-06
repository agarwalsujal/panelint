/**
 * PANE-HIDDEN-005 — off-screen absolute positioning.
 *
 * `position:absolute; left:-9999px` is half of the canonical `.sr-only` recipe,
 * so this rule fires on legitimate accessibility markup by design. scale.ts is
 * what makes that survivable: under 100 characters with an accessibility-shaped
 * class name it lands at INFO, suppressed by default. Over 500 characters, or
 * with imperative second-person phrasing, it escalates.
 *
 * The `.sr-only` recipe also trips PANE-HIDDEN-006 and -014. All three are
 * emitted; each fingerprint includes the rule id, so they stay distinct and a
 * downstream dedup pass can collapse them.
 */

import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding, structuralPath, excerpt } from '../shared/helpers.js';
import { carriersOn } from '../shared/carriers.js';
import { allElements, locationOf } from '../../parse/html.js';
import { collapse, isNonRendered, meta, renderedText, scaleFor } from './common.js';

const RULE = meta({
  id: 'PANE-HIDDEN-005',
  severity: 'MEDIUM',
  confidence: 'HIGH',
  title: 'Text positioned off-screen by a large negative offset',
  cwe: 'CWE-451',
  remediation:
    'Prefer a clip-based visually-hidden utility over large negative offsets, and keep ' +
    'screen-reader-only text short.',
});

export const paneHidden005 = defineRule({
  ...RULE,
  requires: ['content'],
  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];

    for (const el of allElements(ctx.dom)) {
      if (isNonRendered(el)) continue;

      const carriers = carriersOn(el, ctx.styles).filter((c) => c.kind === 'offscreen');
      if (carriers.length === 0) continue;

      const text = collapse(renderedText(el));
      if (text.length === 0) continue;

      const scaled = scaleFor(el, text, ctx.styles, RULE.severity);

      findings.push(
        makeFinding({
          ctx,
          rule: RULE,
          severity: scaled.severity,
          message:
            `<${el.tagName}> is positioned off-screen by ` +
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

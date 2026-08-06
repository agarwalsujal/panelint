/**
 * PANE-HIDDEN-002 — `opacity:0` or near-zero on text.
 *
 * HIGH/HIGH, so it is gate-eligible, which makes its one false-positive mode
 * expensive: `.x{opacity:0;transition:opacity .3s}` paired with
 * `.x.visible{opacity:1}` is the most common fade-in idiom in modern UI.
 *
 * scale.ts demotes when the node declares a transition or animation, and
 * demotion — not suppression — is the deliberate choice. Suppressing on the
 * presence of a `transition` declaration would hand an attacker a one-line
 * evasion; demotion costs only gate-eligibility. Imperative phrasing still wins,
 * so adding `transition:opacity 0s` does not launder a payload.
 */

import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding, structuralPath, excerpt } from '../shared/helpers.js';
import { carriersOn } from '../shared/carriers.js';
import { allElements, locationOf } from '../../parse/html.js';
import { collapse, isNonRendered, meta, renderedText, scaleFor } from './common.js';

const RULE = meta({
  id: 'PANE-HIDDEN-002',
  severity: 'HIGH',
  confidence: 'HIGH',
  title: 'Text-bearing element hidden by opacity:0',
  cwe: 'CWE-451',
  remediation:
    'Remove the text. If this is a fade-in, the finding is informational — but the ' +
    'text is still in the DOM and still reaches any context-extraction pipeline.',
});

export const paneHidden002 = defineRule({
  ...RULE,
  requires: ['content'],
  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];

    for (const el of allElements(ctx.dom)) {
      if (isNonRendered(el)) continue;

      const carriers = carriersOn(el, ctx.styles).filter((c) => c.kind === 'opacity-zero');
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
            `<${el.tagName}> carries ${text.length} characters of text at ` +
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

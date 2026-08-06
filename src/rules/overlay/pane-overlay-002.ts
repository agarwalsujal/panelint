/**
 * PANE-OVERLAY-002 — a near-transparent element that can receive a click,
 * regardless of text content.
 *
 * `PANE-HIDDEN-002` only looks at TEXT-BEARING elements. A transparent
 * click-catcher usually has none:
 *
 * ```html
 * <div style="position:fixed;inset:0;opacity:0.01;z-index:99"></div>
 * ```
 *
 * so this rule exists specifically to not require text.
 *
 * docs/RULES.md states the interval as `(0, 0.1)`, open at zero. That is a
 * documentation bug: `opacity:0` is the canonical click-catcher value (fully
 * invisible, still hit-testable) and an open interval excludes the exact
 * value this rule exists to catch. Implemented here as the closed-at-zero
 * interval `[0, 0.1)`.
 *
 * The one legitimate shape this pattern has is a fade-in-in-progress —
 * `.toast{opacity:0;transition:opacity .3s}` before its `.visible` class is
 * applied — which is demoted to LOW rather than suppressed, for the same
 * reason PANE-HIDDEN-002 demotes it: suppressing on the presence of a
 * `transition` declaration would hand an attacker a one-line evasion.
 */

import type { Finding, RuleContext, RuleResult, Severity } from '../../types.js';
import { defineRule, makeFinding, structuralPath, excerpt } from '../shared/helpers.js';
import { allElements, locationOf } from '../../parse/html.js';
import {
  collapse, containsInteractive, declaresAnimation, firstNumber, hasPointerHandler, isNonRendered,
  meta, renderedText, valuesOf,
} from '../hidden/common.js';

const RULE = meta({
  id: 'PANE-OVERLAY-002',
  severity: 'HIGH',
  confidence: 'HIGH',
  title: 'Near-transparent, clickable element regardless of text content',
  cwe: 'CWE-1021',
  remediation: 'Remove the transparent hit-testable layer, or give it real opacity so it is visible.',
});

/** [0, 0.1) — the interval docs/RULES.md states as (0, 0.1); zero is the canonical case. */
const NEAR_ZERO_MAX = 0.1;

function nearZeroOpacity(value: string): boolean {
  const n = firstNumber(value);
  return n !== null && n >= 0 && n < NEAR_ZERO_MAX;
}

export const paneOverlay002 = defineRule({
  ...RULE,
  requires: ['content'],
  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];

    for (const el of allElements(ctx.dom)) {
      if (isNonRendered(el)) continue;

      const nearZero = valuesOf(el, ctx.styles, 'opacity').some(nearZeroOpacity);
      if (!nearZero) continue;

      const interactive = hasPointerHandler(el) || containsInteractive(el);
      if (!interactive) continue;

      const animated = declaresAnimation(el, ctx.styles);
      const severity: Severity = animated ? 'LOW' : RULE.severity;
      const rationale = animated
        ? 'node declares a transition or animation on opacity — likely a fade-in'
        : 'near-zero opacity with a clickable element and no animation to explain it';

      const text = collapse(renderedText(el));

      findings.push(
        makeFinding({
          ctx,
          rule: RULE,
          severity,
          message:
            `<${el.tagName}> is near-transparent and clickable — ${rationale}.`,
          evidence: excerpt(text.length > 0 ? text : `<${el.tagName}> (no text content)`),
          location: locationOf(el),
          path: structuralPath(el),
        }),
      );
    }

    return { findings };
  },
});

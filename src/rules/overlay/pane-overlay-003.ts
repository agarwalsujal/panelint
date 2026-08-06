/**
 * PANE-OVERLAY-003 — a click-through label under an interactive layer, or a
 * full-pane copy-blocking surface.
 *
 * Two independent signals, both heuristic (MEDIUM/MEDIUM, never gates):
 *
 *   1. `pointer-events:none` on a visible, text-bearing element that sits
 *      BENEATH another element carrying a real interactive control at a
 *      higher `z-index`. The visible label reads one way; the click, which
 *      passes straight through the label, lands on whatever is stacked above
 *      it. `z-index:auto` is treated as stacking level 0 for this
 *      comparison — it is not "elevated" in PANE-OVERLAY-001's sense, but it
 *      is a real baseline two elements can be compared against.
 *   2. A viewport-filling `user-select:none` layer that carries visible text.
 *      A canvas or game surface with no text is excluded — `user-select:none`
 *      on a `<canvas>` container is ordinary, not a copy-blocking trick
 *      played on a real confirmation message.
 */

import type { Element } from 'domhandler';
import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding, structuralPath, excerpt } from '../shared/helpers.js';
import { allElements, locationOf } from '../../parse/html.js';
import {
  collapse, containsInteractive, fillsViewport, firstNumber, hasValue, isNonRendered, meta,
  renderedText, valuesOf,
} from '../hidden/common.js';

const RULE = meta({
  id: 'PANE-OVERLAY-003',
  severity: 'MEDIUM',
  confidence: 'MEDIUM',
  title: 'Click-through label beneath an interactive layer, or a copy-blocking full-pane surface',
  cwe: 'CWE-1021',
  remediation:
    'Remove pointer-events:none from a label sitting under a real control, or scope ' +
    'user-select:none to the surface that actually needs it rather than the whole viewport.',
});

/** Best declared z-index, treating absent/auto as stacking level 0 (a comparison baseline). */
function stackLevel(el: Element, ctx: RuleContext): number {
  let best: number | null = null;
  for (const v of valuesOf(el, ctx.styles, 'z-index')) {
    if (v === 'auto' || v === '') continue;
    const n = firstNumber(v);
    if (n === null) continue;
    if (best === null || n > best) best = n;
  }
  return best ?? 0;
}

export const paneOverlay003 = defineRule({
  ...RULE,
  requires: ['content'],
  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];
    const elements = allElements(ctx.dom);

    // Signal 1: click-through label under an interactive layer.
    for (const el of elements) {
      if (isNonRendered(el)) continue;
      const pointerNone = hasValue(el, ctx.styles, 'pointer-events', (v) => v === 'none');
      if (!pointerNone) continue;

      const text = collapse(renderedText(el));
      if (text.length === 0) continue;

      const ownLevel = stackLevel(el, ctx);
      const coveredByInteractive = elements.some((other) => {
        if (other === el || isNonRendered(other)) return false;
        if (!containsInteractive(other)) return false;
        return stackLevel(other, ctx) > ownLevel;
      });
      if (!coveredByInteractive) continue;

      findings.push(
        makeFinding({
          ctx,
          rule: RULE,
          message:
            `<${el.tagName}> carries visible text "${excerpt(text, 40)}" but pointer-events:none ` +
            'sends clicks through to an interactive element stacked above it — the label a user ' +
            'reads is not what receives the click.',
          evidence: excerpt(text),
          location: locationOf(el),
          path: `${structuralPath(el)}/pointer-events`,
        }),
      );
    }

    // Signal 2: full-pane copy-blocking surface.
    for (const el of elements) {
      if (isNonRendered(el)) continue;
      const userSelectNone =
        hasValue(el, ctx.styles, 'user-select', (v) => v === 'none') ||
        hasValue(el, ctx.styles, '-webkit-user-select', (v) => v === 'none');
      if (!userSelectNone) continue;
      if (!fillsViewport(el, ctx.styles)) continue;

      const text = collapse(renderedText(el));
      if (text.length === 0) continue;

      findings.push(
        makeFinding({
          ctx,
          rule: RULE,
          message:
            `<${el.tagName}> fills the viewport with user-select:none over ${text.length} characters ` +
            'of visible text — a reader cannot select or copy what it says.',
          evidence: excerpt(text),
          location: locationOf(el),
          path: `${structuralPath(el)}/user-select`,
        }),
      );
    }

    return { findings };
  },
});

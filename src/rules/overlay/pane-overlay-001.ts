/**
 * PANE-OVERLAY-001 — a viewport-filling, elevated-z-index element WITH a
 * second signal.
 *
 * Measured on `pdf-server`: geometry plus `z-index` alone fired twice —
 * `.confirm-dialog { position:fixed; inset:0; z-index:1000 }` and
 * `.main.fullscreen { position:fixed; top/left/right/bottom:0; z-index:1000 }`
 * — an ordinary modal and an ordinary fullscreen container. At `HIGH` that
 * would have failed the corpus gate on its own. Geometry plus `z-index` is
 * necessary but nowhere near sufficient; the element must ALSO be
 * near-transparent, contain no visible interactive control of its own, or
 * carry assistant-voice prose. An opaque dialog with a heading and buttons
 * produces nothing.
 *
 * `elevatedZIndex` (common.ts) already treats an absent `z-index` as `auto`,
 * never as elevated — `threejs-server`'s `.error-overlay` fills the viewport
 * with no `z-index` declared at all, and this rule skips it before the
 * second-signal check ever runs.
 *
 * Confidence MEDIUM: "no visible interactive control" and "near-transparent"
 * are both judgment calls a computed-style read would answer more precisely
 * than a declared-CSS one, so this rule never gates.
 */

import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding, structuralPath, excerpt } from '../shared/helpers.js';
import { hasImperativePhrasing } from '../shared/scale.js';
import { allElements, locationOf } from '../../parse/html.js';
import {
  collapse, containsInteractive, elevatedZIndex, fillsViewport, firstNumber, isNonRendered, meta,
  renderedText,
} from '../hidden/common.js';

const RULE = meta({
  id: 'PANE-OVERLAY-001',
  severity: 'MEDIUM',
  confidence: 'MEDIUM',
  title: 'Viewport-filling, elevated element with a second impersonation or click-catching signal',
  cwe: 'CWE-1021',
  remediation:
    'Give the overlay an opaque, legible surface with a real interactive control, or remove it ' +
    'if it is not a genuine modal.',
});

/** Opacity at or below this reads as "near-transparent" for this signal. */
const NEAR_TRANSPARENT = 0.2;

export const paneOverlay001 = defineRule({
  ...RULE,
  requires: ['content'],
  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];

    for (const el of allElements(ctx.dom)) {
      if (isNonRendered(el)) continue;
      if (!fillsViewport(el, ctx.styles)) continue;

      const z = elevatedZIndex(el, ctx.styles);
      if (z === null) continue;

      const opacityCandidates = ctx.styles.candidatesFor(el, 'opacity').map((d) => d.value);
      const nearTransparent = opacityCandidates.some((v) => {
        const n = firstNumber(v);
        return n !== null && n >= 0 && n <= NEAR_TRANSPARENT;
      });
      const hasInteractive = containsInteractive(el);
      const text = collapse(renderedText(el));
      const assistantVoice = hasImperativePhrasing(text);

      const signals: string[] = [];
      if (nearTransparent) signals.push('is near-transparent');
      if (!hasInteractive) signals.push('contains no interactive control of its own');
      if (assistantVoice) signals.push('carries assistant-voice imperative prose');
      if (signals.length === 0) continue;

      findings.push(
        makeFinding({
          ctx,
          rule: RULE,
          message:
            `<${el.tagName}> fills the viewport at z-index:${z} and ${signals.join(', ')} — this ` +
            'combination is consistent with a clickjacking or impersonation overlay rather than an ' +
            'ordinary modal.',
          evidence: excerpt(text.length > 0 ? text : `<${el.tagName}> (no text content)`),
          location: locationOf(el),
          path: structuralPath(el),
        }),
      );
    }

    return { findings };
  },
});

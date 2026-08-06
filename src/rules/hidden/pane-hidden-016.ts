/**
 * PANE-HIDDEN-016 — SVG `<foreignObject>` and MathML `<mtext>`/`<annotation>`
 * text containers.
 *
 * Measured: `selectAll('foreignObject', dom)` returns 0, and so does
 * `selectAll('foreignobject', dom)` — css-select cannot match a camelCase
 * foreign-content tag name in HTML-parsing mode regardless of the case used
 * in the query. domhandler's tree still preserves the true casing on
 * `element.tagName` (verified directly against parse5's output), so this
 * rule walks `allElements` and compares case-insensitively rather than going
 * through the selector layer at all. MathML's `<mtext>`/`<annotation>` are
 * already lowercase and would match a selector, but the same manual walk is
 * used for both so one code path covers all three tags uniformly.
 */

import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding, structuralPath, excerpt } from '../shared/helpers.js';
import { allElements, locationOf } from '../../parse/html.js';
import { collapse, isNonRendered, meta, renderedText, scaleFor } from './common.js';
import { hasImperativePhrasing } from '../shared/scale.js';

const RULE = meta({
  id: 'PANE-HIDDEN-016',
  severity: 'MEDIUM',
  confidence: 'HIGH',
  title: 'SVG foreignObject or MathML mtext/annotation text container',
  cwe: 'CWE-451',
  remediation: 'Remove the text, or move it out of a foreign-content container that scanners routinely miss.',
});

const TARGET_TAGS = new Set(['foreignobject', 'mtext', 'annotation']);

/** Below this, and non-imperative, too short to be a payload worth reporting. */
const MIN_CHARS = 20;

export const paneHidden016 = defineRule({
  ...RULE,
  requires: ['content'],
  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];

    for (const el of allElements(ctx.dom)) {
      if (!TARGET_TAGS.has(el.tagName.toLowerCase())) continue;
      if (isNonRendered(el)) continue;

      const text = collapse(renderedText(el));
      if (text.length === 0) continue;
      if (text.length < MIN_CHARS && !hasImperativePhrasing(text)) continue;

      const scaled = scaleFor(el, text, ctx.styles, RULE.severity);

      findings.push(
        makeFinding({
          ctx,
          rule: RULE,
          severity: scaled.severity,
          message:
            `<${el.tagName}> is a foreign-content text container that CSS selector matching ` +
            `routinely misses, carrying ${text.length} characters — ${scaled.rationale}.`,
          evidence: excerpt(text),
          location: locationOf(el),
          path: structuralPath(el),
        }),
      );
    }

    return { findings };
  },
});

/**
 * PANE-HIDDEN-003 — `font-size:0` or sub-pixel.
 *
 * `ul{font-size:0} li{font-size:14px}` is a decades-old recipe for removing the
 * whitespace between inline-block children, and the `li` text is plainly
 * visible. So the concealed text is only the text this node contributes
 * *directly* plus descendants that do not reset the size themselves — a subtree
 * that declares its own non-zero `font-size` renders, and counting it here would
 * report visible copy as hidden.
 *
 * This is not an evasion route. Adding `font-size:12px` to the child that holds
 * the payload makes the payload render.
 */

import { Element, type AnyNode } from 'domhandler';
import type { Finding, RuleContext, RuleResult, StyleIndexLike } from '../../types.js';
import { defineRule, makeFinding, structuralPath, excerpt, NON_RENDERED_TAGS } from '../shared/helpers.js';
import { carriersOn } from '../shared/carriers.js';
import { allElements, locationOf } from '../../parse/html.js';
import { childNodes, collapse, isNonRendered, meta, nodeData, scaleFor, valuesOf } from './common.js';

const RULE = meta({
  id: 'PANE-HIDDEN-003',
  severity: 'HIGH',
  confidence: 'HIGH',
  title: 'Text rendered at font-size:0 or a sub-pixel size',
  cwe: 'CWE-451',
  remediation: 'Remove the text, or give it a legible size.',
});

function isZeroish(v: string): boolean {
  const t = v.trim().toLowerCase();
  if (t === '0') return true;
  const m = /^-?[\d.]+/.exec(t);
  if (!m) return false;
  const n = Number(m[0]);
  if (!Number.isFinite(n)) return false;
  if (/px$/.test(t)) return n < 1;
  if (/(em|rem)$/.test(t)) return n < 0.06;
  if (/%$/.test(t)) return n < 1;
  return n === 0;
}

/** True when this descendant restores a legible size for its own subtree. */
function resetsSize(el: Element, styles: StyleIndexLike): boolean {
  const declared = valuesOf(el, styles, 'font-size');
  return declared.length > 0 && declared.some((v) => !isZeroish(v));
}

/** Text that stays at the zero size: everything except size-resetting subtrees. */
function textStillCollapsed(el: Element, styles: StyleIndexLike): string {
  let out = '';
  const walk = (node: AnyNode) => {
    if (node instanceof Element) {
      if (NON_RENDERED_TAGS.has(node.tagName.toLowerCase())) return;
      if (resetsSize(node, styles)) return;
    }
    if (node.type === 'text') out += nodeData(node);
    for (const c of childNodes(node)) walk(c);
  };
  for (const c of childNodes(el)) walk(c);
  return out;
}

export const paneHidden003 = defineRule({
  ...RULE,
  requires: ['content'],
  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];

    for (const el of allElements(ctx.dom)) {
      if (isNonRendered(el)) continue;

      const carriers = carriersOn(el, ctx.styles).filter((c) => c.kind === 'font-size-zero');
      if (carriers.length === 0) continue;

      const text = collapse(textStillCollapsed(el, ctx.styles));
      if (text.length === 0) continue;

      const scaled = scaleFor(el, text, ctx.styles, RULE.severity);

      findings.push(
        makeFinding({
          ctx,
          rule: RULE,
          severity: scaled.severity,
          message:
            `<${el.tagName}> renders ${text.length} characters at ` +
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

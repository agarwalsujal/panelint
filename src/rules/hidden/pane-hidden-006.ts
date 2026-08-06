/**
 * PANE-HIDDEN-006 — collapsed `clip-path` / `clip` / 1px-overflow-hidden.
 *
 * `carriersOn` already reports the collapsed `clip` and `clip-path` forms. The
 * third form in the catalog — a 1×1 box with `overflow:hidden` — is checked
 * here rather than in carriers.ts, because carriers.ts's `zero-size` predicate
 * deliberately requires a sub-pixel length: a 1px box is not zero, and treating
 * it as a universal carrier would change what "hidden" means for every family
 * that composes with carriers.ts. The 1px band therefore belongs to this rule
 * and this rule alone, and the two do not overlap.
 */

import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding, structuralPath, excerpt } from '../shared/helpers.js';
import { carriersOn } from '../shared/carriers.js';
import { allElements, locationOf } from '../../parse/html.js';
import { collapse, firstNumber, hasValue, isNonRendered, meta, renderedText, scaleFor } from './common.js';

const RULE = meta({
  id: 'PANE-HIDDEN-006',
  severity: 'MEDIUM',
  confidence: 'HIGH',
  title: 'Text collapsed by clip, clip-path, or a 1px overflow-hidden box',
  cwe: 'CWE-451',
  remediation: 'Keep clip-based visually-hidden text short, or remove it.',
});

/** A length that is 1px or smaller — the visually-hidden collapse band. */
function atMostOnePixel(v: string): boolean {
  const t = v.trim().toLowerCase();
  if (t === '0') return true;
  const n = firstNumber(t);
  if (n === null) return false;
  if (/px$/.test(t)) return n <= 1;
  if (/(em|rem)$/.test(t)) return n <= 0.07;
  return n === 0;
}

/** Strictly sub-pixel — what carriers.ts already reports as `zero-size`. */
function subPixel(v: string): boolean {
  const t = v.trim().toLowerCase();
  if (t === '0') return true;
  const n = firstNumber(t);
  if (n === null) return false;
  if (/px$/.test(t)) return n < 1;
  if (/(em|rem)$/.test(t)) return n < 0.06;
  return n === 0;
}

export const paneHidden006 = defineRule({
  ...RULE,
  requires: ['content'],
  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];

    for (const el of allElements(ctx.dom)) {
      if (isNonRendered(el)) continue;

      const evidence = carriersOn(el, ctx.styles)
        .filter((c) => c.kind === 'clipped')
        .map((c) => c.evidence);

      const overflowHidden = hasValue(el, ctx.styles, 'overflow', (v) => v === 'hidden' || v === 'clip');
      const tinyBox =
        overflowHidden &&
        hasValue(el, ctx.styles, 'width', atMostOnePixel) &&
        hasValue(el, ctx.styles, 'height', atMostOnePixel);
      // The strictly-zero case is carriers.ts's `zero-size`, reported by
      // PANE-HIDDEN-014. Only the 1px band belongs here.
      const alreadyZeroSize =
        hasValue(el, ctx.styles, 'width', subPixel) || hasValue(el, ctx.styles, 'height', subPixel);
      if (tinyBox && !alreadyZeroSize) evidence.push('width/height ≤1px with overflow:hidden');

      if (evidence.length === 0) continue;

      const text = collapse(renderedText(el));
      if (text.length === 0) continue;

      const scaled = scaleFor(el, text, ctx.styles, RULE.severity);

      findings.push(
        makeFinding({
          ctx,
          rule: RULE,
          severity: scaled.severity,
          message: `<${el.tagName}> is collapsed by ${evidence.join(', ')} — ${scaled.rationale}.`,
          evidence: excerpt(text),
          location: locationOf(el),
          path: structuralPath(el),
        }),
      );
    }

    return { findings };
  },
});

/**
 * PANE-HIDDEN-013 — HTML markup inside a JS string literal, carrying a hidden
 * carrier.
 *
 * Apps that build DOM from template strings (`el.innerHTML = '<div ...>'`)
 * carry their markup as JS string literals until the moment it is inserted.
 * A `display:none` node built this way never appears in the tree this
 * family's other rules walk — there is no `<div style="display:none">`
 * anywhere in the served HTML, only a string that will become one once a
 * script runs. Confidence MEDIUM and no gate: whether that string ever
 * actually reaches the DOM is exactly `PANE-DOM-001`'s question, not this
 * one's — this rule reports capability, the same way `PANE-DOM-001` does.
 *
 * Only string and no-interpolation template literals are considered, mirror-
 * ing `isLiteralExpression` in src/parse/js.ts: an interpolated value is not
 * statically knowable, so there is nothing here to sub-parse.
 */

import { simple as walkSimple } from 'acorn-walk';
import type { Node } from 'acorn';
import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding, structuralPath, excerpt } from '../shared/helpers.js';
import { carriersOn, declaredPropNames } from '../shared/carriers.js';
import { scaleHiddenFinding } from '../shared/scale.js';
import { allElements, locationOf, parseHtml } from '../../parse/html.js';
import { buildStyleIndex } from '../../parse/style-index.js';
import type { ScriptSource } from '../../types.js';
import { collapse, isNonRendered, meta, renderedText } from './common.js';

const RULE = meta({
  id: 'PANE-HIDDEN-013',
  severity: 'HIGH',
  confidence: 'MEDIUM',
  title: 'HTML markup in a JS string literal carrying a hidden carrier',
  cwe: 'CWE-451',
  remediation:
    'Remove the hidden carrier from the markup the script builds, or remove the text it conceals.',
});

/** Cheap prefilter before the sub-parse: does this even look like a tag? */
const LOOKS_LIKE_MARKUP = /<[a-zA-Z][^>]*>/;

const MAX_LITERAL_CHARS = 50_000;

function literalStringValue(node: Node): string | null {
  const n = node as unknown as {
    type: string;
    value?: unknown;
    quasis?: Array<{ value: { cooked: string | null; raw: string } }>;
    expressions?: unknown[];
  };
  if (n.type === 'Literal' && typeof n.value === 'string') return n.value;
  if (n.type === 'TemplateLiteral' && (n.expressions ?? []).length === 0) {
    const q = n.quasis?.[0];
    if (!q) return null;
    return q.value.cooked ?? q.value.raw;
  }
  return null;
}

export const paneHidden013 = defineRule({
  ...RULE,
  requires: ['content'],
  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];
    const seenLiterals = new Set<string>();

    const inspectLiteral = (script: ScriptSource, value: string, literalIndex: number) => {
      if (value.length === 0 || value.length > MAX_LITERAL_CHARS) return;
      if (!LOOKS_LIKE_MARKUP.test(value)) return;
      // Same literal text reused (e.g. inside a loop body) is one finding, not N.
      const key = `${script.offset}:${value}`;
      if (seenLiterals.has(key)) return;

      const sub = parseHtml(value, ctx.limits);
      const subStyles = buildStyleIndex(sub.dom, ctx.limits);

      for (const el of allElements(sub.dom)) {
        if (isNonRendered(el)) continue;
        const carriers = carriersOn(el, subStyles);
        if (carriers.length === 0) continue;
        const text = collapse(renderedText(el));
        if (text.length === 0) continue;

        seenLiterals.add(key);
        const scaled = scaleHiddenFinding({
          ceiling: RULE.severity,
          text,
          declaredProps: declaredPropNames(el, subStyles),
        });

        const owner = script.element;
        findings.push(
          makeFinding({
            ctx,
            rule: RULE,
            severity: scaled.severity,
            message:
              `A JS string literal builds <${el.tagName}> hidden by ` +
              `${carriers.map((c) => c.evidence).join(', ')}, carrying ${text.length} characters — ` +
              `${scaled.rationale}.`,
            evidence: excerpt(text),
            ...(owner ? { location: locationOf(owner) } : {}),
            path: owner
              ? `${structuralPath(owner)}/js-literal[${literalIndex}]`
              : `js-literal[${script.offset}:${literalIndex}]`,
          }),
        );
        return;
      }
    };

    for (const script of ctx.scripts) {
      if (!script.ast) continue;
      let literalIndex = 0;
      walkSimple(script.ast as Node, {
        Literal(node: Node) {
          const v = literalStringValue(node);
          if (v !== null) inspectLiteral(script, v, literalIndex++);
        },
        TemplateLiteral(node: Node) {
          const v = literalStringValue(node);
          if (v !== null) inspectLiteral(script, v, literalIndex++);
        },
      });
    }

    return { findings };
  },
});

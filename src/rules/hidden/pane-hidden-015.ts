/**
 * PANE-HIDDEN-015 — attribute-borne prose.
 *
 * The other rule docs/RULES.md credits with closing "the payload that scored
 * clean on all 45 original rules": no original PANE-HIDDEN rule read
 * attribute values at all, and `alt`, `title`, `aria-label` and `data-*` are
 * exactly the fields a context-extraction pipeline reads while rendering
 * them to nobody.
 *
 * The false-positive risk this rule was corrected against is real and
 * common: a long, purely descriptive `alt` is a WCAG 2.1 SC 1.1.1 best
 * practice, and `aria-label`/`title` of ordinary length are completely
 * normal UI. So length alone never escalates past LOW here — only imperative
 * second-person phrasing does, which is a different axis than
 * `scaleHiddenFinding`'s (that function escalates plain length past 500
 * characters, which is exactly the WCAG-alt false positive this rule exists
 * to avoid, so it is not used here).
 *
 * `data-*` values that parse as JSON are configuration, not prose, and are
 * excluded outright — a chart component's `data-values='{"labels":[...]}'`
 * is not a payload.
 */

import type { Finding, RuleContext, RuleResult, Severity } from '../../types.js';
import { defineRule, makeFinding, structuralPath, excerpt } from '../shared/helpers.js';
import { hasImperativePhrasing } from '../shared/scale.js';
import { allElements, attrLocationOf, locationOf } from '../../parse/html.js';
import { atMost, collapse, meta } from './common.js';

const RULE = meta({
  id: 'PANE-HIDDEN-015',
  severity: 'HIGH',
  confidence: 'HIGH',
  title: 'Attribute-borne prose',
  cwe: 'CWE-451',
  remediation:
    'Remove instruction-shaped text from attribute values. Ordinary accessibility text — a ' +
    'long alt, a short aria-label or title — is fine on its own; imperative phrasing is not.',
});

/** Below this, and non-imperative, an attribute value is not worth reporting at all. */
const MIN_CHARS = 40;

const TARGET_ATTRS = new Set(['alt', 'title', 'aria-label', 'placeholder']);

/** `data-*` that parses as JSON is configuration, not prose. */
function parsesAsJson(value: string): boolean {
  const t = value.trim();
  if (!t || !(t.startsWith('{') || t.startsWith('['))) return false;
  try {
    JSON.parse(t);
    return true;
  } catch {
    return false;
  }
}

interface ScaleResult {
  severity: Severity;
  rationale: string;
}

/**
 * Attribute prose scales on shape, not length. A long descriptive `alt` is a
 * WCAG best practice and lands at LOW; only imperative phrasing reaches HIGH.
 */
function scaleAttributeProse(ceiling: Severity, text: string): ScaleResult {
  if (hasImperativePhrasing(text)) {
    return {
      severity: atMost('HIGH', ceiling),
      rationale: `attribute value contains imperative second-person phrasing (${text.length} chars)`,
    };
  }
  return {
    severity: atMost('LOW', ceiling),
    rationale:
      `${text.length} chars of attribute-borne text with no imperative phrasing — likely ` +
      'legitimate long-form accessibility text',
  };
}

export const paneHidden015 = defineRule({
  ...RULE,
  requires: ['content'],
  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];

    for (const el of allElements(ctx.dom)) {
      for (const [name, rawValue] of Object.entries(el.attribs ?? {})) {
        const lname = name.toLowerCase();
        const isData = lname.startsWith('data-');
        if (!TARGET_ATTRS.has(lname) && !isData) continue;
        if (isData && parsesAsJson(rawValue)) continue;

        const text = collapse(rawValue);
        if (text.length === 0) continue;
        if (text.length < MIN_CHARS && !hasImperativePhrasing(text)) continue;

        const scaled = scaleAttributeProse(RULE.severity, text);

        findings.push(
          makeFinding({
            ctx,
            rule: RULE,
            severity: scaled.severity,
            message:
              `<${el.tagName} ${lname}> carries ${text.length} characters of attribute-borne ` +
              `text — ${scaled.rationale}.`,
            evidence: excerpt(text),
            location: attrLocationOf(el, name) ?? locationOf(el),
            path: `${structuralPath(el)}@${lname}`,
          }),
        );
      }
    }

    return { findings };
  },
});

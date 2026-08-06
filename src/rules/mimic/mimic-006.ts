/**
 * PANE-MIMIC-006 — an inline data-URI favicon matching a claimed brand.
 *
 * Demoted to INFO. Browsers do NOT render `<link rel="icon">` inside an
 * iframe, so a favicon in an MCP App has no visual effect and cannot
 * contribute to visual mimicry. Kept only as an intent signal — an author
 * who bundled a brand's favicon anyway was thinking about brand impersonation
 * even where it cannot render.
 */

import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding } from '../shared/helpers.js';
import { selectAll, attr, locationOf } from '../../parse/html.js';
import { detectedBrands, renderedText } from './shared.js';

const REMEDIATION =
  'No functional change required — this has no visual effect inside an iframe. Remove it if it was ' +
  'meant to reinforce a brand claim; it does not do so here.';

export const mimic006 = defineRule({
  id: 'PANE-MIMIC-006',
  ruleClass: 'INFO',
  severity: 'LOW',
  confidence: 'LOW',
  title: 'Inline data-URI favicon matching a claimed brand',
  specRef: 'docs/RULES.md § PANE-MIMIC — browsers do not render link rel=icon in an iframe',
  remediation: REMEDIATION,
  experimental: true,
  status: 'active',
  since: '0.1.0',
  requires: ['content'],

  check(ctx: RuleContext): RuleResult {
    const brands = detectedBrands(renderedText(ctx.dom));
    if (brands.length === 0) return { findings: [] };

    const findings: Finding[] = [];
    let n = 0;

    for (const el of selectAll('link[rel="icon"]', ctx.dom)) {
      const href = (attr(el, 'href') ?? '').trim();
      if (!href.toLowerCase().startsWith('data:')) continue;

      findings.push(
        makeFinding({
          ctx,
          rule: mimic006,
          message:
            `<link rel="icon"> is an inline data-URI, and the page claims to be ` +
            `${brands.map((b) => b.name).join('/')} in its rendered text. Browsers do not render ` +
            '<link rel="icon"> inside an iframe, so this has no visual effect and cannot ' +
            'contribute to visual mimicry — kept only as an intent signal.',
          evidence: href.slice(0, 60),
          location: locationOf(el),
          path: `link#${n++}`,
        }),
      );
    }

    return { findings };
  },
});

export default mimic006;

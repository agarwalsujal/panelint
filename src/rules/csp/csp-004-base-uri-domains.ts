/**
 * PANE-CSP-004 — `baseUriDomains` non-empty.
 *
 * The CSP construction sets `base-uri ${baseUriDomains.join(' ') || "'self'"}`,
 * so the default is already correct and declaring the field can only widen it.
 * A widened `base-uri` lets a `<base href>` retarget every relative URL in the
 * document, which composes with PANE-EXFIL-006.
 *
 * An earlier revision of RULES.md claimed the schema and the mandated default
 * contradicted each other on `base-uri`. They do not — `apps.mdx` L1743 applies
 * `'self'` exactly as the schema describes. This rule fires on the narrower and
 * correct grounds that a declared `baseUriDomains` widens it.
 */

import type { RuleMeta, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding, CSP_SYNTHESIS_ASSUMPTION } from '../shared/helpers.js';
import { cspOf, entriesOf, pointerFor } from './domains.js';

const meta: RuleMeta = {
  id: 'PANE-CSP-004',
  ruleClass: 'RISK',
  severity: 'MEDIUM',
  confidence: 'CERTAIN',
  title: "base-uri widened from the default of 'self'",
  specRef: 'SEP-1865 §Security Implications — CSP Enforcement (apps.mdx L1743)',
  cwe: 'CWE-942',
  remediation:
    "Remove baseUriDomains. The construction already applies base-uri 'self', and a " +
    'wider base-uri lets a <base> element retarget every relative URL in the document.',
  experimental: false,
  status: 'active',
  since: '0.1.0',
};

export const paneCsp004 = defineRule({
  ...meta,
  requires: ['meta'],
  check(ctx: RuleContext): RuleResult {
    const csp = cspOf(ctx.meta);
    if (!csp) return { findings: [] };

    const entries = entriesOf(csp, 'baseUriDomains');
    if (entries.length === 0) return { findings: [] };

    return {
      findings: [
        makeFinding({
          ctx,
          rule: meta,
          message:
            `baseUriDomains declares ${entries.length} origin${entries.length === 1 ? '' : 's'}, ` +
            "widening base-uri from the 'self' the CSP construction applies by default. A " +
            '<base href> pointing at one of them retargets every relative URL in the document.',
          evidence: entries.map((e) => e.value).join(' '),
          jsonPointer: pointerFor('baseUriDomains'),
          assumption: CSP_SYNTHESIS_ASSUMPTION,
        }),
      ],
    };
  },
});

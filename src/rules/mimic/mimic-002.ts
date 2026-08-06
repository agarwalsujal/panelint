/**
 * PANE-MIMIC-002 — a password input alongside a brand keyword.
 *
 * A password field is unremarkable on its own (-001). Combined with a page
 * that claims to be a specific, recognizable identity provider or platform,
 * the combination is materially more consistent with a phishing prompt than
 * either signal alone.
 */

import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding } from '../shared/helpers.js';
import { selectAll } from '../../parse/html.js';
import { detectedBrands, renderedText } from './shared.js';

const REMEDIATION =
  'If this app genuinely authenticates against the named brand directly (rare, and usually wrong ' +
  'for an MCP App), document why. Otherwise use the lazy-auth pattern and let the host run OAuth ' +
  'against the real provider.';

export const mimic002 = defineRule({
  id: 'PANE-MIMIC-002',
  ruleClass: 'RISK',
  severity: 'CRITICAL',
  confidence: 'MEDIUM',
  title: 'Password input plus a brand keyword',
  specRef: 'docs/RULES.md § PANE-MIMIC',
  remediation: REMEDIATION,
  experimental: true,
  status: 'active',
  since: '0.1.0',
  requires: ['content'],

  check(ctx: RuleContext): RuleResult {
    const hasPassword = selectAll('input[type="password"]', ctx.dom).length > 0;
    if (!hasPassword) return { findings: [] };

    const brands = detectedBrands(renderedText(ctx.dom));
    if (brands.length === 0) return { findings: [] };

    const findings: Finding[] = [
      makeFinding({
        ctx,
        rule: mimic002,
        message:
          `This resource contains a password input and claims to be ${brands.map((b) => b.name).join('/')} ` +
          'in its rendered text. A credential prompt combined with a specific brand claim is ' +
          'materially more consistent with impersonation than either signal alone.',
        evidence: brands.map((b) => b.name).join(', '),
      }),
    ];

    return { findings };
  },
});

export default mimic002;

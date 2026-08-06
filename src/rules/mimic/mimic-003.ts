/**
 * PANE-MIMIC-003 — a claimed brand posts to an unrelated origin.
 *
 * A brand-mismatch signal only. This ported the UCI SFH feature (empty or
 * `about:blank` action is suspicious) until it was reduced: in an MCP App the
 * document URL is a `srcdoc` / `blob:` / opaque-origin URL that no attacker
 * controls, so an EMPTY action is the BENIGN case, not the dangerous one. The
 * genuinely dangerous cross-origin case with no brand claim at all is
 * PANE-EXFIL-001, at CRITICAL and non-experimental — this rule does not
 * duplicate it, and requires a brand claim to fire at all.
 */

import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding, originOf } from '../shared/helpers.js';
import { selectAll, attr, attrLocationOf } from '../../parse/html.js';
import { detectedBrands, renderedText } from './shared.js';

const REMEDIATION =
  'If the app genuinely claims to be this brand, point the form at the brand\'s real origin or, ' +
  'better, remove the direct form post entirely and let the host-mediated flow (OAuth via the ' +
  'lazy-auth pattern) handle authentication.';

function hostOf(origin: string): string {
  try {
    return new URL(origin).hostname.toLowerCase();
  } catch {
    return '';
  }
}

export const mimic003 = defineRule({
  id: 'PANE-MIMIC-003',
  ruleClass: 'RISK',
  severity: 'MEDIUM',
  confidence: 'LOW',
  title: 'Claimed brand posts to an unrelated origin',
  specRef: 'docs/RULES.md § PANE-MIMIC — reduced from the UCI SFH feature',
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

    for (const form of selectAll('form[action]', ctx.dom)) {
      const action = (attr(form, 'action') ?? '').trim();
      const origin = originOf(action);
      if (!origin) continue; // empty/relative — the benign case in an MCP App.

      const host = hostOf(origin);
      const matchesClaimedBrand = brands.some((b) => host === b.domain || host.endsWith(`.${b.domain}`));
      if (matchesClaimedBrand) continue;

      findings.push(
        makeFinding({
          ctx,
          rule: mimic003,
          message:
            `The page claims to be ${brands.map((b) => b.name).join('/')} in its rendered text, but ` +
            `<form action> posts to ${host}, an origin unrelated to the claimed brand.`,
          evidence: action,
          location: attrLocationOf(form, 'action'),
          path: `form#${n++}`,
        }),
      );
    }

    return { findings };
  },
});

export default mimic003;

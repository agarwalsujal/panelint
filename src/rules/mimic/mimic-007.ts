/**
 * PANE-MIMIC-007 — `prefersBorder: false` combined with credential-shaped or
 * host-mimicking content.
 *
 * The best-grounded rule in this family, and the only one resting on a
 * DECLARED value rather than a heuristic. SPEC-REFERENCE.md §3.5:
 * `prefersBorder: false` asks the host to remove the visible border and
 * background — while the spec's own social-engineering mitigation is
 * "Hosts should clearly indicate sandboxed UI boundaries." Alone it is
 * unremarkable; plenty of apps legitimately want a seamless chart. It fires
 * only in combination with a credential-shaped field or host-private tokens
 * — asking to look seamless while asking for a password is the signal.
 */

import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding } from '../shared/helpers.js';
import { hasCredentialField, hostPrivateTokens } from './shared.js';

const REMEDIATION =
  'If a seamless boundary is genuinely intended and this content is not credential-collecting or ' +
  'host-mimicking, no change is required. Otherwise, either request a visible border ' +
  '(`prefersBorder: true`) or remove the credential field / host-private styling — the combination ' +
  'is the signal, not either piece alone.';

export const mimic007 = defineRule({
  id: 'PANE-MIMIC-007',
  ruleClass: 'RISK',
  severity: 'HIGH',
  confidence: 'HIGH',
  title: 'prefersBorder:false combined with credential-shaped or host-mimicking content',
  specRef: 'SPEC-REFERENCE.md §3.5 — prefersBorder, the only boundary signal',
  remediation: REMEDIATION,
  experimental: true,
  status: 'active',
  since: '0.1.0',
  requires: ['content', 'meta'],

  check(ctx: RuleContext): RuleResult {
    if (ctx.meta?.prefersBorder !== false) return { findings: [] };

    const hasCred = hasCredentialField(ctx);
    const hostPrivate = hostPrivateTokens(ctx);
    if (!hasCred && hostPrivate.length === 0) return { findings: [] };

    const reasons: string[] = [];
    if (hasCred) reasons.push('a credential-shaped field');
    if (hostPrivate.length > 0) reasons.push('host-private design tokens');

    const findings: Finding[] = [
      makeFinding({
        ctx,
        rule: mimic007,
        message:
          '_meta.ui.prefersBorder is explicitly false — the app asked the host to remove the ' +
          "visible border and background that are the spec's own social-engineering mitigation — " +
          `and the resource also contains ${reasons.join(' and ')}. Asking to look seamless while ` +
          'asking for a credential (or borrowing a host\'s private visual identity) is the signal.',
        evidence: 'prefersBorder:false',
        jsonPointer: '/_meta/ui/prefersBorder',
      }),
    ];

    return { findings };
  },
});

export default mimic007;

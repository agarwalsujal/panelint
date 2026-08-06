/**
 * PANE-SANDBOX-004 — `referrerpolicy="unsafe-url"` on a nested frame.
 *
 * Demoted from RISK/MEDIUM: the rationale "leaks the full URL including
 * tokens" does not hold here. The app document's URL is `about:srcdoc`, a
 * `blob:` URL, or an opaque origin — there are no tokens IN it, and opaque
 * origins send no referrer at all regardless of the declared policy.
 */

import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding, HOST_SANDBOX_ASSUMPTION } from '../shared/helpers.js';
import { selectAll, attr, attrLocationOf } from '../../parse/html.js';
import { withFrameClause } from './shared.js';

const REMEDIATION =
  'Informational only — the app document\'s opaque origin (about:srcdoc, blob:) sends no referrer ' +
  'regardless of this policy, and carries no tokens in its URL to leak. Prefer a stricter policy ' +
  'only for documentation clarity.';

export const sandbox004 = defineRule({
  id: 'PANE-SANDBOX-004',
  ruleClass: 'INFO',
  severity: 'LOW',
  confidence: 'CERTAIN',
  title: 'referrerpolicy="unsafe-url" on a nested frame',
  specRef: 'SPEC-REFERENCE.md §3.3',
  remediation: REMEDIATION,
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['content'],

  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];
    let n = 0;

    for (const el of selectAll('iframe', ctx.dom)) {
      const policy = (attr(el, 'referrerpolicy') ?? '').trim().toLowerCase();
      if (policy !== 'unsafe-url') continue;

      findings.push(
        makeFinding({
          ctx,
          rule: sandbox004,
          message: withFrameClause(
            '<iframe referrerpolicy="unsafe-url"> is declared on a nested frame. The app document\'s ' +
              'URL is about:srcdoc, a blob: URL, or an opaque origin — there are no tokens in it, and ' +
              'opaque origins send no referrer at all.',
          ),
          evidence: policy,
          location: attrLocationOf(el, 'referrerpolicy'),
          assumption: HOST_SANDBOX_ASSUMPTION,
          path: `iframe#${n++}`,
        }),
      );
    }

    return { findings };
  },
});

export default sandbox004;

/**
 * PANE-CSP-005 — a wildcard over ground anyone can publish to.
 *
 * This is where a subdomain wildcard goes, and it fires only when the base is
 * shared hosting. `https://*.mapbox.com` produces nothing; `https://*.github.io`
 * grants every GitHub user in the world a slot in the policy.
 *
 * ⚠ The Public Suffix List private-vs-ICANN delta is NECESSARY BUT NOT
 * SUFFICIENT. The delta also matches `s3.amazonaws.com`,
 * `blob.core.windows.net`, `appspot.com` and `herokuapp.com` — and a first-party
 * bucket namespace is not the threat. `*.mycorp.blob.core.windows.net` must
 * produce nothing. The narrowing is in `isSharedHostingWildcard`: the wildcard
 * has to sit AT the suffix, or on a hand-listed suffix that hands out
 * subdomains to strangers.
 *
 * HIGH confidence, not CERTAIN: the PSL is a snapshot bundled with `tldts`, and
 * whether a given namespace admits strangers is a judgment the list encodes
 * rather than a fact that survives any rendering.
 */

import type { RuleMeta, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding, CSP_SYNTHESIS_ASSUMPTION } from '../shared/helpers.js';
import { allEntries, cspOf, isSharedHostingWildcard, parseSource, pointerFor } from './domains.js';

const meta: RuleMeta = {
  id: 'PANE-CSP-005',
  ruleClass: 'RISK',
  severity: 'HIGH',
  confidence: 'HIGH',
  title: 'Wildcard declared over a shared-hosting namespace',
  specRef: 'SEP-1865 §Security Implications — CSP Enforcement',
  cwe: 'CWE-942',
  remediation:
    'Name the specific subdomain the app uses. A wildcard over a shared-hosting suffix ' +
    'admits every account on that platform, not only yours.',
  experimental: false,
  status: 'active',
  since: '0.1.0',
};

export const paneCsp005 = defineRule({
  ...meta,
  requires: ['meta'],
  check(ctx: RuleContext): RuleResult {
    const csp = cspOf(ctx.meta);
    if (!csp) return { findings: [] };

    const findings = [];
    for (const entry of allEntries(csp)) {
      const parsed = parseSource(entry.value);
      if (parsed.kind !== 'host' || !parsed.host) continue;

      const hit = isSharedHostingWildcard(parsed.host);
      if (!hit) continue;

      findings.push(
        makeFinding({
          ctx,
          rule: meta,
          message:
            `${entry.array} declares ${entry.value}. ${hit.detail}, so this entry admits ` +
            'content published by anyone with an account there — not only content you control.',
          evidence: entry.value,
          jsonPointer: pointerFor(entry.array, entry.index),
          assumption: CSP_SYNTHESIS_ASSUMPTION,
        }),
      );
    }

    return { findings };
  },
});

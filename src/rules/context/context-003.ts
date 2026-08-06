/**
 * PANE-CONTEXT-003 — `ui/open-link` with a string-literal URL.
 *
 * `ui/open-link` is a HOST RPC — it opens the URL in the user's own browser,
 * with the user's own cookies — so it is not subject to the app's CSP at all.
 * A literal URL is simple capability disclosure: the destination is fixed at
 * author time and visible in the source. The dangerous, non-literal case
 * (attacker-controlled or data-bearing destination) is split out to
 * PANE-CONTEXT-008 — see docs/RULES.md § PANE-CONTEXT for why that split
 * exists.
 */

import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding } from '../shared/helpers.js';
import { isLiteralExpression } from '../../parse/js.js';
import type { Node } from 'acorn';
import { scriptsOf, rebase, sourceOf } from '../exfil/url-shape.js';
import { findOpenLinkSites } from './shared.js';

const REMEDIATION =
  'No action required — the destination is a fixed literal, visible in source. If this ever ' +
  'becomes a computed URL, PANE-CONTEXT-008 covers that case at a materially higher severity, ' +
  'because `ui/open-link` is a host RPC with no CSP governing it.';

export const context003 = defineRule({
  id: 'PANE-CONTEXT-003',
  ruleClass: 'INFO',
  severity: 'LOW',
  confidence: 'CERTAIN',
  title: 'App calls ui/open-link with a string-literal URL',
  specRef: 'SPEC-REFERENCE.md §4 — ui/open-link is a host RPC, not subject to the app CSP',
  remediation: REMEDIATION,
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['content'],

  check(ctx: RuleContext): RuleResult {
    const scripts = scriptsOf(ctx);
    const findings: Finding[] = [];
    let n = 0;

    for (const site of findOpenLinkSites(scripts)) {
      if (!isLiteralExpression(site.urlNode as unknown as Node)) continue;
      const loc = rebase(site.script, site.node);
      findings.push(
        makeFinding({
          ctx,
          rule: context003,
          message:
            'The app requests `ui/open-link` with a string-literal URL. The host opens this in the ' +
            'user\'s own browser; it is a host RPC and not subject to the app\'s CSP, but a literal ' +
            'destination is fixed at author time.',
          evidence: sourceOf(site.script, site.node),
          ...(loc ? { location: loc } : {}),
          path: `script#${n++}`,
        }),
      );
    }

    return { findings };
  },
});

export default context003;

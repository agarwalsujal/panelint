/**
 * PANE-MIMIC-001 — a password input is present in an MCP App at all.
 *
 * `ext-apps/examples/lazy-auth-server` is the canonical auth example, and it
 * collects NO credentials in the app: it renders an "Auth me" button, calls a
 * protected tool, receives a 401 with `WWW-Authenticate`, and lets the HOST
 * run the OAuth flow. A password field inside the app itself is therefore
 * worth surfacing.
 *
 * But "an MCP App has no legitimate reason to collect a password" is too
 * strong on its own. A database client legitimately collects a connection
 * password — Metabase is on the adopter list — and `type="password"` is the
 * correct control for an API key or token. Reworded to "credentials
 * collected outside the OAuth flow," MEDIUM confidence, false positives
 * expected.
 */

import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding } from '../shared/helpers.js';
import { selectAll, attr, locationOf } from '../../parse/html.js';

const REMEDIATION =
  'If this is genuinely a credential the app needs (a database connection password, an API key), ' +
  'no change is required. If it is meant to authenticate the PERSON to the host or the server, use ' +
  'the lazy-auth pattern instead: a button that hands off to a tool call, which returns 401 with ' +
  '`WWW-Authenticate` and lets the host run OAuth.';

export const mimic001 = defineRule({
  id: 'PANE-MIMIC-001',
  ruleClass: 'RISK',
  severity: 'HIGH',
  confidence: 'MEDIUM',
  title: 'Password input present in an MCP App',
  specRef: 'docs/RULES.md § PANE-MIMIC — ext-apps/examples/lazy-auth-server',
  remediation: REMEDIATION,
  experimental: true,
  status: 'active',
  since: '0.1.0',
  requires: ['content'],

  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];
    let n = 0;

    for (const el of selectAll('input[type="password"]', ctx.dom)) {
      findings.push(
        makeFinding({
          ctx,
          rule: mimic001,
          message:
            'This app collects a credential outside the OAuth flow via a `type="password"` input. ' +
            'Not necessarily wrong — a database client legitimately collects a connection password, ' +
            'and `type="password"` is the correct control for an API key — but it is worth a look.',
          evidence: attr(el, 'name') ?? attr(el, 'id') ?? 'input[type=password]',
          location: locationOf(el),
          path: `input#${n++}`,
        }),
      );
    }

    return { findings };
  },
});

export default mimic001;

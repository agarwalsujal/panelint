/**
 * PANE-CSP-001 — bare or scheme-only wildcard in `connectDomains`.
 *
 * ⚠ This rule fires on a BARE `*` or a scheme-only source (`https:`) and on
 * nothing else. A first-party subdomain wildcard — `https://*.mapbox.com` — is
 * spec-sanctioned (SPEC-REFERENCE.md §3.1) and produces nothing here. It goes
 * to PANE-CSP-005, which fires only when the base is shared hosting.
 *
 * `csp_evaluator` cannot implement this rule: its checks iterate
 * `DIRECTIVES_CAUSING_XSS`, and `connect-src` is not in that list, so
 * `connectDomains: ["*"]` produces zero findings from it (DESIGN.md §3.3).
 */

import type { RuleMeta, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding, CSP_SYNTHESIS_ASSUMPTION } from '../shared/helpers.js';
import { cspOf, entriesOf, isUnboundedSource, parseSource, pointerFor } from './domains.js';

const meta: RuleMeta = {
  id: 'PANE-CSP-001',
  ruleClass: 'RISK',
  severity: 'HIGH',
  confidence: 'CERTAIN',
  title: 'Wildcard connect-src domain declared',
  specRef: 'SEP-1865 §Security Implications — CSP Enforcement',
  cwe: 'CWE-942',
  remediation: 'Replace the wildcard with the specific origins the app calls.',
  experimental: false,
  status: 'active',
  since: '0.1.0',
};

export const paneCsp001 = defineRule({
  ...meta,
  requires: ['meta'],
  check(ctx: RuleContext): RuleResult {
    const csp = cspOf(ctx.meta);
    if (!csp) return { findings: [] };

    const findings = [];
    for (const entry of entriesOf(csp, 'connectDomains')) {
      const kind = isUnboundedSource(parseSource(entry.value));
      if (!kind) continue;

      const what =
        kind === 'bare-wildcard'
          ? 'permits fetch(), XHR, WebSocket and EventSource to every origin on the internet'
          : `permits those connections to every origin on the ${parseSource(entry.value).scheme}: scheme`;

      findings.push(
        makeFinding({
          ctx,
          rule: meta,
          message:
            `connectDomains declares ${entry.value}, which synthesizes to connect-src ` +
            `'self' ${entry.value}. That ${what}. The host cannot narrow what the server ` +
            'declared — "No Loosening" constrains the host, not the declaration.',
          evidence: entry.value,
          jsonPointer: pointerFor(entry.array, entry.index),
          assumption: CSP_SYNTHESIS_ASSUMPTION,
        }),
      );
    }

    return { findings };
  },
});

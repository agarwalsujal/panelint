/**
 * PANE-CSP-007 — a known JSONP endpoint or hosted AngularJS copy in
 * `resourceDomains`.
 *
 * ⚠ This rule reads `resourceDomains`, NOT `connectDomains`. An earlier
 * revision had it pointed at `connectDomains`, which was a category error it
 * could never recover from: JSONP bypasses matter for `script-src`, which is fed
 * by `resourceDomains`, and an open redirector in `connect-src` buys an attacker
 * nothing — reaching it already requires permission to send it the data, which
 * *is* the exfiltration.
 *
 * The bypass DATA is deep-imported (`allowlist_bypasses/jsonp.js`, 123 URLs;
 * `angular.js`, 41 URLs) rather than obtained by calling
 * `checkScriptAllowlistBypass`, for two reasons. That check unconditionally
 * flags any `'self'` in `script-src` — which the spec's mandated policy contains
 * — so it can never be run. And its finding text says "script-src" where
 * Panelint's finding is about `resourceDomains`. A test asserts both counts, so
 * a dependency bump that empties either list fails CI rather than silently
 * turning this rule into one that can never fire.
 *
 * MEDIUM confidence: the allowlists are a maintained snapshot of endpoints that
 * were exploitable when they were catalogued, and a matched host is evidence
 * that the namespace is risky rather than proof that the app is exploitable.
 */

import type { RuleMeta, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding, CSP_SYNTHESIS_ASSUMPTION } from '../shared/helpers.js';
import { cspOf, entriesOf, parseSource, pointerFor } from './domains.js';
import { angularBypassFor, jsonpBypassFor } from './evaluator-adapter.js';

const meta: RuleMeta = {
  id: 'PANE-CSP-007',
  ruleClass: 'RISK',
  severity: 'HIGH',
  confidence: 'MEDIUM',
  title: 'resourceDomains covers a known script-src allowlist bypass',
  specRef: 'SEP-1865 §Security Implications — CSP Enforcement',
  cwe: 'CWE-829',
  remediation:
    'Narrow the entry to the exact path the app loads, or move to an origin that hosts ' +
    'no JSONP endpoint and no AngularJS build.',
  experimental: false,
  status: 'active',
  since: '0.1.0',
};

export const paneCsp007 = defineRule({
  ...meta,
  requires: ['meta'],
  check(ctx: RuleContext): RuleResult {
    const csp = cspOf(ctx.meta);
    if (!csp) return { findings: [] };

    const findings = [];
    for (const entry of entriesOf(csp, 'resourceDomains')) {
      const parsed = parseSource(entry.value);
      if (parsed.kind !== 'host') continue;

      const jsonp = jsonpBypassFor(entry.value);
      const angular = angularBypassFor(entry.value);
      if (!jsonp && !angular) continue;

      const kinds: string[] = [];
      if (jsonp) kinds.push(`a JSONP endpoint (${jsonp})`);
      if (angular) kinds.push(`a hosted AngularJS build (${angular})`);

      findings.push(
        makeFinding({
          ctx,
          rule: meta,
          message:
            `resourceDomains declares ${entry.value}, which covers ${kinds.join(' and ')}. ` +
            'Because resourceDomains feeds script-src, that origin can be used to execute ' +
            'attacker-chosen code inside the app while the policy still reads as narrow.',
          evidence: entry.value,
          jsonPointer: pointerFor(entry.array, entry.index),
          assumption: CSP_SYNTHESIS_ASSUMPTION,
        }),
      );
    }

    return { findings };
  },
});

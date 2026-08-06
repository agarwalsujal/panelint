/**
 * PANE-INPUT-002 — `autocomplete` token in the payment, address, or identity
 * groups.
 *
 * Capability disclosure, not accusation: an app that requests payment, address
 * or identity autofill is doing something completely ordinary — a checkout
 * form, a profile editor. This rule fires regardless of visibility (that
 * condition is `PANE-INPUT-001`'s job) because the fact worth surfacing is
 * simply "this app collects this category of data," which an operator deciding
 * whether to enable an MCP app is entitled to know before `PANE-INPUT-001`
 * ever has a reason to fire.
 *
 * `CERTAIN` confidence: the `autocomplete` attribute value is read verbatim
 * and matched against the WHATWG token list. No rendering, no cascade, no
 * ambiguity.
 */

import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding, structuralPath } from '../shared/helpers.js';
import { allElements, attr, locationOf } from '../../parse/html.js';
import { autocompleteGroup, sensitiveAutocompleteTokens } from './autocomplete-groups.js';

const REMEDIATION =
  'None required for conformance. Documented here so an operator knows this app requests payment, ' +
  'address, or identity autofill — worth confirming that request matches what the app is meant to do.';

export const input002 = defineRule({
  id: 'PANE-INPUT-002',
  ruleClass: 'RISK',
  severity: 'MEDIUM',
  confidence: 'CERTAIN',
  title: 'autocomplete requests payment, address, or identity autofill',
  specRef: 'WHATWG HTML §form-control-infrastructure — autofill field name categories',
  cwe: 'CWE-359',
  remediation: REMEDIATION,
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['content'],

  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];
    let n = 0;

    for (const el of allElements(ctx.dom)) {
      if (el.tagName !== 'input' && el.tagName !== 'textarea' && el.tagName !== 'select') continue;
      const autocomplete = attr(el, 'autocomplete');
      if (!autocomplete) continue;

      const hits = sensitiveAutocompleteTokens(autocomplete);
      if (hits.length === 0) continue;

      const groups = [...new Set(hits.map((t) => autocompleteGroup(t)).filter((g): g is NonNullable<typeof g> => g !== null))];

      findings.push(
        makeFinding({
          ctx,
          rule: input002,
          message:
            `<${el.tagName} autocomplete="${autocomplete}"> requests ${groups.join('/')} autofill ` +
            `(${hits.join(', ')}). Reported as capability disclosure.`,
          evidence: `autocomplete="${autocomplete}"`,
          location: locationOf(el),
          path: `${structuralPath(el)}#${n++}`,
        }),
      );
    }

    return { findings };
  },
});

export default input002;

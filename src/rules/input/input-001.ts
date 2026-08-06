/**
 * PANE-INPUT-001 — credential- or PII-shaped input concealed by any carrier.
 *
 * The real generalization of `PANE-MIMIC-005` (docs/RULES.md), and unlike the
 * MIMIC family this one is NOT experimental — it composes two deterministic
 * facts rather than a heuristic judgment of visual mimicry. Fact one: the field
 * is shaped to collect a credential or PII, either because `type="password"` or
 * because `autocomplete` names a payment/address/identity field. Fact two: the
 * field is concealed by any `PANE-HIDDEN-*` carrier (`carriersOn`,
 * src/rules/shared/carriers.ts).
 *
 * Browser autofill harvests through EITHER path with no `type="password"`
 * anywhere:
 *
 *     <input autocomplete="cc-number" style="position:absolute;left:-9999px">
 *     <input autocomplete="street-address" style="opacity:0">
 *
 * The browser fills these from its stored autofill data the moment the page
 * loads or the user interacts with a nearby visible field in the same form —
 * no keystrokes needed, and nothing renders to alert the user.
 */

import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding, structuralPath } from '../shared/helpers.js';
import { carriersOn } from '../shared/carriers.js';
import { allElements, attr, locationOf, type Element } from '../../parse/html.js';
import { sensitiveAutocompleteTokens } from './autocomplete-groups.js';

const REMEDIATION =
  'Do not place a credential- or PII-shaped field off-screen, at zero size, or otherwise concealed. ' +
  'If the field is not meant to be seen or filled by the user, remove it — a concealed autofill ' +
  'target has no legitimate purpose and browser autofill will populate it without any user action.';

function shapeReason(el: Element): string | null {
  const type = (attr(el, 'type') ?? 'text').trim().toLowerCase();
  if (type === 'password') return 'type="password"';
  const autocomplete = attr(el, 'autocomplete');
  if (autocomplete) {
    const hits = sensitiveAutocompleteTokens(autocomplete);
    if (hits.length > 0) return `autocomplete="${autocomplete}"`;
  }
  return null;
}

export const input001 = defineRule({
  id: 'PANE-INPUT-001',
  ruleClass: 'RISK',
  severity: 'CRITICAL',
  confidence: 'HIGH',
  title: 'Credential- or PII-shaped input concealed by a hidden-content carrier',
  specRef: 'docs/RULES.md — PANE-INPUT (real generalization of PANE-MIMIC-005, not experimental)',
  cwe: 'CWE-522',
  remediation: REMEDIATION,
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['content'],

  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];
    let n = 0;

    for (const el of allElements(ctx.dom)) {
      if (el.tagName !== 'input' && el.tagName !== 'textarea') continue;
      const type = (attr(el, 'type') ?? '').trim().toLowerCase();
      if (type === 'hidden') continue; // a genuinely inert field, not a concealed one

      const reason = shapeReason(el);
      if (!reason) continue;

      const carriers = carriersOn(el, ctx.styles);
      if (carriers.length === 0) continue;

      findings.push(
        makeFinding({
          ctx,
          rule: input001,
          message:
            `<${el.tagName} ${reason}> is shaped to collect a credential or PII, and is concealed by ` +
            `${carriers.map((c) => c.evidence).join(', ')}. Browser autofill can populate it with no ` +
            'user action and nothing rendered to alert the user.',
          evidence: reason,
          location: locationOf(el),
          path: `${structuralPath(el)}#${n++}`,
        }),
      );
    }

    return { findings };
  },
});

export default input001;

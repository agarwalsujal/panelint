/**
 * PANE-MIMIC-005 — a credential-shaped field that is concealed.
 *
 * Composes with the PANE-HIDDEN carrier vocabulary (../shared/carriers.ts): a
 * password field or a credential-SHAPED field (by name/id, not only by
 * `type="password"`) that is hidden by any declared CSS carrier or the
 * `hidden` attribute has no legitimate rendering reason to exist concealed —
 * a VISIBLE password field is -001's business, not this rule's.
 */

import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding, excerpt } from '../shared/helpers.js';
import { carriersOn } from '../shared/carriers.js';
import { selectAll, locationOf, attr } from '../../parse/html.js';
import { isCredentialShaped } from './shared.js';

const REMEDIATION =
  'Remove the concealed credential field, or render it visibly. A credential control with no ' +
  'visible presence has no legitimate reason to collect input from the person using the app.';

export const mimic005 = defineRule({
  id: 'PANE-MIMIC-005',
  ruleClass: 'RISK',
  severity: 'CRITICAL',
  confidence: 'MEDIUM',
  title: 'Credential-shaped field that is concealed',
  cwe: 'CWE-451',
  specRef: 'docs/RULES.md § PANE-MIMIC — composes with PANE-HIDDEN',
  remediation: REMEDIATION,
  experimental: true,
  status: 'active',
  since: '0.1.0',
  requires: ['content'],

  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];
    let n = 0;

    for (const el of selectAll('input', ctx.dom)) {
      if (!isCredentialShaped(el)) continue;
      const carriers = carriersOn(el, ctx.styles);
      if (carriers.length === 0) continue;

      findings.push(
        makeFinding({
          ctx,
          rule: mimic005,
          message:
            `A credential-shaped <input> (${excerpt(attr(el, 'name') ?? attr(el, 'id') ?? el.tagName)}) ` +
            `is concealed by ${carriers.map((c) => c.evidence).join(', ')}. A concealed credential ` +
            'field has no legitimate rendering reason to exist.',
          evidence: carriers.map((c) => c.evidence).join(', '),
          location: locationOf(el),
          path: `input#${n++}`,
        }),
      );
    }

    return { findings };
  },
});

export default mimic005;

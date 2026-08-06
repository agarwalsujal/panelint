/**
 * PANE-CSP-009 — a declared `connectDomains` origin the app never contacts.
 *
 * Over-declaration. Not dangerous on its own, which is why this is LOW/MEDIUM
 * and well below the default gate, but it is worth telling an author: a domain
 * declared and unused is permission granted for nothing, and it is usually a
 * copy-paste left over from a template or a service that was removed.
 *
 * MEDIUM confidence, and the reason is honest rather than conventional: this is
 * a static scan of one resource. An app can build a URL at runtime, fetch from
 * a worker, or reach the origin from a code path this resource does not
 * contain. So "the host appears nowhere in this document" is evidence of
 * non-use, not proof of it — and the rule says so rather than asserting the
 * domain is dead.
 *
 * A wildcard entry resolves against its base domain: `https://*.mapbox.com` is
 * used if anything in the document mentions `mapbox.com`.
 */

import type { RuleContext, RuleResult, Finding } from '../../types.js';
import { defineRule, makeFinding, CSP_SYNTHESIS_ASSUMPTION } from '../shared/helpers.js';
import { cspOf, entriesOf, parseSource, pointerFor } from './domains.js';

export const paneCsp009 = defineRule({
  id: 'PANE-CSP-009',
  ruleClass: 'RISK',
  severity: 'LOW',
  confidence: 'MEDIUM',
  title: 'connectDomains declares an origin the app never contacts',
  specRef: 'SEP-1865 §Security Implications — CSP Enforcement',
  remediation:
    'Remove origins the app does not contact. A declared domain the app never ' +
    'uses is permission granted for nothing.',
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['meta', 'content'],

  check(ctx: RuleContext): RuleResult {
    const csp = cspOf(ctx.meta);
    if (csp === null) return { findings: [] };

    const haystack = ctx.rawSource.toLowerCase();
    const findings: Finding[] = [];

    for (const entry of entriesOf(csp, 'connectDomains')) {
      const parsed = parseSource(entry.value);
      const host = parsed.host;
      if (!host) continue;

      // A wildcard is used if its base domain appears anywhere.
      const needle = host.startsWith('*.') ? host.slice(2) : host;
      if (!needle) continue;
      if (haystack.includes(needle)) continue;

      findings.push(
        makeFinding({
          ctx,
          rule: paneCsp009,
          message:
            `\`${entry.value}\` is declared in connectDomains but appears nowhere in ` +
            'this resource. It may still be reached from a runtime-built URL or from ' +
            'code this resource does not contain, so this is evidence of non-use ' +
            'rather than proof of it.',
          jsonPointer: pointerFor(entry.array, entry.index),
          path: `${entry.array}[${entry.index}]`,
          assumption: CSP_SYNTHESIS_ASSUMPTION,
        }),
      );
    }

    return { findings };
  },
});

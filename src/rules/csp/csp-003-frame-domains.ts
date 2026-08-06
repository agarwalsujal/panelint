/**
 * PANE-CSP-003 — `frameDomains` non-empty.
 *
 * Omitting the field yields `frame-src 'none'`. Declaring anything at all turns
 * nested framing on, and a nested frame is a surface the operator reviewing the
 * app's markup never sees. This is capability disclosure with a risk edge, not
 * an accusation — hence MEDIUM.
 *
 * One finding per array, not per entry: the fact being reported is that the
 * field is non-empty, and the individual origins are evidence for it.
 */

import type { RuleMeta, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding, CSP_SYNTHESIS_ASSUMPTION } from '../shared/helpers.js';
import { cspOf, entriesOf, pointerFor } from './domains.js';

const meta: RuleMeta = {
  id: 'PANE-CSP-003',
  ruleClass: 'RISK',
  severity: 'MEDIUM',
  confidence: 'CERTAIN',
  title: 'Nested frames permitted — frame-src widened from the default of none',
  specRef: 'SEP-1865 §Security Implications — CSP Enforcement',
  cwe: 'CWE-1021',
  remediation:
    'Remove frameDomains unless the app genuinely nests a frame. Omitting the field ' +
    "yields frame-src 'none'.",
  experimental: false,
  status: 'active',
  since: '0.1.0',
};

export const paneCsp003 = defineRule({
  ...meta,
  requires: ['meta'],
  check(ctx: RuleContext): RuleResult {
    const csp = cspOf(ctx.meta);
    if (!csp) return { findings: [] };

    const entries = entriesOf(csp, 'frameDomains');
    if (entries.length === 0) return { findings: [] };

    return {
      findings: [
        makeFinding({
          ctx,
          rule: meta,
          message:
            `frameDomains declares ${entries.length} origin${entries.length === 1 ? '' : 's'}, ` +
            "so frame-src is widened from its default of 'none'. Content inside a nested " +
            'frame is not visible in this resource and is not analyzed by Panelint.',
          evidence: entries.map((e) => e.value).join(' '),
          jsonPointer: pointerFor('frameDomains'),
          assumption: CSP_SYNTHESIS_ASSUMPTION,
        }),
      ],
    };
  },
});

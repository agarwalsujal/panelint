/**
 * PANE-SANDBOX-002 — nested iframe declares no `sandbox` attribute.
 *
 * Demoted from RISK/HIGH: a nested browsing context INHERITS its ancestor's
 * sandbox flags and cannot acquire flags the parent lacks, so omitting
 * `sandbox` on a child of a sandboxed pane grants the child nothing. Flagging
 * it fires on the legitimate `srcdoc` pattern and describes no privilege
 * gain — exactly what docs/GOALS.md G2 calls non-negotiable.
 */

import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding, HOST_SANDBOX_ASSUMPTION } from '../shared/helpers.js';
import { selectAll, attr, locationOf } from '../../parse/html.js';
import { withFrameClause } from './shared.js';

const REMEDIATION =
  'Informational only — inheritance already applies the ancestor\'s flags. Declare `sandbox` ' +
  'explicitly only if you want documentation of the intended restriction, not because omitting it ' +
  'is a gap.';

export const sandbox002 = defineRule({
  id: 'PANE-SANDBOX-002',
  ruleClass: 'INFO',
  severity: 'LOW',
  confidence: 'CERTAIN',
  title: 'Nested iframe declares no sandbox attribute',
  specRef: 'SPEC-REFERENCE.md §3.3',
  remediation: REMEDIATION,
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['content'],

  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];
    let n = 0;

    for (const el of selectAll('iframe', ctx.dom)) {
      if (attr(el, 'sandbox') !== undefined) continue;
      findings.push(
        makeFinding({
          ctx,
          rule: sandbox002,
          message: withFrameClause(
            'This nested <iframe> declares no sandbox attribute of its own, so it simply ' +
              "inherits its ancestor's sandbox flags — it cannot gain anything by omitting one.",
          ),
          location: locationOf(el),
          assumption: HOST_SANDBOX_ASSUMPTION,
          path: `iframe#${n++}`,
        }),
      );
    }

    return { findings };
  },
});

export default sandbox002;

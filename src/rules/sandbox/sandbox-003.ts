/**
 * PANE-SANDBOX-003 — wildcard `allow=` allowlist on a nested frame.
 *
 * Demoted from RISK/HIGH: a child cannot receive a Permissions Policy feature
 * the parent was never granted, so `allow="camera *"` on its own describes no
 * privilege gain. The genuinely dangerous version — re-delegating a feature
 * the SERVER declared in `_meta.ui.permissions` to a nested third-party frame
 * — is PANE-SANDBOX-007.
 */

import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding, HOST_SANDBOX_ASSUMPTION } from '../shared/helpers.js';
import { selectAll, attr, attrLocationOf } from '../../parse/html.js';
import { hasWildcardAllow, withFrameClause } from './shared.js';

const REMEDIATION =
  'Informational only — a wildcard allowlist cannot grant a feature the ancestor never had. Prefer ' +
  'a specific origin over `*` for documentation clarity, not because the wildcard itself is unsafe ' +
  'here.';

export const sandbox003 = defineRule({
  id: 'PANE-SANDBOX-003',
  ruleClass: 'INFO',
  severity: 'LOW',
  confidence: 'CERTAIN',
  title: 'Wildcard allow= allowlist on a nested frame',
  specRef: 'SPEC-REFERENCE.md §3.2, §3.3',
  remediation: REMEDIATION,
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['content'],

  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];
    let n = 0;

    for (const el of selectAll('iframe', ctx.dom)) {
      const allowValue = attr(el, 'allow');
      if (!allowValue || !hasWildcardAllow(allowValue)) continue;

      findings.push(
        makeFinding({
          ctx,
          rule: sandbox003,
          message: withFrameClause(
            `<iframe allow="${allowValue}"> grants a wildcard (*) allowlist to a nested frame. It ` +
              'cannot receive a feature the ancestor was never granted, so this describes no ' +
              'privilege gain on its own.',
          ),
          evidence: allowValue,
          location: attrLocationOf(el, 'allow'),
          assumption: HOST_SANDBOX_ASSUMPTION,
          path: `iframe#${n++}`,
        }),
      );
    }

    return { findings };
  },
});

export default sandbox003;

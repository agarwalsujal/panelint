/**
 * PANE-SANDBOX-007 — a declared permission is re-delegated via `allow=` to a
 * nested THIRD-PARTY frame.
 *
 * The genuinely dangerous version of `-003`: a wildcard allowlist alone
 * cannot exceed the ancestor's grant, but handing a permission the SERVER
 * itself declared in `_meta.ui.permissions` to a cross-origin nested frame
 * extends that grant to code the server does not control. Relative (same-
 * document) frames are exempt — there is no third party to re-delegate to.
 */

import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding, HOST_SANDBOX_ASSUMPTION, isAbsoluteOffOrigin } from '../shared/helpers.js';
import { selectAll, attr, attrLocationOf } from '../../parse/html.js';
import { PERMISSION_FEATURES, allowFeatureNames, withFrameClause } from './shared.js';

const REMEDIATION =
  'Do not pass a permission the server declared for this app\'s own use through to a nested ' +
  'third-party frame via `allow=`. If the third party genuinely needs it, that is a decision for ' +
  'the operator to make explicitly, not something this markup should do implicitly.';

export const sandbox007 = defineRule({
  id: 'PANE-SANDBOX-007',
  ruleClass: 'RISK',
  severity: 'HIGH',
  confidence: 'CERTAIN',
  title: 'Declared permission re-delegated to a nested third-party frame',
  cwe: 'CWE-441',
  specRef: 'SPEC-REFERENCE.md §3.2, §3.3',
  remediation: REMEDIATION,
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['content', 'meta'],

  check(ctx: RuleContext): RuleResult {
    const perms = ctx.meta?.permissions ?? {};
    const findings: Finding[] = [];
    let n = 0;

    for (const el of selectAll('iframe', ctx.dom)) {
      const src = (attr(el, 'src') ?? '').trim();
      if (!isAbsoluteOffOrigin(src)) continue;

      const allowValue = attr(el, 'allow');
      if (!allowValue) continue;
      const features = new Set(allowFeatureNames(allowValue));

      let hostname = src;
      try {
        hostname = new URL(src).hostname;
      } catch {
        /* keep the raw src as evidence */
      }

      for (const [permKey, featureName] of Object.entries(PERMISSION_FEATURES)) {
        if (!(perms as Record<string, unknown>)[permKey]) continue;
        if (!features.has(featureName)) continue;

        findings.push(
          makeFinding({
            ctx,
            rule: sandbox007,
            message: withFrameClause(
              `_meta.ui.permissions declares "${permKey}", and this nested <iframe allow="` +
                `${allowValue}"> re-delegates the "${featureName}" Permissions-Policy feature to ` +
                `the third-party origin ${hostname}.`,
            ),
            evidence: src,
            location: attrLocationOf(el, 'allow'),
            assumption: HOST_SANDBOX_ASSUMPTION,
            path: `iframe#${n++}`,
          }),
        );
      }
    }

    return { findings };
  },
});

export default sandbox007;

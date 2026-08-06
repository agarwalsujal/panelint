/**
 * PANE-CSP-013 — `_meta.ui.csp` is present but declares nothing.
 *
 * A spec quirk, found by diffing the two policies the specification defines
 * rather than from any known incident.
 *
 *   Omitting `ui.csp` entirely  → `connect-src 'none'`   (the restrictive default)
 *   Declaring `"csp": {}`       → `connect-src 'self'`   (the CSP construction)
 *
 * So an author who writes `"csp": {}` **to mean "lock this down" receives more
 * permission than one who writes nothing at all.** It inverts the author's
 * intent silently, which is exactly the failure the PANE-SCHEMA family exists
 * to catch. Reported at INFO because no host behaviour is confirmed to differ
 * in practice given the sandboxed opaque origin.
 *
 * ### ✅ Confirmed in the wild, twice, within an hour of the rule being written
 *
 * A 21-server hand-scan on 2026-08-05 found two independent servers declaring
 * exactly this shape:
 *
 *     csp: { connectDomains: [], resourceDomains: [] }          // TypeScript
 *     "csp": {"connectDomains": [], "resourceDomains": []}      # Python
 *
 * Both authors evidently meant "this app makes no network requests". Both
 * received `connect-src 'self'` instead of `'none'`.
 *
 * ⚠ **"Empty" is NOT `Object.keys(csp).length === 0`.** That predicate misses
 * both real-world confirmations, which each carried two keys holding empty
 * arrays. Empty means: every one of the four fields is absent, or present and
 * empty. `test/rules-csp.test.ts` locks that distinction.
 */

import type { RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding, CSP_SYNTHESIS_ASSUMPTION } from '../shared/helpers.js';
import { CSP_ARRAYS, cspOf, fieldIsEmpty, pointerFor } from './domains.js';

export const paneCsp013 = defineRule({
  id: 'PANE-CSP-013',
  ruleClass: 'INFO',
  severity: 'LOW',
  confidence: 'CERTAIN',
  title: 'csp declared but empty — yields connect-src \'self\', not \'none\'',
  specRef: 'SEP-1865 §Security Implications — CSP Enforcement',
  remediation:
    'Omit `_meta.ui.csp` entirely to get `connect-src \'none\'`. Declaring an empty ' +
    '`csp` object runs the host\'s CSP construction instead, which yields ' +
    '`connect-src \'self\'` — more permissive than declaring nothing.',
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['meta'],

  check(ctx: RuleContext): RuleResult {
    const csp = cspOf(ctx.meta);
    if (csp === null) return { findings: [] };

    // Every field absent, or present and empty.
    const declaresNothing = CSP_ARRAYS.every((array) => fieldIsEmpty(csp, array));
    if (!declaresNothing) return { findings: [] };

    return {
      findings: [
        makeFinding({
          ctx,
          rule: paneCsp013,
          message:
            '`_meta.ui.csp` is present but declares no domains. The host runs its CSP ' +
            'construction rather than the restrictive default, so this yields ' +
            "`connect-src 'self'` — more permissive than omitting `csp` entirely, which " +
            "would yield `connect-src 'none'`.",
          jsonPointer: pointerFor('connectDomains').replace('/connectDomains', ''),
          path: 'csp',
          assumption: CSP_SYNTHESIS_ASSUMPTION,
        }),
      ],
    };
  },
});

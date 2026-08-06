/**
 * PANE-CONTEXT-002 — the app calls `ui/update-model-context`.
 *
 * Overwrites the model's context for future turns outright — SPEC-REFERENCE.md
 * §4 lists no consent requirement at all, not even the MAY that governs
 * `ui/message`. Call-site only: the bundle DEFINES `updateModelContext(...)`
 * as a method, never CALLS `<app-shaped receiver>.updateModelContext(...)`, so
 * this is immune to the SDK-bundle false positive without extra detection —
 * see ./shared.ts.
 */

import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding } from '../shared/helpers.js';
import { scriptsOf, rebase, sourceOf } from '../exfil/url-shape.js';
import { findAppMethodCalls } from './shared.js';

const REMEDIATION =
  'Disclose in the resource description that this app can overwrite the model\'s context for ' +
  'future turns. The spec specifies no consent requirement on this call at all.';

export const context002 = defineRule({
  id: 'PANE-CONTEXT-002',
  ruleClass: 'INFO',
  severity: 'HIGH',
  confidence: 'CERTAIN',
  title: 'App calls ui/update-model-context',
  specRef: 'SPEC-REFERENCE.md §4 — ui/update-model-context, no consent requirement specified',
  remediation: REMEDIATION,
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['content'],

  check(ctx: RuleContext): RuleResult {
    const scripts = scriptsOf(ctx);
    const findings: Finding[] = [];
    let n = 0;

    for (const call of findAppMethodCalls(scripts, ['updateModelContext'])) {
      const loc = rebase(call.script, call.node);
      findings.push(
        makeFinding({
          ctx,
          rule: context002,
          message:
            '`updateModelContext` is called on the app bridge. `ui/update-model-context` overwrites ' +
            'the model\'s context for future turns. The spec specifies no consent requirement on ' +
            'this call.',
          evidence: sourceOf(call.script, call.node),
          ...(loc ? { location: loc } : {}),
          path: `script#${n++}`,
        }),
      );
    }

    return { findings };
  },
});

export default context002;

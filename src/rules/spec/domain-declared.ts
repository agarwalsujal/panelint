/**
 * PANE-SPEC-008 — `_meta.ui.domain` declared.
 *
 * ── Correction [v3] — this was class `SPEC` for something that violates no MUST ──
 * Declaring `_meta.ui.domain` is a documented, schema-valid feature request for a
 * dedicated sandbox origin. Nothing in SEP-1865 forbids it, so `SPEC` was a
 * category error of exactly the kind the classification model at the top of
 * docs/RULES.md exists to prevent. Reclassed to `INFO`, where its `INFO`
 * severity already put it in practice.
 *
 * It also duplicates `PANE-CONTEXT-006`, which reports the same declaration with
 * the consequence attached: a stable origin makes app-side storage persist
 * across conversations. The two are deduped on `(resource, json-pointer)` in the
 * dedup stage, and `PANE-CONTEXT-006` wins there because it tells the operator
 * what the declaration *does*. This rule still exists as the structural fact —
 * "domain was declared" — independent of that consequence.
 *
 * An empty-string domain requests nothing, so it is silent rather than reported:
 * a value that asks for no dedicated origin is not the declaration this rule is
 * about.
 */

import { defineRule, makeFinding, NO_FINDINGS } from '../shared/helpers.js';
import type { RuleResult } from '../../types.js';

export const paneSpec008 = defineRule({
  id: 'PANE-SPEC-008',
  ruleClass: 'INFO',
  severity: 'INFO',
  confidence: 'CERTAIN',
  title: '_meta.ui.domain declared — server requests a dedicated sandbox origin',
  specRef: 'SPEC-REFERENCE.md §2 — _meta.ui.domain',
  remediation:
    'No action required. This reports what the server requested, not a defect — see ' +
    'PANE-CONTEXT-006 for the consequence of a stable, dedicated origin.',
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['meta'],

  check(ctx): RuleResult {
    const domain = ctx.meta?.domain;
    if (typeof domain !== 'string' || domain.trim() === '') return NO_FINDINGS;

    return {
      findings: [
        makeFinding({
          ctx,
          rule: paneSpec008,
          message:
            '_meta.ui.domain is declared — the server requests a dedicated sandbox origin for ' +
            'this view.',
          evidence: domain,
          jsonPointer: '/domain',
          path: 'domain',
        }),
      ],
    };
  },
});

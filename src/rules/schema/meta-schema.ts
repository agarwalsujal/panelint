/**
 * PANE-SCHEMA-004 — `_meta.ui` validates against the published JSON Schema.
 *
 * The catch-all for `ctx.schemaErrors` — every violation not already claimed by
 * a more specific rule. `additionalProperties` errors are excluded outright:
 * they belong to `PANE-SCHEMA-001` (`/csp`), `-002` (`/permissions`), or `-006`
 * (root), and reporting them again here would double the finding for the same
 * mistake.
 *
 * Reads the SAME `ajv` run as the rest of the family (`src/parse/meta.ts`); this
 * file compiles no schema of its own.
 */

import { defineRule, makeFinding, NO_FINDINGS } from '../shared/helpers.js';
import type { Finding, RuleResult } from '../../types.js';

/** Reporting ceiling, so a maximally malformed document cannot flood a report. */
const MAX_REPORTED = 25;

export const paneSchema004 = defineRule({
  id: 'PANE-SCHEMA-004',
  ruleClass: 'SCHEMA',
  severity: 'MEDIUM',
  confidence: 'CERTAIN',
  title: '_meta.ui does not validate against the published JSON Schema',
  specRef: 'SPEC-REFERENCE.md §2 — McpUiResourceMeta',
  remediation:
    'Fix the reported field so _meta.ui matches the published schema. Unknown keys are reported ' +
    'by PANE-SCHEMA-001/002/006 instead — this rule covers every other violation.',
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['meta'],

  check(ctx): RuleResult {
    const relevant = ctx.schemaErrors.filter((e) => e.keyword !== 'additionalProperties');
    if (relevant.length === 0) return NO_FINDINGS;

    const findings: Finding[] = relevant.slice(0, MAX_REPORTED).map((e) => {
      const pointer = e.instancePath || '';
      return makeFinding({
        ctx,
        rule: paneSchema004,
        message: `_meta.ui${pointer} fails schema validation: ${e.message ?? e.keyword}.`,
        ...(pointer ? { jsonPointer: pointer } : {}),
        path: pointer || 'root',
      });
    });

    if (relevant.length > MAX_REPORTED) {
      ctx.diagnostic(
        'LIMIT_EXCEEDED',
        `PANE-SCHEMA-004 reported ${MAX_REPORTED} of ${relevant.length} schema violations`,
        'The report is truncated. The resource fails schema validation in more places than a report can usefully carry.',
      );
    }

    return { findings };
  },
});

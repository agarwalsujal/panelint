/**
 * PANE-SPEC-003 — resource content supplied via `text` or `blob`.
 *
 * A `resources/read` content item carries its payload in exactly one of `text`
 * or `blob`. A UI resource with neither is a declaration with nothing behind it:
 * the host has an entry to render and no document to put in the frame.
 *
 * By the time a rule runs, both forms have collapsed into `UIResource.content`
 * (with `fromBlob` recording which one it was), so the observable fact is that
 * the content is empty. Whitespace-only content is deliberately NOT a finding —
 * "empty" is the structural fact this rule reports, and "short" is a judgment
 * call that belongs to no rule in this catalog.
 */

import { defineRule, makeFinding, NO_FINDINGS } from '../shared/helpers.js';
import type { RuleResult } from '../../types.js';

export const paneSpec003 = defineRule({
  id: 'PANE-SPEC-003',
  ruleClass: 'SPEC',
  severity: 'MEDIUM',
  confidence: 'CERTAIN',
  title: 'Resource carries no content in either text or blob',
  specRef: 'SPEC-REFERENCE.md §2 — Resource model',
  remediation:
    'Return the app HTML in the content item\'s text field, or base64 in blob. A ui:// entry ' +
    'with neither gives the host nothing to render.',
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['content'],

  check(ctx): RuleResult {
    if (ctx.resource.content.length > 0) return NO_FINDINGS;

    const via = ctx.resource.fromBlob ? 'blob' : 'text';
    return {
      findings: [
        makeFinding({
          ctx,
          rule: paneSpec003,
          message:
            `Resource content is empty — the ${via} field carried no bytes, so the host has ` +
            `nothing to render for this ui:// entry.`,
          jsonPointer: `/${via}`,
          path: 'content',
        }),
      ],
    };
  },
});

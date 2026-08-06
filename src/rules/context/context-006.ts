/**
 * PANE-CONTEXT-006 — `_meta.ui.domain` declares a stable sandbox origin.
 *
 * Disclosure, not a defect. SPEC-REFERENCE.md §3.4: the default sandbox
 * origin is *per-conversation*, so app-side `localStorage`, `sessionStorage`,
 * IndexedDB and cookies are naturally discarded between conversations. A
 * declared `domain` makes app storage persist and become
 * cross-conversation-correlatable. Legitimate — OAuth callbacks genuinely
 * need it — and worth knowing.
 */

import type { RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding } from '../shared/helpers.js';

const REMEDIATION =
  'No action required if the persistent origin is intentional (e.g. an OAuth callback needs a ' +
  'stable redirect URI). If it was not intentional, remove `domain` and let the host use its ' +
  'default per-conversation sandbox origin.';

export const context006 = defineRule({
  id: 'PANE-CONTEXT-006',
  ruleClass: 'INFO',
  severity: 'MEDIUM',
  confidence: 'CERTAIN',
  title: '_meta.ui.domain declares a stable, cross-conversation origin',
  specRef: 'SPEC-REFERENCE.md §3.4 — domain: dedicated origin for the view sandbox',
  remediation: REMEDIATION,
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['meta'],

  check(ctx: RuleContext): RuleResult {
    const domain = ctx.meta?.domain;
    if (typeof domain !== 'string' || !domain.trim()) return { findings: [] };

    return {
      findings: [
        makeFinding({
          ctx,
          rule: context006,
          message:
            `_meta.ui.domain declares "${domain}" as a dedicated sandbox origin. The default ` +
            'sandbox origin is per-conversation, so app-side localStorage, IndexedDB and cookies ' +
            'are naturally discarded between conversations — this declaration makes them persist ' +
            'and become cross-conversation-correlatable. Legitimate (OAuth callbacks need it) and ' +
            'worth disclosing.',
          evidence: domain,
          jsonPointer: '/_meta/ui/domain',
        }),
      ],
    };
  },
});

export default context006;

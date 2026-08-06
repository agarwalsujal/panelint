/**
 * PANE-SANDBOX-005 — a permission declared in `_meta.ui.permissions` that the
 * HTML never uses.
 *
 * Over-declaration is untidy, not dangerous — the attacker's move is the
 * inverse (PANE-SANDBOX-006). Feature detection counts as "use" here, on
 * purpose: SPEC-REFERENCE.md §3.2 recommends it ("Apps SHOULD NOT assume
 * permissions are granted; use JS feature detection as fallback"), and this
 * rule is not the one that should punish following that guidance. When a
 * script this document loads cannot be read (an external `src`), the rule
 * declines rather than assumes the permission is unused.
 */

import type { Finding, RuleContext, RuleResult, UndecidedNote } from '../../types.js';
import { defineRule, makeFinding, undecided, HOST_SANDBOX_ASSUMPTION } from '../shared/helpers.js';
import { selectAll } from '../../parse/html.js';
import { scriptsOf } from '../exfil/url-shape.js';
import { navigatorAccessedFeatures, withFrameClause } from './shared.js';

const REMEDIATION =
  'Remove the unused permission from `_meta.ui.permissions`, or use it — an unused declaration ' +
  'widens what the host may grant this app for no benefit.';

export const sandbox005 = defineRule({
  id: 'PANE-SANDBOX-005',
  ruleClass: 'RISK',
  severity: 'LOW',
  confidence: 'MEDIUM',
  title: 'Declared permission the HTML never uses',
  specRef: 'SPEC-REFERENCE.md §3.2',
  remediation: REMEDIATION,
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['content', 'meta'],

  check(ctx: RuleContext): RuleResult {
    const perms = ctx.meta?.permissions ?? {};
    const declared = Object.keys(perms).filter((k) => (perms as Record<string, unknown>)[k] !== undefined);
    if (declared.length === 0) return { findings: [] };

    const used = navigatorAccessedFeatures(scriptsOf(ctx));
    const hasUnreadableScript = selectAll('script[src]', ctx.dom).length > 0;

    const findings: Finding[] = [];
    const notes: UndecidedNote[] = [];

    for (const key of declared) {
      if (used.has(key)) continue;

      if (hasUnreadableScript) {
        notes.push(
          undecided(
            ctx,
            sandbox005,
            `_meta.ui.permissions declares "${key}" and this document loads at least one external ` +
              'script whose content cannot be inspected, so whether it uses this permission cannot ' +
              'be determined',
          ),
        );
        continue;
      }

      findings.push(
        makeFinding({
          ctx,
          rule: sandbox005,
          message: withFrameClause(
            `_meta.ui.permissions declares "${key}", but no script visible in this resource ` +
              'references it — not even via feature detection.',
          ),
          evidence: key,
          jsonPointer: `/_meta/ui/permissions/${key}`,
          assumption: HOST_SANDBOX_ASSUMPTION,
        }),
      );
    }

    return { findings, ...(notes.length ? { undecided: notes } : {}) };
  },
});

export default sandbox005;

/**
 * PANE-CONTEXT-010 — a side-effecting tool the app itself can call.
 *
 * `visibility` DEFAULTS to `["model", "app"]` (SPEC-REFERENCE.md §2.2), so
 * "has 'app' in visibility and no readOnlyHint" would match almost every tool
 * in the ecosystem if `visibility` merely being absent counted. It must not:
 * an EXPLICIT `visibility` that includes `"app"` is required for that signal.
 *
 * The second, independent signal is a destructive-verb tool name — `app` is
 * already in scope there via the (possibly implicit) default, so this signal
 * does not require an explicit declaration, only the absence of
 * `readOnlyHint: true`.
 */

import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding } from '../shared/helpers.js';

const REMEDIATION =
  'If the app should be able to trigger this without the model in the loop, confirm that is ' +
  'intentional and document it. If the tool is actually read-only, declare `readOnlyHint: true`.';

const DESTRUCTIVE_VERB = /^(delete|remove|destroy|drop|purge|revoke|terminate|cancel|wipe|clear|uninstall|disable)_/i;

export const context010 = defineRule({
  id: 'PANE-CONTEXT-010',
  ruleClass: 'RISK',
  severity: 'MEDIUM',
  confidence: 'MEDIUM',
  title: 'Side-effecting tool with app-visibility and no readOnlyHint',
  specRef: 'SPEC-REFERENCE.md §2.2 — visibility, tool annotations',
  remediation: REMEDIATION,
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['tools'],

  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];
    let n = 0;

    for (const tool of ctx.tools) {
      if (tool.meta?.resourceUri !== ctx.resource.uri) continue;
      if (tool.annotations?.readOnlyHint === true) continue;

      const visibility = tool.meta?.visibility;
      const explicitAppVisible = Array.isArray(visibility) && visibility.includes('app');
      const destructiveName = DESTRUCTIVE_VERB.test(tool.name);
      if (!explicitAppVisible && !destructiveName) continue;

      const why = explicitAppVisible
        ? 'declares "app" in `visibility` with no `readOnlyHint: true`'
        : 'has a destructive-verb name with no `readOnlyHint: true`, and the app-callable default ' +
          'is in scope';

      findings.push(
        makeFinding({
          ctx,
          rule: context010,
          message: `Tool \`${tool.name}\` ${why}. Verify it is not reachable by the app without the model's involvement.`,
          evidence: tool.name,
          path: `tools/${tool.name}#${n++}`,
        }),
      );
    }

    return { findings };
  },
});

export default context010;

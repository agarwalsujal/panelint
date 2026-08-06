/**
 * PANE-CONTEXT-004 — a tool declares `visibility: ["app"]` with no `"model"`.
 *
 * SPEC-REFERENCE.md §2.2: `visibility` defaults to `["model", "app"]`; a host
 * MUST NOT include a tool in the agent's tool list when `visibility` omits
 * `"model"`. A tool the model can never see, but the app on the same
 * connection can call, is a private channel between the resource and the
 * server — worth an operator's attention, not necessarily wrong.
 *
 * Attribution is scoped to THIS resource: a tool's `_meta.ui.resourceUri`
 * must match the resource under scan, so a finding on `app.html` is not
 * produced by a tool that actually belongs to `other.html`.
 */

import type { Finding, RuleContext, RuleResult, ToolWithUIMeta } from '../../types.js';
import { defineRule, makeFinding } from '../shared/helpers.js';

const REMEDIATION =
  'If this tool is genuinely app-only, document why in the tool description. If the model should ' +
  'also be able to call it, add `"model"` to `visibility`.';

function toolsOf(ctx: RuleContext): ToolWithUIMeta[] {
  const tools = ctx.options['tools'];
  return Array.isArray(tools) ? (tools as ToolWithUIMeta[]) : [];
}

export const context004 = defineRule({
  id: 'PANE-CONTEXT-004',
  ruleClass: 'INFO',
  severity: 'MEDIUM',
  confidence: 'CERTAIN',
  title: 'Server declares tools with visibility: ["app"] only',
  specRef: 'SPEC-REFERENCE.md §2.2 — visibility defaults to ["model","app"]',
  remediation: REMEDIATION,
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['tools'],

  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];
    let n = 0;

    for (const tool of toolsOf(ctx)) {
      const visibility = tool.meta?.visibility;
      if (!Array.isArray(visibility)) continue;
      if (!visibility.includes('app') || visibility.includes('model')) continue;
      if (tool.meta?.resourceUri !== ctx.resource.uri) continue;

      findings.push(
        makeFinding({
          ctx,
          rule: context004,
          message:
            `Tool \`${tool.name}\` declares \`visibility: ["app"]\` with no "model" — the host MUST ` +
            'NOT include it in the agent\'s tool list, so only the app running on this resource can ' +
            'call it. A private channel between this resource and the server.',
          evidence: tool.name,
          path: `tools/${tool.name}#${n++}`,
        }),
      );
    }

    return { findings };
  },
});

export default context004;

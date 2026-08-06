/**
 * PANE-MIMIC-004 — host-PRIVATE design tokens, not the sanctioned set.
 *
 * The spec SUPPLIES apps with the host's own colours and fonts BY DESIGN:
 * `McpUiStyleVariableKey` enumerates a fixed 76-member set of CSS custom
 * properties across the background/text/border/ring colour families, fonts,
 * border radii, border width and shadows (SPEC-REFERENCE.md §3.6). Visual
 * blending via THAT set is conformance, not evidence — this rule fires only
 * on tokens OUTSIDE it that are specific to a particular host's PRIVATE
 * design system (`--vscode-*`, GitHub Primer class names). Stays LOW
 * confidence: mechanically similar to phish.report's IOK asset-reuse rules,
 * and nobody has built this for design tokens.
 */

import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding } from '../shared/helpers.js';
import { hostPrivateTokens } from './shared.js';

const REMEDIATION =
  'If this token is intentional (e.g. the app is meant to run inside VS Code specifically), no ' +
  'change is required. If it was copied from a host-private design system to make the app blend ' +
  'in, use the spec\'s sanctioned McpUiStyleVariableKey set instead — that theming is provided by ' +
  'design.';

export const mimic004 = defineRule({
  id: 'PANE-MIMIC-004',
  ruleClass: 'RISK',
  severity: 'MEDIUM',
  confidence: 'LOW',
  title: 'Host-private design tokens outside the sanctioned style-variable set',
  specRef: 'SPEC-REFERENCE.md §3.6 — McpUiStyleVariableKey',
  remediation: REMEDIATION,
  experimental: true,
  status: 'active',
  since: '0.1.0',
  requires: ['content'],

  check(ctx: RuleContext): RuleResult {
    const hits = hostPrivateTokens(ctx);

    const findings: Finding[] = hits.map((h, i) =>
      makeFinding({
        ctx,
        rule: mimic004,
        message:
          `\`${h.evidence}\` is a design token or class name specific to a particular host's ` +
          'PRIVATE UI system — not part of the spec\'s sanctioned McpUiStyleVariableKey ' +
          'enumeration. Blending in via the sanctioned set is conformance; this is outside it.',
        evidence: h.evidence,
        ...(h.location ? { location: h.location } : {}),
        path: `token#${i}`,
      }),
    );

    return { findings };
  },
});

export default mimic004;

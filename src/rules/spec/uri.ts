/**
 * PANE-SPEC-001 — resource `uri` begins with `ui://`.
 *
 * `ui://` is a reserved scheme (SPEC-REFERENCE.md §1, verbatim: *"The resource
 * prefix `ui://` will be reserved for MCP Apps"*), so a resource served as an
 * MCP App under any other scheme is not one.
 *
 * ── Normalization, for the same reason PANE-SPEC-002 normalizes ──────────────
 * RFC 3986 §3.1 makes URI schemes case-INSENSITIVE ("should be normalized to
 * lowercase", not "must be produced in lowercase"). So `UI://server/view` names
 * the same scheme, and reporting it as a MUST violation at SPEC/HIGH/CERTAIN
 * would fail a build over a semantically conformant declaration — the same
 * false-positive class the MIME rule was corrected for.
 *
 * The scheme comparison is therefore case-insensitive. There is deliberately no
 * finding for the non-canonical spelling: `PANE-SPEC-009` is scoped to
 * `mimeType`, and inventing a rule ID is not this file's call.
 */

import { defineRule, makeFinding } from '../shared/helpers.js';
import { NO_FINDINGS } from '../shared/helpers.js';
import type { RuleResult } from '../../types.js';

export const UI_SCHEME = 'ui://';

/** Case-insensitive scheme test, per RFC 3986 §3.1. */
export function hasUiScheme(uri: string): boolean {
  return uri.slice(0, UI_SCHEME.length).toLowerCase() === UI_SCHEME;
}

export const paneSpec001 = defineRule({
  id: 'PANE-SPEC-001',
  ruleClass: 'SPEC',
  severity: 'HIGH',
  confidence: 'CERTAIN',
  title: 'Resource URI does not use the reserved ui:// scheme',
  specRef: 'SPEC-REFERENCE.md §1 — Exact identifiers',
  remediation:
    'Serve the resource under a ui:// URI. The scheme is reserved for MCP Apps and is how a ' +
    'host distinguishes an app resource from an ordinary MCP resource.',
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: [],

  check(ctx): RuleResult {
    const uri = ctx.resource.uri;
    if (hasUiScheme(uri)) return NO_FINDINGS;

    return {
      findings: [
        makeFinding({
          ctx,
          rule: paneSpec001,
          message:
            'Resource URI does not begin with the reserved ui:// scheme, so a host will not ' +
            'treat it as an MCP App resource.',
          evidence: uri,
          jsonPointer: '/uri',
          path: 'uri',
        }),
      ],
    };
  },
});

/**
 * PANE-SCHEMA-001, -002, -006 — unknown keys in `_meta.ui`, `_meta.ui.csp`, and
 * `_meta.ui.permissions`.
 *
 * `_meta.ui.csp` and `_meta.ui.permissions` are `additionalProperties: false`,
 * and so is `_meta.ui` itself. A misspelled key is not a warning — it means the
 * author believes they declared a restriction that does not exist, and gets
 * *less* protection than they think, with no error anywhere else.
 *
 * All three rules read the SAME `ajv` run (`ctx.schemaErrors`, populated by
 * `validateResourceMeta` against the `_meta.ui` SUBTREE — never `_meta` itself,
 * see `src/parse/meta.ts`), filtered by `(instancePath, keyword)`. Three rules
 * writing three validators is how they drift; this file writes none.
 */

import { defineRule, makeFinding, NO_FINDINGS } from '../shared/helpers.js';
import type { ErrorObject } from 'ajv';
import type { Finding, RuleContext, RuleMeta, RuleResult } from '../../types.js';

interface UnknownKeyHit {
  key: string;
}

/** Every `additionalProperties` violation whose object sits at `instancePath`. */
function unknownKeysAt(errors: ErrorObject[], instancePath: string): UnknownKeyHit[] {
  const hits: UnknownKeyHit[] = [];
  for (const e of errors) {
    if (e.keyword !== 'additionalProperties' || e.instancePath !== instancePath) continue;
    const key = (e.params as { additionalProperty?: unknown }).additionalProperty;
    if (typeof key === 'string' && key !== '') hits.push({ key });
  }
  return hits;
}

function buildFindings(ctx: RuleContext, rule: RuleMeta, instancePath: string, subtreeLabel: string): Finding[] {
  return unknownKeysAt(ctx.schemaErrors, instancePath).map(({ key }) => {
    const pointer = `${instancePath}/${key}`;
    return makeFinding({
      ctx,
      rule,
      message:
        `_meta.ui${subtreeLabel} contains an unrecognized key: "${key}". The schema does not ` +
        'declare it, so the author gets no protection from whatever they believe it restricts.',
      evidence: key,
      jsonPointer: pointer,
      path: pointer,
    });
  });
}

// ---------------------------------------------------------------------------
// PANE-SCHEMA-001 — _meta.ui.csp
// ---------------------------------------------------------------------------

export const paneSchema001 = defineRule({
  id: 'PANE-SCHEMA-001',
  ruleClass: 'SCHEMA',
  severity: 'HIGH',
  confidence: 'CERTAIN',
  title: '_meta.ui.csp contains an unrecognized key',
  specRef: 'SPEC-REFERENCE.md §2 — McpUiResourceCsp, additionalProperties: false',
  remediation:
    'Rename or remove the key. csp declares only connectDomains, resourceDomains, frameDomains, ' +
    'and baseUriDomains — anything else is silently ignored, not enforced.',
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['meta'],

  check(ctx): RuleResult {
    const findings = buildFindings(ctx, paneSchema001, '/csp', '.csp');
    return findings.length > 0 ? { findings } : NO_FINDINGS;
  },
});

// ---------------------------------------------------------------------------
// PANE-SCHEMA-002 — _meta.ui.permissions
// ---------------------------------------------------------------------------

export const paneSchema002 = defineRule({
  id: 'PANE-SCHEMA-002',
  ruleClass: 'SCHEMA',
  severity: 'HIGH',
  confidence: 'CERTAIN',
  title: '_meta.ui.permissions contains an unrecognized key',
  specRef: 'SPEC-REFERENCE.md §2 — McpUiResourcePermissions, additionalProperties: false',
  remediation:
    'Rename or remove the key. permissions declares only camera, microphone, geolocation, and ' +
    'clipboardWrite — anything else is silently ignored, not granted.',
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['meta'],

  check(ctx): RuleResult {
    const findings = buildFindings(ctx, paneSchema002, '/permissions', '.permissions');
    return findings.length > 0 ? { findings } : NO_FINDINGS;
  },
});

// ---------------------------------------------------------------------------
// PANE-SCHEMA-006 — _meta.ui root
// ---------------------------------------------------------------------------

export const paneSchema006 = defineRule({
  id: 'PANE-SCHEMA-006',
  ruleClass: 'SCHEMA',
  severity: 'MEDIUM',
  confidence: 'CERTAIN',
  title: '_meta.ui contains an unrecognized key',
  specRef: 'SPEC-REFERENCE.md §2 — McpUiResourceMeta, additionalProperties: false',
  remediation:
    'Rename or remove the key. _meta.ui declares only csp, permissions, domain, and prefersBorder.',
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['meta'],

  check(ctx): RuleResult {
    const findings = buildFindings(ctx, paneSchema006, '', '');
    return findings.length > 0 ? { findings } : NO_FINDINGS;
  },
});

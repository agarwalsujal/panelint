/**
 * PANE-SCHEMA-005 — `csp` or `permissions` declared on a tool's `_meta.ui`.
 *
 * `McpUiToolMeta` declares both `csp` and `permissions` as `{"not": {}}` —
 * they must be ABSENT. This catches a mistake that is natural, not merely
 * plausible: `resourceUri` lives on the tool's `_meta.ui`, so putting `csp`
 * there too is the obvious guess. A server doing this ships with **no CSP at
 * all** while believing it declared one — the CSP that governs a view lives on
 * the RESOURCE's `_meta.ui`, never the tool's.
 *
 * Reads `tool.schemaErrors`, the SAME `validateToolMeta` run every tool goes
 * through once (`src/parse/meta.ts`). No second validator.
 */

import type { Finding, ResourceSet } from '../../types.js';
import { defineSetRule, makeSetFinding, toolSubject } from '../spec/set-rule.js';

const FORBIDDEN_KEYS = ['csp', 'permissions'] as const;
type ForbiddenKey = (typeof FORBIDDEN_KEYS)[number];

const KEY_LABEL: Record<ForbiddenKey, string> = {
  csp: 'CSP',
  permissions: 'permissions grant',
};

export const paneSchema005 = defineSetRule({
  id: 'PANE-SCHEMA-005',
  ruleClass: 'SCHEMA',
  severity: 'HIGH',
  confidence: 'CERTAIN',
  title: "csp or permissions declared on a tool's _meta.ui",
  specRef: 'SPEC-REFERENCE.md §2 — McpUiToolMeta, csp and permissions are {"not": {}}',
  remediation:
    "Remove csp/permissions from the tool's _meta.ui. The schema forbids both there — the CSP " +
    "and permissions that govern a view live on the RESOURCE's _meta.ui, never the tool's.",
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['tools'],

  checkSet(set: ResourceSet): Finding[] {
    const findings: Finding[] = [];

    for (const tool of set.tools) {
      for (const key of FORBIDDEN_KEYS) {
        const pointer = `/${key}`;
        const hit = tool.schemaErrors.some((e) => e.instancePath === pointer && e.keyword === 'not');
        if (!hit) continue;

        findings.push(
          makeSetFinding({
            rule: paneSchema005,
            resourceUri: toolSubject(tool.name),
            message:
              `Tool declares ${key} on its _meta.ui. The schema forbids it there — the server ` +
              `ships with no ${KEY_LABEL[key]} at all while believing it declared one.`,
            jsonPointer: pointer,
            path: `tool/${tool.name}/${key}`,
          }),
        );
      }
    }

    return findings;
  },
});

/**
 * PANE-SPEC-005, -006 and -011 — the tool → resource link.
 *
 * All three read the SAME two fields, which is why they live in one file:
 * the modern `_meta.ui.resourceUri` and the deprecated flat
 * `_meta["ui/resourceUri"]`. All three are `SetRule`s because `RuleContext` has
 * no tool list — DESIGN.md removed `set` from the per-resource context
 * deliberately, since it invited accidental O(n²) and made rules order-sensitive.
 *
 * ── ☠ PANE-SPEC-006 is the third poisoned rule ───────────────────────────────
 * From `@modelcontextprotocol/ext-apps@1.7.5`, `dist/src/server/index.js`,
 * de-minified — `registerAppTool` reconciles the two forms in ONE direction each:
 *
 *     let V = J._meta, D = V.ui, L = V["ui/resourceUri"], W = V;
 *     if (D?.resourceUri && !L)      W = { ...V, ["ui/resourceUri"]: D.resourceUri };
 *     else if (L && !D?.resourceUri) W = { ...V, ui: { ...D, resourceUri: L } };
 *
 * Supplying ONLY the modern form makes the SDK emit the deprecated key on the
 * wire. `basic-server-react`, `basic-server-vanillajs` and `map-server` were each
 * confirmed to call `registerAppTool` with modern-only `_meta`. A rule keyed on
 * "the flat key is present" therefore fires on every conformant TypeScript
 * server, including the reference fixtures. It fires here ONLY when the flat key
 * is present AND the modern key is absent — genuinely legacy-only registration,
 * which is the case the deprecation notice is actually about.
 *
 * ── PANE-SPEC-011 exists because of what that same code does NOT do ──────────
 * When BOTH forms are supplied, `W = V` — the `_meta` is passed through
 * unchanged, with no reconciliation and no consistency check. A server whose two
 * forms disagree ships a contradiction nothing in the toolchain catches, and the
 * host's choice of which to honour is unspecified.
 *
 * ── PANE-SPEC-005 and "MAY omit from resources/list" ─────────────────────────
 * The spec says servers **MAY** omit UI-only resources from `resources/list`. So
 * a tool pointing at a resource that is not in the acquired set is NOT by itself
 * non-conformant — the resource may be unlisted and perfectly readable. This
 * rule fires only when the acquire path RECORDED that the URI could not be
 * resolved. Absence of evidence is not evidence of absence, and treating it as
 * such would flag conformant servers that keep their app resources unlisted.
 */

import type { Finding, ResourceSet, ToolWithUIMeta } from '../../types.js';
import { extractFlatResourceUri } from '../../parse/meta.js';
import { defineSetRule, makeSetFinding, toolSubject } from './set-rule.js';

/** The modern `_meta.ui.resourceUri`, when it is a string. */
function modernUri(tool: ToolWithUIMeta): string | undefined {
  const v = tool.meta?.resourceUri;
  return typeof v === 'string' && v !== '' ? v : undefined;
}

/** The deprecated flat `_meta["ui/resourceUri"]`, when it is a string. */
function flatUri(tool: ToolWithUIMeta): string | undefined {
  const v = extractFlatResourceUri(tool.rawMeta);
  return v !== undefined && v !== '' ? v : undefined;
}

// ---------------------------------------------------------------------------
// PANE-SPEC-005
// ---------------------------------------------------------------------------

/**
 * Did the acquire path record that this URI could not be resolved?
 *
 * This is the whole false-positive control. An UNRESOLVED_URI diagnostic or a
 * ScanError naming the URI is positive evidence that a read was attempted and
 * failed. Anything else — including silence — leaves open that the resource is
 * an unlisted-but-readable one the scan simply never asked for.
 */
function recordedUnresolvable(set: ResourceSet, uri: string): boolean {
  const byDiagnostic = set.diagnostics.some(
    (d) => d.resourceUri === uri && (d.code === 'UNRESOLVED_URI' || d.code === 'PARSE_FAILED'),
  );
  const byError = set.errors.some((e) => e.resourceUri === uri);
  return byDiagnostic || byError;
}

export const paneSpec005 = defineSetRule({
  id: 'PANE-SPEC-005',
  ruleClass: 'SPEC',
  severity: 'HIGH',
  confidence: 'CERTAIN',
  title: 'Tool references a resource that cannot be resolved',
  specRef: 'SPEC-REFERENCE.md §2 — Resource model, tool linked to a UI resource',
  remediation:
    'Serve the resource the tool names, or point the tool at one that exists. Servers MAY omit ' +
    'UI-only resources from resources/list, but the URI must still be readable.',
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['tools'],

  checkSet(set: ResourceSet): Finding[] {
    // Live scan only. Directory mode never performs a read, so it has no failed
    // read to report and every reference would look dangling.
    if (set.source === 'directory') return [];

    const acquired = new Set(set.resources.map((r) => r.uri));
    const findings: Finding[] = [];

    for (const tool of set.tools) {
      const uri = modernUri(tool) ?? flatUri(tool);
      if (uri === undefined) continue;
      if (acquired.has(uri)) continue;
      if (!recordedUnresolvable(set, uri)) continue;

      findings.push(
        makeSetFinding({
          rule: paneSpec005,
          resourceUri: toolSubject(tool.name),
          message:
            'Tool references a ui:// resource the server could not serve. The host has a tool ' +
            'it can call and no view to render for it.',
          evidence: uri,
          jsonPointer: '/_meta/ui/resourceUri',
          path: `tool/${tool.name}/resourceUri`,
        }),
      );
    }

    return findings;
  },
});

// ---------------------------------------------------------------------------
// PANE-SPEC-006
// ---------------------------------------------------------------------------

export const paneSpec006 = defineSetRule({
  id: 'PANE-SPEC-006',
  ruleClass: 'INFO',
  severity: 'LOW',
  confidence: 'CERTAIN',
  title: 'Tool registered only through the deprecated flat _meta["ui/resourceUri"]',
  specRef: 'SPEC-REFERENCE.md §1 — Deprecated flat form, "Will be removed before GA"',
  remediation:
    'Move the value to _meta.ui.resourceUri. The flat key is deprecated and scheduled for ' +
    'removal before GA; the official SDK will keep emitting it alongside the modern key for ' +
    'compatibility, so nothing breaks by adding the modern form.',
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['tools'],

  checkSet(set: ResourceSet): Finding[] {
    const findings: Finding[] = [];

    for (const tool of set.tools) {
      const flat = flatUri(tool);
      // ☠ The guard. The SDK dual-writes the flat key, so presence alone says
      // nothing. Only flat-WITHOUT-modern is legacy-only registration.
      if (flat === undefined) continue;
      if (modernUri(tool) !== undefined) continue;

      findings.push(
        makeSetFinding({
          rule: paneSpec006,
          resourceUri: toolSubject(tool.name),
          message:
            'Tool links to its view only through the deprecated flat _meta["ui/resourceUri"] ' +
            'key, with no _meta.ui.resourceUri. The deprecated key is scheduled for removal ' +
            'before GA.',
          evidence: flat,
          jsonPointer: '/_meta/ui~1resourceUri',
          path: `tool/${tool.name}/flatResourceUri`,
        }),
      );
    }

    return findings;
  },
});

// ---------------------------------------------------------------------------
// PANE-SPEC-011
// ---------------------------------------------------------------------------

export const paneSpec011 = defineSetRule({
  id: 'PANE-SPEC-011',
  ruleClass: 'SPEC',
  severity: 'MEDIUM',
  confidence: 'CERTAIN',
  title: 'Modern and deprecated resourceUri forms carry different values',
  specRef: 'RULES.md § PANE-SPEC — PANE-SPEC-011 exists because of what the SDK does not do',
  remediation:
    'Remove the flat _meta["ui/resourceUri"] key and keep _meta.ui.resourceUri. While both are ' +
    'present with different values the server ships a contradiction, and which one a host ' +
    'honours is unspecified.',
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['tools'],

  checkSet(set: ResourceSet): Finding[] {
    const findings: Finding[] = [];

    for (const tool of set.tools) {
      const modern = modernUri(tool);
      const flat = flatUri(tool);
      if (modern === undefined || flat === undefined) continue;
      if (modern === flat) continue;

      findings.push(
        makeSetFinding({
          rule: paneSpec011,
          resourceUri: toolSubject(tool.name),
          message:
            'Tool declares both _meta.ui.resourceUri and the deprecated flat ' +
            '_meta["ui/resourceUri"] with different values. The SDK passes both through ' +
            'unreconciled, and the spec does not say which one a host honours.',
          evidence: `_meta.ui.resourceUri=${modern} _meta["ui/resourceUri"]=${flat}`,
          jsonPointer: '/_meta/ui/resourceUri',
          path: `tool/${tool.name}/resourceUriConflict`,
        }),
      );
    }

    return findings;
  },
});

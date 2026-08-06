/**
 * PANE-SPEC-007 — server-side `io.modelcontextprotocol/ui` extension declaration.
 *
 * ── Correction — the original rule audited the scanner, not the server ───────
 * It previously checked that the *client* capability declares `mimeTypes` — but
 * in a live scan Panelint **is** the client, so it would have been inspecting its
 * own outbound `initialize`, and it contradicted non-goal N2 (no host conformance
 * testing). Repointed at the server side: a server that serves `ui://` resources
 * is expected to declare the extension, and to list the exact MCP App MIME type
 * among the `mimeTypes` it advertises for it.
 *
 * `mimeTypes` is required by spec prose, not by JSON Schema — `McpUiClientCapabilities`
 * has no `required` array — so this is `HIGH`, not `CERTAIN`.
 *
 * Live scan only. Directory mode, and any acquire path that never observed the
 * `initialize` handshake, leaves `ResourceSet.declaresUiExtension` `undefined`;
 * this rule declines outright rather than guessing at a capability nobody saw.
 */

import type { Finding, ResourceSet } from '../../types.js';
import { defineSetRule, makeSetFinding } from './set-rule.js';
import { hasUiScheme } from './uri.js';
import { classifyMimeType } from './mime-type.js';

export const paneSpec007 = defineSetRule({
  id: 'PANE-SPEC-007',
  ruleClass: 'SPEC',
  severity: 'MEDIUM',
  confidence: 'HIGH',
  title: 'Server serves ui:// resources without declaring the io.modelcontextprotocol/ui extension',
  specRef: 'SPEC-REFERENCE.md §1 — Extension declaration',
  remediation:
    'Declare the io.modelcontextprotocol/ui extension at initialize, with mimeTypes including ' +
    'text/html;profile=mcp-app. A host that never sees the declaration has no signal that these ' +
    'resources are MCP Apps.',
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['capabilities'],

  checkSet(set: ResourceSet): Finding[] {
    // Capabilities are only observable from a live initialize handshake. An
    // acquire path that never recorded one leaves this undefined, and guessing
    // would be inspecting a capability nobody actually saw.
    if (set.declaresUiExtension === undefined) return [];

    const uiResources = set.resources.filter((r) => hasUiScheme(r.uri));
    if (uiResources.length === 0) return [];
    const subject = uiResources[0]!.uri;

    // A server that did not declare the extension is NOT a violation, and this
    // rule used to say it was — at class SPEC, severity MEDIUM, confidence
    // HIGH, so it gated at `--fail-on medium`.
    //
    // The requirement does not exist. The extension block in the spec's
    // capability negotiation is shown inside an `initialize` REQUEST, i.e. the
    // client's capabilities; `mimeTypes` is REQUIRED of the client. The only
    // normative server text is "Servers SHOULD check client capabilities before
    // registering UI-enabled tools". The schema has McpUiClientCapabilities,
    // McpUiHostCapabilities and McpUiAppCapabilities and no server equivalent,
    // the official SDK exposes no helper for a server to declare it, and not
    // one of the reference example servers does — every one constructs
    // `new McpServer({ name, version })` with no capabilities argument.
    //
    // So this fired on every server built the way the specification's own code
    // sample shows. That is the twelfth member of the eleven-rule class
    // CLAUDE.md §4 records, and it shipped in 0.1.0. The reference corpus could
    // not catch it: test/corpus.test.ts synthesizes ResourceSets with no
    // capabilities, so `requires: ['capabilities']` skips this rule entirely.
    //
    // The ID stays and the rule stays — the second branch below is real, and
    // rule IDs are permanent.
    if (!set.declaresUiExtension) return [];

    const declared = set.declaredMimeTypes ?? [];
    const coversMcpApp = declared.some((m) => {
      const verdict = classifyMimeType(m);
      return verdict.kind === 'canonical' || verdict.kind === 'equivalent';
    });
    if (coversMcpApp) return [];

    return [
      makeSetFinding({
        rule: paneSpec007,
        resourceUri: subject,
        message:
          'Server declares the io.modelcontextprotocol/ui extension but its mimeTypes list does ' +
          "not include text/html;profile=mcp-app. A host matching the declaration against a " +
          'resource\'s mimeType will not recognize it as an MCP App.',
        jsonPointer: '/capabilities/io.modelcontextprotocol~1ui/mimeTypes',
        path: 'capabilities/ui-extension/mimeTypes',
      }),
    ];
  },
});

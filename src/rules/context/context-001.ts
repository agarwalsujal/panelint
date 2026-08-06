/**
 * PANE-CONTEXT-001 — the app calls `ui/message`.
 *
 * SPEC-REFERENCE.md §4, verbatim: `ui/message` injects app-authored content
 * into the conversation with role `"user"` — as if the person had typed it —
 * and the host only MAY request consent first, never MUST. This is prompt
 * injection as a supported protocol feature. It is not a bug and cannot be
 * "fixed" by a scanner, but every app that uses it should be disclosed so an
 * operator knows what they are enabling. Hence INFO, not RISK.
 *
 * Detection is call-site AST analysis, not a string search — see
 * ./shared.ts for why `content.includes("ui/message")` is unusable on an app
 * that inlines the ext-apps SDK bundle.
 */

import type { Finding, RuleContext, RuleResult, UndecidedNote } from '../../types.js';
import { defineRule, makeFinding, undecided } from '../shared/helpers.js';
import { findCalls } from '../../parse/js.js';
import { scriptsOf, rebase, sourceOf } from '../exfil/url-shape.js';
import { findAppMethodCalls, isVendoredSdkBundle } from './shared.js';

const REMEDIATION =
  'Disclose in the resource description that this app can inject text into the conversation as ' +
  'if the user typed it. The host MAY request consent before delivering it — the spec does not ' +
  'require consent — so do not rely on a consent prompt as a control.';

export const context001 = defineRule({
  id: 'PANE-CONTEXT-001',
  ruleClass: 'INFO',
  severity: 'HIGH',
  confidence: 'CERTAIN',
  title: 'App calls ui/message',
  specRef: 'SPEC-REFERENCE.md §4 — ui/message, consent is MAY not MUST',
  remediation: REMEDIATION,
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['content'],

  check(ctx: RuleContext): RuleResult {
    const scripts = scriptsOf(ctx);
    const findings: Finding[] = [];
    const notes: UndecidedNote[] = [];
    let n = 0;

    for (const call of findAppMethodCalls(scripts, ['sendMessage'])) {
      const loc = rebase(call.script, call.node);
      findings.push(
        makeFinding({
          ctx,
          rule: context001,
          message:
            '`sendMessage` is called on the app bridge. `ui/message` injects the given content into ' +
            'the conversation with role "user" — as if the person had typed it. The host MAY request ' +
            'consent before delivering it; the spec does not require it.',
          evidence: sourceOf(call.script, call.node),
          ...(loc ? { location: loc } : {}),
          path: `script#${n++}`,
        }),
      );
    }

    const rpcSites = findCalls(scripts, [{ rpcMethod: 'ui/message' }]);
    if (rpcSites.length > 0) {
      if (isVendoredSdkBundle(ctx)) {
        notes.push(
          undecided(
            ctx,
            context001,
            'a vendored ext-apps SDK bundle was detected inline; its internal JSON-RPC call sites ' +
              'for `ui/message` are not distinguishable from an app-authored call and were ' +
              'suppressed rather than reported as findings',
          ),
        );
      } else {
        for (const site of rpcSites) {
          findings.push(
            makeFinding({
              ctx,
              rule: context001,
              message:
                'A raw JSON-RPC object literal declares `method: "ui/message"`. This injects the ' +
                'given content into the conversation with role "user" — as if the person had typed ' +
                'it. The host MAY request consent before delivering it; the spec does not require it.',
              evidence: sourceOf(site.script, site.node),
              ...(site.location ? { location: site.location } : {}),
              path: `script#${n++}`,
            }),
          );
        }
      }
    }

    return { findings, ...(notes.length ? { undecided: notes } : {}) };
  },
});

export default context001;

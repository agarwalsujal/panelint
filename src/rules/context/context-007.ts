/**
 * PANE-CONTEXT-007 — the app calls `ui/download-file`.
 *
 * Under-rated by its `INFO` class in an ordinary reading: SPEC-REFERENCE.md
 * §4 specifies NO consent requirement on `ui/download-file`. The host
 * capability `downloadFile` gates whether downloads work AT ALL, not whether
 * any individual download is approved. Combined with an attacker-chosen
 * filename and attacker-chosen bytes, this is a malware-delivery path — when
 * reachable from tainted tool output it is PANE-CONTEXT-005's business
 * (v1.1); this rule is the v1 capability disclosure.
 */

import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding } from '../shared/helpers.js';
import { scriptsOf, rebase, sourceOf } from '../exfil/url-shape.js';
import { findAppMethodCalls } from './shared.js';

const REMEDIATION =
  'Disclose in the resource description that this app can write an attacker- or app-chosen file ' +
  'to the user\'s disk. The spec specifies no per-download consent requirement — only the host ' +
  'capability `downloadFile` gates whether downloads work at all.';

export const context007 = defineRule({
  id: 'PANE-CONTEXT-007',
  ruleClass: 'INFO',
  severity: 'HIGH',
  confidence: 'CERTAIN',
  title: 'App calls ui/download-file',
  cwe: 'CWE-434',
  specRef: 'SPEC-REFERENCE.md §4 — ui/download-file, no consent requirement specified',
  remediation: REMEDIATION,
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['content'],

  check(ctx: RuleContext): RuleResult {
    const scripts = scriptsOf(ctx);
    const findings: Finding[] = [];
    let n = 0;

    for (const call of findAppMethodCalls(scripts, ['downloadFile'])) {
      const loc = rebase(call.script, call.node);
      findings.push(
        makeFinding({
          ctx,
          rule: context007,
          message:
            '`downloadFile` is called on the app bridge. `ui/download-file` writes an app-named file ' +
            'to the user\'s disk. The spec specifies no consent requirement on this call — the host ' +
            'capability `downloadFile` gates whether downloads work at all, not whether any ' +
            'individual one is approved.',
          evidence: sourceOf(call.script, call.node),
          ...(loc ? { location: loc } : {}),
          path: `script#${n++}`,
        }),
      );
    }

    return { findings };
  },
});

export default context007;

/**
 * PANE-SANDBOX-006 — the HTML invokes a capability `_meta.ui.permissions`
 * never declared.
 *
 * `-005` inverted, and the security-relevant direction: over-declaration is
 * untidy, under-declared USE is the attacker's move. Requires an actual
 * INVOCATION — `getCurrentPosition(`, `getUserMedia(`, `clipboard.writeText(`
 * — never mere member access. SPEC-REFERENCE.md §3.2, verbatim: "Apps SHOULD
 * NOT assume permissions are granted; use JS feature detection as fallback."
 * A matcher keyed on `navigator.geolocation` member access would flag the
 * spec-RECOMMENDED pattern — see fixtures/nondetect/feature-detection.html.
 *
 * `getUserMedia`'s constraints argument is read rather than assumed: a call
 * requesting only `{ audio: true }` is missing `microphone`, not `camera`.
 */

import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding, HOST_SANDBOX_ASSUMPTION } from '../shared/helpers.js';
import { findCalls } from '../../parse/js.js';
import { scriptsOf, rebase, sourceOf } from '../exfil/url-shape.js';
import { getUserMediaConstraints, withFrameClause } from './shared.js';

const REMEDIATION =
  'Declare the capability in `_meta.ui.permissions` so the host can honor it via the iframe `allow` ' +
  'attribute, and so an operator reviewing the resource sees it up front instead of discovering it ' +
  'in the script.';

export const sandbox006 = defineRule({
  id: 'PANE-SANDBOX-006',
  ruleClass: 'RISK',
  severity: 'MEDIUM',
  confidence: 'HIGH',
  title: 'HTML invokes a capability not declared in _meta.ui.permissions',
  specRef: 'SPEC-REFERENCE.md §3.2',
  remediation: REMEDIATION,
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['content', 'meta'],

  check(ctx: RuleContext): RuleResult {
    const scripts = scriptsOf(ctx);
    const perms = ctx.meta?.permissions ?? {};
    const findings: Finding[] = [];
    let n = 0;

    for (const call of findCalls(scripts, [{ object: 'geolocation', method: 'getCurrentPosition' }])) {
      if (perms.geolocation) continue;
      const loc = call.location ?? rebase(call.script, call.node);
      findings.push(
        makeFinding({
          ctx,
          rule: sandbox006,
          message: withFrameClause(
            '`navigator.geolocation.getCurrentPosition` is invoked, but _meta.ui.permissions never ' +
              'declares geolocation.',
          ),
          evidence: sourceOf(call.script, call.node),
          ...(loc ? { location: loc } : {}),
          assumption: HOST_SANDBOX_ASSUMPTION,
          path: `script#${n++}`,
        }),
      );
    }

    for (const call of findCalls(scripts, [{ object: 'mediaDevices', method: 'getUserMedia' }])) {
      const { audio, video } = getUserMediaConstraints(call.args[0]);
      const missing: Array<[string, string]> = [];
      if (audio && !perms.microphone) missing.push(['microphone', 'an audio']);
      if (video && !perms.camera) missing.push(['camera', 'a video']);

      for (const [feature, track] of missing) {
        const loc = call.location ?? rebase(call.script, call.node);
        findings.push(
          makeFinding({
            ctx,
            rule: sandbox006,
            message: withFrameClause(
              `\`navigator.mediaDevices.getUserMedia\` requests ${track} track, but ` +
                `_meta.ui.permissions never declares ${feature}.`,
            ),
            evidence: sourceOf(call.script, call.node),
            ...(loc ? { location: loc } : {}),
            assumption: HOST_SANDBOX_ASSUMPTION,
            path: `script#${n++}`,
          }),
        );
      }
    }

    for (const call of findCalls(scripts, [{ object: 'clipboard', method: 'writeText' }])) {
      if (perms.clipboardWrite) continue;
      const loc = call.location ?? rebase(call.script, call.node);
      findings.push(
        makeFinding({
          ctx,
          rule: sandbox006,
          message: withFrameClause(
            '`navigator.clipboard.writeText` is invoked, but _meta.ui.permissions never declares ' +
              'clipboardWrite.',
          ),
          evidence: sourceOf(call.script, call.node),
          ...(loc ? { location: loc } : {}),
          assumption: HOST_SANDBOX_ASSUMPTION,
          path: `script#${n++}`,
        }),
      );
    }

    return { findings };
  },
});

export default sandbox006;

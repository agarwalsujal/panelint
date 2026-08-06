/**
 * PANE-SANDBOX-001 — nested iframe combines `allow-scripts allow-same-origin`
 * with a `src` matching the server's own declared `_meta.ui.domain`.
 *
 * `allow-scripts allow-same-origin` is MANDATED for the sandbox proxy
 * (SPEC-REFERENCE.md §3.3) and safe only because the proxy sits on a
 * different origin from the host. This rule's whole premise is knowing what
 * "same-origin with the host" means, and the host's own origin is only
 * knowable through a declared `_meta.ui.domain`. Measured: none of the eight
 * reference servers declares it, and `srcdoc` (no `src` at all) is the
 * legitimate pattern in that case. With no declared domain, or with no `src`
 * to compare, this rule declines rather than guesses — see
 * fixtures/nondetect/nested-srcdoc-frame.html.
 */

import type { Finding, RuleContext, RuleResult, UndecidedNote } from '../../types.js';
import { defineRule, makeFinding, undecided, HOST_SANDBOX_ASSUMPTION } from '../shared/helpers.js';
import { selectAll, attr, attrLocationOf } from '../../parse/html.js';
import { withFrameClause } from './shared.js';

const REMEDIATION =
  'Only declare `_meta.ui.domain` if this frame genuinely needs a stable origin (OAuth callback, ' +
  'CORS allowlist). If it does, do not also point a same-origin `allow-scripts allow-same-origin` ' +
  'child at content this document does not fully trust — that combination defeats the isolation ' +
  'the sandbox flags exist to provide.';

function sandboxTokens(sandboxValue: string): Set<string> {
  return new Set(
    sandboxValue
      .trim()
      .split(/\s+/)
      .filter(Boolean)
      .map((t) => t.toLowerCase()),
  );
}

export const sandbox001 = defineRule({
  id: 'PANE-SANDBOX-001',
  ruleClass: 'RISK',
  severity: 'CRITICAL',
  confidence: 'HIGH',
  title: 'Nested iframe: allow-scripts + allow-same-origin at a same-origin src',
  cwe: 'CWE-1021',
  specRef: 'SPEC-REFERENCE.md §3.3, §3.4',
  remediation: REMEDIATION,
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['content', 'meta'],

  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];
    const notes: UndecidedNote[] = [];
    let n = 0;

    for (const el of selectAll('iframe', ctx.dom)) {
      const sandboxValue = attr(el, 'sandbox');
      if (sandboxValue === undefined) continue;
      const tokens = sandboxTokens(sandboxValue);
      if (!tokens.has('allow-scripts') || !tokens.has('allow-same-origin')) continue;

      const domain = ctx.meta?.domain;
      if (typeof domain !== 'string' || !domain.trim()) {
        notes.push(
          undecided(
            ctx,
            sandbox001,
            'the nested frame declares allow-scripts and allow-same-origin, but no ' +
              '_meta.ui.domain is declared, so there is no declared origin to compare its src ' +
              'against',
            attrLocationOf(el, 'sandbox'),
          ),
        );
        continue;
      }

      const src = (attr(el, 'src') ?? '').trim();
      if (!src) continue; // srcdoc with a declared domain: nothing to compare the domain against.

      let hostname: string | null = null;
      try {
        hostname = new URL(src).hostname.toLowerCase();
      } catch {
        hostname = null;
      }
      if (!hostname || hostname !== domain.trim().toLowerCase()) continue;

      findings.push(
        makeFinding({
          ctx,
          rule: sandbox001,
          message: withFrameClause(
            `<iframe sandbox="${sandboxValue}"> combines allow-scripts and allow-same-origin with a ` +
              `src (${src}) whose host matches the server's own declared _meta.ui.domain (${domain}) ` +
              '— treat this as same-origin with the host.',
          ),
          evidence: src,
          location: attrLocationOf(el, 'src'),
          assumption: HOST_SANDBOX_ASSUMPTION,
          path: `iframe#${n++}`,
        }),
      );
    }

    return { findings, ...(notes.length ? { undecided: notes } : {}) };
  },
});

export default sandbox001;

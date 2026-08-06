/**
 * PANE-CSP-011 — a nested frame sourced from `srcdoc`, `data:` or `blob:`.
 *
 * `frame-src` applies inconsistently across engines for these sources. A frame
 * whose content never travels over the network is not obviously a "fetch" at
 * all, and engines have historically disagreed about whether the directive
 * governs it — so a host that declared `frame-src 'none'` may or may not
 * actually prevent the nested document from existing.
 *
 * This is CERTAIN confidence because it is a structural fact about the markup:
 * the attribute is either there or it is not. What the rule does NOT claim is
 * what any particular engine does with it, which is host behaviour and out of
 * scope per GOALS.md N2.
 */

import type { RuleContext, RuleResult, Finding } from '../../types.js';
import { defineRule, makeFinding, structuralPath, CSP_SYNTHESIS_ASSUMPTION } from '../shared/helpers.js';
import { attr, attrLocationOf, selectAll } from '../../parse/html.js';

/** Schemes whose document body is carried in the URL rather than fetched. */
const OPAQUE_SCHEMES = ['data:', 'blob:', 'filesystem:'];

export const paneCsp011 = defineRule({
  id: 'PANE-CSP-011',
  ruleClass: 'RISK',
  severity: 'MEDIUM',
  confidence: 'CERTAIN',
  title: 'Nested iframe sourced from srcdoc, data: or blob:',
  specRef: 'SEP-1865 §Security Implications — CSP Enforcement',
  cwe: 'CWE-1021',
  remediation:
    'Serve nested frame content from an origin listed in `frameDomains` so the ' +
    'host\'s `frame-src` governs it predictably, or inline the content directly ' +
    'rather than nesting a browsing context.',
  experimental: false,
  status: 'active',
  since: '0.1.0',
  // The whole PANE-CSP family declares `meta`, so directory mode skips it as a
  // unit rather than running some of it against scraped source.
  requires: ['meta', 'content'],

  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];

    for (const frame of selectAll('iframe, frame', ctx.dom)) {
      const srcdoc = attr(frame, 'srcdoc');
      const src = (attr(frame, 'src') ?? '').trim().toLowerCase();

      let carrier: string | null = null;
      if (srcdoc !== undefined) carrier = 'srcdoc';
      else {
        const scheme = OPAQUE_SCHEMES.find((s) => src.startsWith(s));
        if (scheme) carrier = scheme;
      }
      if (!carrier) continue;

      findings.push(
        makeFinding({
          ctx,
          rule: paneCsp011,
          message:
            `A nested frame is sourced from \`${carrier}\`. \`frame-src\` applies ` +
            'inconsistently across engines to frames whose content is not fetched, so a ' +
            'declared `frameDomains` may not govern this frame at all.',
          evidence: carrier === 'srcdoc' ? 'srcdoc=…' : src,
          location: attrLocationOf(frame, carrier === 'srcdoc' ? 'srcdoc' : 'src'),
          path: structuralPath(frame),
          assumption: CSP_SYNTHESIS_ASSUMPTION,
        }),
      );
    }

    return { findings };
  },
});

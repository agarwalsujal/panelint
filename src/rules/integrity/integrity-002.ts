/**
 * PANE-INTEGRITY-002 — `integrity` present, `crossorigin` absent.
 *
 * An author who writes `integrity` has decided the bytes matter. Without
 * `crossorigin`, a CROSS-ORIGIN fetch is made in no-cors mode and returns an
 * opaque response the browser cannot hash — so the load fails, or in the older
 * behaviour the check silently does not happen. Either way the author's
 * intention is not what ships.
 *
 * ── Correction against the RULES.md row ─────────────────────────────────────
 * The row is unconditional and rated CERTAIN. That claim is false for a
 * SAME-DOCUMENT subresource: SRI on a same-origin fetch needs no CORS and
 * works exactly as written. Restricted to off-document URLs, where the claim
 * holds and CERTAIN is earned.
 *
 * PANE-INTEGRITY-001 covers the no-`integrity` case, so the two never both
 * fire on the same element.
 */

import type { Element } from 'domhandler';
import type { RuleContext, RuleResult } from '../../types.js';
import { attr, attrLocationOf, hasAttr, selectAll } from '../../parse/html.js';
import { defineRule, makeFinding, structuralPath } from '../shared/helpers.js';
import { isOffDocument } from '../exfil/url-shape.js';

const REMEDIATION =
  'Add `crossorigin="anonymous"` alongside `integrity`. A cross-origin subresource fetched without ' +
  'CORS returns an opaque response the browser cannot hash, so the pin you wrote is not the pin ' +
  'that runs.';

function subresources(ctx: RuleContext): Array<{ el: Element; attrName: 'src' | 'href' }> {
  const out: Array<{ el: Element; attrName: 'src' | 'href' }> = [];
  for (const el of selectAll('script[integrity][src]', ctx.dom)) out.push({ el, attrName: 'src' });
  for (const el of selectAll('link[integrity][href]', ctx.dom)) out.push({ el, attrName: 'href' });
  return out;
}

export const integrity002 = defineRule({
  id: 'PANE-INTEGRITY-002',
  ruleClass: 'RISK',
  severity: 'MEDIUM',
  confidence: 'CERTAIN',
  title: 'Subresource integrity declared without crossorigin',
  cwe: 'CWE-353',
  remediation: REMEDIATION,
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['content'],

  check(ctx: RuleContext): RuleResult {
    const findings = [];

    for (const { el, attrName } of subresources(ctx)) {
      if (hasAttr(el, 'crossorigin')) continue;
      const url = attr(el, attrName) ?? '';
      // Same-document: SRI works without CORS. Claiming otherwise would be a
      // CERTAIN finding on correct markup.
      if (!isOffDocument(url)) continue;

      const location = attrLocationOf(el, 'integrity');
      findings.push(
        makeFinding({
          ctx,
          rule: integrity002,
          message:
            `<${el.tagName}> declares \`integrity\` for an off-document subresource but no ` +
            '`crossorigin`. The fetch is made in no-cors mode and the response is opaque, so the ' +
            'hash the author wrote is not enforced on the bytes that load.',
          evidence: url,
          ...(location ? { location } : {}),
          path: `${structuralPath(el)}@integrity`,
        }),
      );
    }

    return { findings };
  },
});

export default integrity002;

/**
 * PANE-EXFIL-003 — `<meta http-equiv="refresh">`.
 *
 * Governed by no CSP directive, and gated by no sandbox flag. The reference
 * host's sandbox is `allow-scripts allow-same-origin allow-forms` — it grants
 * neither `allow-popups` nor `allow-top-navigation` — but a document
 * navigating ITSELF is not a top-level navigation, so a meta refresh remains
 * live where `window.open` does not.
 *
 * ── Two corrections against the RULES.md row ────────────────────────────────
 * 1. The row reads "`<meta http-equiv="refresh">` present". Presence is not
 *    enough: `content="30"` has no `url=` component. It reloads the same
 *    document on a timer, which is what a dashboard app does, and it
 *    exfiltrates nothing.
 *
 * 2. A refresh inside `<noscript>` is INERT in any host granting
 *    `allow-scripts` — which the spec mandates, since the default CSP carries
 *    `script-src 'self' 'unsafe-inline'`. Claiming an egress channel there
 *    would be a finding on code that cannot run. PANE-HIDDEN-012 covers it as
 *    a non-rendered carrier instead. parse/html.ts parses with
 *    `scriptingEnabled: false`, so noscript content IS in the tree as markup
 *    rather than as a text node — the ancestry check has to be explicit.
 */

import { Element } from 'domhandler';
import type { RuleContext, RuleResult, Severity } from '../../types.js';
import { ancestors, attr, attrLocationOf, selectAll } from '../../parse/html.js';
import { defineRule, makeFinding, structuralPath } from '../shared/helpers.js';
import { isOffDocument } from './url-shape.js';

const REMEDIATION =
  'Remove the refresh. No `_meta.ui.csp` field governs it, so a host cannot block the navigation ' +
  'and the URL carries whatever the app puts in it. Navigate with an explicit user action, or ' +
  'send data with `fetch()` to an origin declared in `connectDomains`.';

/**
 * The `url=` component of a refresh directive.
 *
 * HTML's parser is lenient here: whitespace anywhere, `URL` in any case, and
 * the value optionally quoted. Returns null when the directive is a bare
 * timeout, which is the case this rule must stay silent on.
 */
export function refreshTarget(content: string): string | null {
  const m = /(?:^|[;,])\s*url\s*=\s*(.*)$/is.exec(content);
  if (!m) return null;
  let url = (m[1] ?? '').trim();
  const quote = url[0];
  if (quote === '"' || quote === "'") {
    const end = url.indexOf(quote, 1);
    url = end === -1 ? url.slice(1) : url.slice(1, end);
  }
  url = url.trim();
  return url ? url : null;
}

function insideNoscript(el: Element): boolean {
  return ancestors(el).some((a) => a.tagName === 'noscript');
}

export const exfil003 = defineRule({
  id: 'PANE-EXFIL-003',
  ruleClass: 'RISK',
  severity: 'HIGH',
  confidence: 'CERTAIN',
  title: 'Meta refresh navigation, governed by no CSP directive',
  specRef: 'SEP-1865 apps.mdx L275-284 — the mandated default policy has no navigation directive',
  cwe: 'CWE-601',
  remediation: REMEDIATION,
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['content'],

  check(ctx: RuleContext): RuleResult {
    const findings = [];

    for (const el of selectAll('meta[http-equiv]', ctx.dom)) {
      if ((attr(el, 'http-equiv') ?? '').trim().toLowerCase() !== 'refresh') continue;

      const target = refreshTarget(attr(el, 'content') ?? '');
      if (!target) continue;
      if (insideNoscript(el)) continue;

      const offDocument = isOffDocument(target);
      // A same-document target navigates but does not egress. Reported, because
      // nothing governs the directive either way — demoted below the gate,
      // because `content="5;url=/next"` is not worth breaking a build over.
      const severity: Severity = offDocument ? 'HIGH' : 'MEDIUM';
      const location = attrLocationOf(el, 'content');

      findings.push(
        makeFinding({
          ctx,
          rule: exfil003,
          message: offDocument
            ? '`<meta http-equiv="refresh">` navigates to an off-document origin. No CSP directive ' +
              'governs this navigation and no sandbox flag gates it — a document navigating itself ' +
              'is not a top-level navigation — so the URL, and anything encoded in it, leaves.'
            : '`<meta http-equiv="refresh">` navigates to a same-document target. No CSP directive ' +
              'governs the directive, so the target is worth knowing, but nothing leaves the app.',
          evidence: attr(el, 'content') ?? '',
          ...(location ? { location } : {}),
          severity,
          path: `${structuralPath(el)}@content`,
        }),
      );
    }

    return { findings };
  },
});

export default exfil003;

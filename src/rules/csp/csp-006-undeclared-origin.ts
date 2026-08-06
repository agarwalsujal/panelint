/**
 * PANE-CSP-006 — the HTML references an origin no declaration covers.
 *
 * This is a FUNCTIONALITY lint, not a risk finding. It fires when the CSP is
 * *working*: the host will block the request and the app will be silently
 * broken. Hence class INFO, severity LOW, and no gate eligibility.
 *
 * ⚠ The exclusion list is the rule. Without it, six of eight reference servers
 * produce findings and the family becomes noise:
 *
 *   `<a href>`        anchors are navigation, not a fetch. No fetch directive
 *                     governs them.
 *   `<form action>`   governed by NOTHING — `form-action` has no `_meta.ui.csp`
 *                     field and does not inherit from `default-src`. That is
 *                     PANE-EXFIL-001's territory, and reporting it here as
 *                     "will be blocked at runtime" would be actively false.
 *   `ui/open-link`    a host RPC, subject to no app CSP at all.
 *   `data:` `blob:`   already permitted by the mandated default for images and
 *                     media, or same-document.
 *   relative, `#…`,   the app document's origin is opaque; every relative URL is
 *   `mailto:`         same-document and reaches no network.
 *
 * Coverage is checked against the UNION of all four arrays rather than against
 * the directive that actually governs each element. That is deliberately
 * generous: a finding here asserts the app is broken, and over-reporting a
 * breakage that will not happen is worse than missing one that will.
 */

import type { RuleMeta, RuleContext, RuleResult, SourceLocation } from '../../types.js';
import { defineRule, makeFinding, CSP_SYNTHESIS_ASSUMPTION } from '../shared/helpers.js';
import { attr, attrLocationOf, selectAll } from '../../parse/html.js';
import { absoluteHttpUrl, anyEntryCovers, cspOf } from './domains.js';

const meta: RuleMeta = {
  id: 'PANE-CSP-006',
  ruleClass: 'INFO',
  severity: 'LOW',
  confidence: 'HIGH',
  title: 'Resource loaded from an origin no declared domain covers',
  specRef: 'SEP-1865 §Security Implications — "Host MUST block connections to undeclared domains"',
  remediation:
    'Add the origin to resourceDomains (or frameDomains for a frame), or remove the ' +
    'reference. As declared, the host will block this request.',
  experimental: false,
  status: 'active',
  since: '0.1.0',
};

/**
 * Fetch-governed markup only.
 *
 * `a[href]`, `form[action]` and `button[formaction]` are absent by design — see
 * the module note. `object[data]` and `embed[src]` are present because the
 * construction pins `object-src 'none'`, so they are always blocked.
 */
const FETCH_ATTRS: ReadonlyArray<{ selector: string; attrs: string[]; srcset?: boolean }> = [
  { selector: 'img', attrs: ['src', 'srcset'], srcset: true },
  { selector: 'source', attrs: ['src', 'srcset'], srcset: true },
  { selector: 'script', attrs: ['src'] },
  { selector: 'iframe', attrs: ['src'] },
  { selector: 'video', attrs: ['src', 'poster'] },
  { selector: 'audio', attrs: ['src'] },
  { selector: 'track', attrs: ['src'] },
  { selector: 'embed', attrs: ['src'] },
  { selector: 'object', attrs: ['data'] },
  { selector: 'input', attrs: ['src'] },
];

/** `<link rel>` values that cause a fetch this policy governs. */
const FETCHING_LINK_RELS = new Set([
  'stylesheet',
  'preload',
  'modulepreload',
  'icon',
  'shortcut icon',
  'apple-touch-icon',
  'apple-touch-icon-precomposed',
  'manifest',
  'mask-icon',
]);

const URL_IN_CSS = /url\(\s*(['"]?)([^'")]+)\1\s*\)/gi;

function srcsetUrls(value: string): string[] {
  return value
    .split(',')
    .map((candidate) => candidate.trim().split(/\s+/)[0] ?? '')
    .filter(Boolean);
}

export const paneCsp006 = defineRule({
  ...meta,
  requires: ['meta'],
  check(ctx: RuleContext): RuleResult {
    const csp = cspOf(ctx.meta);

    /** origin → the first reference that used it, so one origin is one finding. */
    const seen = new Map<string, { raw: string; where: string; location?: SourceLocation }>();

    const consider = (raw: string, where: string, location?: SourceLocation) => {
      const url = absoluteHttpUrl(raw);
      if (!url) return;
      if (anyEntryCovers(csp, url)) return;
      if (seen.has(url.origin)) return;
      seen.set(url.origin, { raw, where, ...(location ? { location } : {}) });
    };

    for (const { selector, attrs, srcset } of FETCH_ATTRS) {
      for (const el of selectAll(selector, ctx.dom)) {
        if (selector === 'input' && (attr(el, 'type') ?? '').toLowerCase() !== 'image') continue;
        for (const name of attrs) {
          const value = attr(el, name);
          if (!value) continue;
          const location = attrLocationOf(el, name);
          const raws = srcset && name === 'srcset' ? srcsetUrls(value) : [value];
          for (const raw of raws) consider(raw, `<${selector} ${name}>`, location);
        }
      }
    }

    for (const el of selectAll('link', ctx.dom)) {
      const rel = (attr(el, 'rel') ?? '').trim().toLowerCase();
      if (!FETCHING_LINK_RELS.has(rel)) continue;
      const href = attr(el, 'href');
      if (href) consider(href, `<link rel="${rel}">`, attrLocationOf(el, 'href'));
    }

    for (const decl of ctx.styles.allDeclarations()) {
      if (!decl.value.includes('url(')) continue;
      URL_IN_CSS.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = URL_IN_CSS.exec(decl.value)) !== null) {
        consider(m[2] ?? '', `CSS ${decl.prop}`, decl.location);
      }
    }

    const findings = [...seen.entries()].map(([origin, ref]) =>
      makeFinding({
        ctx,
        rule: meta,
        message:
          `${ref.where} loads from ${origin}, which no declared domain covers. ` +
          (csp
            ? 'The host must block connections to undeclared domains, so this request will fail at runtime.'
            : 'No _meta.ui.csp is declared, so the restrictive default applies and this request will fail at runtime.'),
        evidence: ref.raw,
        ...(ref.location ? { location: ref.location } : {}),
        path: `origin:${origin}`,
        assumption: CSP_SYNTHESIS_ASSUMPTION,
      }),
    );

    return { findings };
  },
});

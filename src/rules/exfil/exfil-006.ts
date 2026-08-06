/**
 * PANE-EXFIL-006 — `<base>` with an off-document `href`.
 *
 * One element repoints every relative URL in the document, including the
 * `action` of a form that looks same-document in the source.
 *
 * ── Correction against the RULES.md row ─────────────────────────────────────
 * The row reads "…or **any** `<base>` when `baseUriDomains` is unset". That
 * condition is universally true: measured, not one of the eight reference
 * servers declares `baseUriDomains`. So the rule as written fires on every app
 * that has a `<base>` at all — a gate-eligible HIGH/CERTAIN finding on
 * conformant markup, which is the single most expensive kind of bug this
 * project can ship (GOALS.md G2).
 *
 * Narrowed to an absolute off-document `href`. `<base target="_blank">` sets
 * only the default browsing context and has no `href`; `<base href="/">`
 * cannot leave a document whose origin is opaque. Both produce nothing.
 *
 * `baseUriDomains` still matters, and it is why this rule declares `meta`: the
 * spec's CSP construction sets `base-uri {baseUriDomains | 'self'}`, so a
 * declared entry covering the origin means a conforming host would permit this
 * `<base>` rather than block it. That changes the message, not the severity —
 * Panelint reports properties of the content, and host enforcement is out of
 * scope per non-goal N2.
 */

import type { RuleContext, RuleResult } from '../../types.js';
import { attr, attrLocationOf, selectAll } from '../../parse/html.js';
import {
  CSP_SYNTHESIS_ASSUMPTION,
  defineRule,
  makeFinding,
  structuralPath,
} from '../shared/helpers.js';
import { isOffDocument, offDocumentOrigin, originDeclared } from './url-shape.js';

const REMEDIATION =
  'Remove the `<base href>`, or point it at a same-document path. An off-document base rewrites ' +
  'every relative URL in the app, so a `<form action="/report">` that reads as same-document in ' +
  'the source submits to the base origin instead.';

export const exfil006 = defineRule({
  id: 'PANE-EXFIL-006',
  ruleClass: 'RISK',
  severity: 'HIGH',
  confidence: 'CERTAIN',
  title: 'Base element repoints every relative URL off-document',
  specRef: 'SEP-1865 apps.mdx L1743 — base-uri ${baseUriDomains} || \'self\'',
  cwe: 'CWE-942',
  remediation: REMEDIATION,
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['content', 'meta'],

  check(ctx: RuleContext): RuleResult {
    const findings = [];
    const declared = ctx.meta?.csp?.baseUriDomains;

    for (const el of selectAll('base[href]', ctx.dom)) {
      const href = attr(el, 'href') ?? '';
      if (!isOffDocument(href)) continue;

      const permitted = originDeclared(offDocumentOrigin(href), declared);
      const location = attrLocationOf(el, 'href');

      findings.push(
        makeFinding({
          ctx,
          rule: exfil006,
          message:
            '`<base href>` points off-document, so every relative URL in this app — form actions, ' +
            'subresource URLs, links — resolves against that origin instead. ' +
            (permitted
              ? 'The origin appears in the declared `baseUriDomains`, so the synthesized `base-uri` ' +
                'permits it and a conforming host would not block it.'
              : 'No `baseUriDomains` entry covers this origin, so the synthesized `base-uri` would ' +
                "default to `'self'`. Whether the host enforces that is out of scope (N2), and the " +
                'element is in the resource either way.'),
          evidence: href,
          ...(location ? { location } : {}),
          assumption: CSP_SYNTHESIS_ASSUMPTION,
          path: `${structuralPath(el)}@href`,
        }),
      );
    }

    return { findings };
  },
});

export default exfil006;

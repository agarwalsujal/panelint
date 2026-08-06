/**
 * PANE-CSP-012 — a user-publishable CDN is declared AND a script actually
 * executes from it without `integrity`.
 *
 * The escalation half of the split described in csp-008. The danger of a
 * publishable CDN is **script execution, not the declaration**:
 *
 *   PANE-CSP-008  the latent grant                     MEDIUM, below the gate
 *   PANE-CSP-012  the grant is actually used to run code  HIGH, gate-eligible
 *
 * ⚠ MEASURED, and this split is why the rule is shippable. `pdf-server`
 * declares `resourceDomains: ["https://unpkg.com"]` to fetch the pdf.js
 * Standard-14 fonts. It grants `script-src` to unpkg implicitly — one knob
 * opens five directives — but only ever loads *fonts* from it, so the script
 * capability is latent and unused. A single HIGH rule on the declaration alone
 * would have failed CI against a conformant reference server, breaching
 * GOALS.md G2 on day one.
 *
 * jsDelivr, unpkg and cdnjs serve arbitrary attacker-published npm packages, so
 * a script executing from one with no `integrity` is operationally close to
 * `script-src *` for anyone who can publish to npm. That is attacker A4's
 * `eslint-config-prettier` scenario with the door already open.
 *
 * `integrity` is the discriminator: a pinned hash means a substituted package
 * fails to execute rather than running silently.
 */

import type { RuleContext, RuleResult, Finding } from '../../types.js';
import { defineRule, makeFinding, structuralPath, CSP_SYNTHESIS_ASSUMPTION } from '../shared/helpers.js';
import { attr, attrLocationOf, selectAll } from '../../parse/html.js';
import { cspOf } from './domains.js';
import { publishableCdnEntries } from './csp-008-publishable-cdn.js';

export const paneCsp012 = defineRule({
  id: 'PANE-CSP-012',
  ruleClass: 'RISK',
  severity: 'HIGH',
  confidence: 'HIGH',
  title: 'Executable script loaded from a user-publishable CDN without integrity',
  specRef: 'SEP-1865 §Security Implications — CSP Enforcement',
  cwe: 'CWE-353',
  remediation:
    'Add an `integrity` hash (with `crossorigin`) to the script tag, or serve the ' +
    'script from an origin only you can publish to. Anyone able to publish to this ' +
    'CDN can change what executes inside the app.',
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['meta', 'content'],

  check(ctx: RuleContext): RuleResult {
    const csp = cspOf(ctx.meta);
    if (csp === null) return { findings: [] };

    const cdnHits = publishableCdnEntries(csp);
    if (cdnHits.length === 0) return { findings: [] };

    const findings: Finding[] = [];

    for (const script of selectAll('script[src]', ctx.dom)) {
      const src = (attr(script, 'src') ?? '').trim();
      if (!src) continue;

      // `integrity` present means a substituted package fails closed.
      if ((attr(script, 'integrity') ?? '').trim().length > 0) continue;

      let host: string;
      try {
        host = new URL(src).hostname.toLowerCase();
      } catch {
        // A relative script cannot come from a declared CDN.
        continue;
      }

      const hit = cdnHits.find((h) => {
        const declared = h.cdn.toLowerCase();
        return host === declared || host.endsWith(`.${declared}`);
      });
      if (!hit) continue;

      findings.push(
        makeFinding({
          ctx,
          rule: paneCsp012,
          message:
            `An executable script loads from \`${hit.cdn}\` with no \`integrity\` ` +
            'attribute, and `resourceDomains` grants that origin. Anyone able to publish ' +
            'to that CDN can change what runs inside this app.',
          evidence: src,
          location: attrLocationOf(script, 'src'),
          path: structuralPath(script),
          assumption: CSP_SYNTHESIS_ASSUMPTION,
        }),
      );
    }

    return { findings };
  },
});

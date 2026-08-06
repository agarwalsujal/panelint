/**
 * PANE-CSP-008 — `resourceDomains` covers a CDN anyone can publish to.
 *
 * ⚠ MEASURED: the original HIGH version failed on day one.
 * `pdf-server/server.ts` declares `resourceDomains: ["https://unpkg.com"]` — the
 * exact CDN this rule names — to fetch the PDF Standard-14 fonts that pdf.js
 * ships with. Legitimate, deliberate, and documented in a comment. At HIGH the
 * rule is gate-eligible, so it would have failed CI against a conformant
 * reference server, breaching GOALS.md G2 immediately.
 *
 * The split that fixes it is principled rather than cosmetic: **the danger of a
 * user-publishable CDN is script execution, not the declaration.** pdf-server
 * grants `script-src` to unpkg implicitly, but only ever loads *fonts* from it —
 * the script capability is latent and unused. So this rule reports the latent
 * grant at MEDIUM, below the default `--fail-on high` gate, and PANE-CSP-012
 * escalates to HIGH only when the HTML actually executes a script from that
 * origin without `integrity`.
 *
 * pdf-server therefore produces exactly one MEDIUM finding and does not break
 * the build. `test/rules-csp.test.ts` locks that.
 */

import type { RuleMeta, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding, CSP_SYNTHESIS_ASSUMPTION } from '../shared/helpers.js';
import {
  cspOf,
  entriesOf,
  parseSource,
  pointerFor,
  type DomainEntry,
  type ParsedSource,
} from './domains.js';
import { RESOURCE_FAN_OUT } from './evaluator-adapter.js';
import type { UIResourceCsp } from '../../types.js';

/**
 * Origins that serve packages published by arbitrary third parties.
 *
 * The distinguishing property is not "CDN" — a first-party `cdn.mycorp.com` is
 * fine, and Google Fonts is not on this list. It is that ANY STRANGER can put
 * executable JavaScript on the origin, which makes granting it `script-src`
 * operationally equivalent to `script-src *` for anyone who can publish to npm
 * or push to a GitHub repository.
 */
const PUBLISHABLE_CDN_HOSTS: readonly string[] = Object.freeze([
  'cdn.jsdelivr.net',
  'fastly.jsdelivr.net',
  'unpkg.com',
  'npmcdn.com',
  'raw.githubusercontent.com',
  'gist.githubusercontent.com',
  'rawcdn.githack.com',
  'raw.githack.com',
  'cdn.statically.io',
  'cdnjs.cloudflare.com',
  'esm.sh',
  'esm.run',
  'cdn.skypack.dev',
  'jspm.dev',
  'ga.jspm.io',
  'bundle.run',
  'cdn.pika.dev',
]);

/** A path pinning a specific published version, e.g. `/chart.js@4.4.1/`. */
const PINNED_PATH = /(@\d+[\w.+-]*|\/\d+\.\d+[\w.+-]*)(\/|$)/;

export interface PublishableCdnHit {
  entry: DomainEntry;
  parsed: ParsedSource;
  cdn: string;
}

/**
 * `resourceDomains` entries that cover a user-publishable CDN.
 *
 * Shared with PANE-CSP-012 so the escalation is defined over exactly the set
 * this rule reports — "…**and** the HTML loads a script from that origin" has to
 * mean the same origins in both places.
 *
 * A version-pinned path is exempt: `https://unpkg.com/pdfjs-dist@4.0.379/`
 * grants one immutable published artifact, not the whole registry.
 */
export function publishableCdnEntries(csp: UIResourceCsp | null): PublishableCdnHit[] {
  const out: PublishableCdnHit[] = [];
  for (const entry of entriesOf(csp, 'resourceDomains')) {
    const parsed = parseSource(entry.value);
    if (parsed.kind !== 'host' || !parsed.host) continue;
    if (parsed.path && PINNED_PATH.test(parsed.path)) continue;

    const host = parsed.host;
    const cdn = PUBLISHABLE_CDN_HOSTS.find((candidate) =>
      host.startsWith('*.') ? candidate.endsWith(host.slice(1)) : candidate === host,
    );
    if (cdn) out.push({ entry, parsed, cdn });
  }
  return out;
}

const meta: RuleMeta = {
  id: 'PANE-CSP-008',
  ruleClass: 'RISK',
  severity: 'MEDIUM',
  confidence: 'HIGH',
  title: 'resourceDomains grants a user-publishable CDN',
  specRef: 'SEP-1865 §Security Implications — CSP Enforcement',
  cwe: 'CWE-1104',
  remediation:
    'Pin the entry to the exact published version the app loads, vendor the file into ' +
    'the resource, or move it to an origin only you can publish to.',
  experimental: false,
  status: 'active',
  since: '0.1.0',
};

export const paneCsp008 = defineRule({
  ...meta,
  requires: ['meta'],
  check(ctx: RuleContext): RuleResult {
    const csp = cspOf(ctx.meta);
    if (!csp) return { findings: [] };

    const findings = publishableCdnEntries(csp).map((hit) =>
      makeFinding({
        ctx,
        rule: meta,
        message:
          `resourceDomains declares ${hit.entry.value}, and ${hit.cdn} serves packages ` +
          `published by arbitrary third parties. One entry there opens ` +
          `${RESOURCE_FAN_OUT.join(', ')}, so this is a latent script-execution grant as ` +
          'well as an image-beacon and CSS-exfiltration sink. Reported at MEDIUM because ' +
          'the grant may be unused — PANE-CSP-012 escalates if a script actually loads from it.',
        evidence: hit.entry.value,
        jsonPointer: pointerFor(hit.entry.array, hit.entry.index),
        assumption: CSP_SYNTHESIS_ASSUMPTION,
      }),
    );

    return { findings };
  },
});

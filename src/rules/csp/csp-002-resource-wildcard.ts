/**
 * PANE-CSP-002 — bare or scheme-only wildcard in `resourceDomains`.
 *
 * ⚠ DOC BUG. RULES.md's `-002` row reads "`resourceDomains` contains `*`". Taken
 * literally that flags `https://*.mapbox.com`, and `-002` is CRITICAL at CERTAIN
 * confidence — gate-eligible, so it would break the build of the
 * best-configured server in the corpus. The `-001` carve-out applies here too:
 * a BARE `*` or a scheme-only source, and nothing else. The boxed
 * `-001` vs `-005` note two paragraphs below that table says so; the row text
 * contradicts it.
 *
 * `resourceDomains` is one knob that opens FIVE directives — `script-src`,
 * `style-src`, `img-src`, `font-src`, `media-src` — which is why this rule is
 * CRITICAL where `-001` is HIGH. A wildcard here is `script-src *`.
 */

import type { RuleMeta, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding, CSP_SYNTHESIS_ASSUMPTION } from '../shared/helpers.js';
import { cspOf, entriesOf, isUnboundedSource, parseSource, pointerFor } from './domains.js';
import { RESOURCE_FAN_OUT } from './evaluator-adapter.js';

const meta: RuleMeta = {
  id: 'PANE-CSP-002',
  ruleClass: 'RISK',
  severity: 'CRITICAL',
  confidence: 'CERTAIN',
  title: 'Wildcard resource domain declared — script may load from anywhere',
  specRef: 'SEP-1865 §Security Implications — CSP Enforcement',
  cwe: 'CWE-942',
  remediation:
    'Replace the wildcard with the specific origins the app loads scripts, styles, ' +
    'images, fonts and media from.',
  experimental: false,
  status: 'active',
  since: '0.1.0',
};

export const paneCsp002 = defineRule({
  ...meta,
  requires: ['meta'],
  check(ctx: RuleContext): RuleResult {
    const csp = cspOf(ctx.meta);
    if (!csp) return { findings: [] };

    const findings = [];
    for (const entry of entriesOf(csp, 'resourceDomains')) {
      const parsed = parseSource(entry.value);
      const kind = isUnboundedSource(parsed);
      if (!kind) continue;

      const scope =
        kind === 'bare-wildcard'
          ? 'every origin on the internet'
          : `every origin on the ${parsed.scheme}: scheme`;

      findings.push(
        makeFinding({
          ctx,
          rule: meta,
          message:
            `resourceDomains declares ${entry.value}. One entry there opens ` +
            `${RESOURCE_FAN_OUT.join(', ')} — so this grants script execution from ` +
            `${scope}, not merely image loading.`,
          evidence: entry.value,
          jsonPointer: pointerFor(entry.array, entry.index),
          assumption: CSP_SYNTHESIS_ASSUMPTION,
        }),
      );
    }

    return { findings };
  },
});

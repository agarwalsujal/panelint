/**
 * PANE-DOM-001 — string-to-DOM sink assigned a non-literal value.
 *
 * Attacker A1 is the stated design centre of the threat model, and before v2
 * the only rule addressing A1's ingress was PANE-CONTEXT-005, deferred to v1.1.
 * This rule covers the sink side deterministically, with no taint analysis.
 *
 * It is reported as CAPABILITY DISCLOSURE, not accusation: *this app builds DOM
 * from strings; if any of those strings is tool output, T2 applies.* It is the
 * v1 approximation of PANE-CONTEXT-005 and upgrades to a taint finding in v1.1
 * rather than being replaced.
 *
 * ── The correction that makes it shippable ──────────────────────────────────
 * As first written — "any assignment to innerHTML" — this rule produced ELEVEN
 * findings on `pdf-server`, every one either a static icon-SVG literal or
 * `innerHTML = ""` to clear a layer. None can carry injected content. At HIGH
 * confidence it is gate-eligible, so that alone would have failed the corpus
 * gate. The assigned expression must therefore be NON-LITERAL.
 *
 * "Literal" includes more than a string literal. A template literal with no
 * interpolation is literal, the empty string is literal, and — the case that
 * catches pdf-server's pattern with one refactor applied — a module-level
 * `const ICON = '<svg…>'` referenced by name is literal too. An Identifier is
 * non-literal unless somebody resolves it, and `moduleStringConstants` is who
 * resolves it.
 */

import type { Finding, RuleContext, RuleResult, UndecidedNote } from '../../types.js';
import { defineRule, makeFinding, structuralPath, undecided } from '../shared/helpers.js';
import { analyseDataflow, isEffectivelyLiteral, moduleStringConstants, scriptsOf } from '../shared/dataflow.js';
import { sourceOf } from '../exfil/url-shape.js';

const REMEDIATION =
  'Build the node with `textContent`, `createElement` and `append` instead, or run the string ' +
  'through a sanitizer before it reaches the sink. If the string can ever contain tool output, ' +
  'this is the point at which attacker-authored markup becomes part of the app.';

export const dom001 = defineRule({
  id: 'PANE-DOM-001',
  ruleClass: 'RISK',
  severity: 'HIGH',
  confidence: 'HIGH',
  title: 'DOM built from a non-literal string',
  specRef: 'docs/THREAT-MODEL.md A1 — data supply; T2 rendered injection',
  cwe: 'CWE-79',
  remediation: REMEDIATION,
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['content'],

  check(ctx: RuleContext): RuleResult {
    const scripts = scriptsOf(ctx);
    const consts = moduleStringConstants(scripts);
    const df = analyseDataflow(scripts);

    const findings: Finding[] = [];
    const notes: UndecidedNote[] = [];
    let n = 0;

    for (const sink of df.sinks) {
      if (sink.kind !== 'dom-html') continue;
      // `el.insertAdjacentHTML('beforeend')` with no second argument writes
      // nothing. No value, no finding.
      if (!sink.valueNode) continue;
      if (isEffectivelyLiteral(sink.valueNode, consts)) continue;

      const base = sink.script.element ? structuralPath(sink.script.element) : 'script';
      findings.push(
        makeFinding({
          ctx,
          rule: dom001,
          message:
            `\`${sink.detail}\` is assigned a value built at runtime. The app constructs DOM from ` +
            'strings, so any of those strings that carries tool output carries whatever markup the ' +
            'tool returned. This is reported as a capability, not as proof of a defect.',
          evidence: sourceOf(sink.script, sink.node),
          ...(sink.location ? { location: sink.location } : {}),
          path: `${base}::${sink.detail}#${n++}`,
        }),
      );
    }

    // A script that did not parse has no sinks, which is indistinguishable from
    // a script with none. Say so rather than report clean.
    for (const script of df.unparsedScripts) {
      notes.push(
        undecided(
          ctx,
          dom001,
          `a script did not parse (${script.parseError ?? 'unknown'}); its DOM sinks were not inspected`,
        ),
      );
    }

    return { findings, ...(notes.length ? { undecided: notes } : {}) };
  },
});

export default dom001;

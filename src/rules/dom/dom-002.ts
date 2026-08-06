/**
 * PANE-DOM-002 — string evaluated as code.
 *
 * ── Why this is INFO, and why that is not a concession ──────────────────────
 * `threejs-server` uses `new Function(…)` as THE CORE MECHANISM of the app: it
 * is how LLM-authored scene code is executed, and there is no alternative code
 * path. Flagging it as RISK would fail the corpus gate against a reference
 * server whose entire purpose is that pattern.
 *
 * It is also largely moot. The mandated default CSP omits `'unsafe-eval'`
 * (docs/SPEC-REFERENCE.md §3.1), and `_meta.ui.csp` has no field that could add
 * it — `resourceDomains` maps to `script-src` origins, not to source
 * expressions. So in a conformant host these calls are blocked before they run.
 *
 * That makes this an INTENT SIGNAL and never an exploit, which is exactly what
 * INFO says. An operator deserves to know the app wants to evaluate strings;
 * nobody's build should break over it.
 */

import type { Finding, RuleContext, RuleResult, UndecidedNote } from '../../types.js';
import { defineRule, makeFinding, structuralPath, undecided } from '../shared/helpers.js';
import { analyseDataflow, scriptsOf } from '../shared/dataflow.js';
import { sourceOf } from '../exfil/url-shape.js';

const REMEDIATION =
  'None required for conformance — the mandated default CSP omits `\'unsafe-eval\'`, so these ' +
  'calls do not run in a conformant host. If the app depends on them working, that dependency is ' +
  'the finding: it will fail in the field, and it is worth stating in the app\'s documentation.';

export const dom002 = defineRule({
  id: 'PANE-DOM-002',
  ruleClass: 'INFO',
  severity: 'MEDIUM',
  confidence: 'HIGH',
  title: 'String evaluated as code',
  specRef: 'SEP-1865 apps.mdx L275-284 — the default policy omits \'unsafe-eval\'',
  cwe: 'CWE-95',
  remediation: REMEDIATION,
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['content'],

  check(ctx: RuleContext): RuleResult {
    const df = analyseDataflow(scriptsOf(ctx));
    const findings: Finding[] = [];
    const notes: UndecidedNote[] = [];
    let n = 0;

    for (const sink of df.sinks) {
      if (sink.kind !== 'eval') continue;
      const base = sink.script.element ? structuralPath(sink.script.element) : 'script';
      findings.push(
        makeFinding({
          ctx,
          rule: dom002,
          message:
            `\`${sink.detail}\` evaluates a string as code. Reported as an intent signal, not as an ` +
            'exploit: the mandated default CSP omits `\'unsafe-eval\'`, and no `_meta.ui.csp` field ' +
            'can add it, so a conformant host blocks this call.',
          evidence: sourceOf(sink.script, sink.node),
          ...(sink.location ? { location: sink.location } : {}),
          path: `${base}::eval#${n++}`,
        }),
      );
    }

    for (const script of df.unparsedScripts) {
      notes.push(
        undecided(
          ctx,
          dom002,
          `a script did not parse (${script.parseError ?? 'unknown'}); its evaluation sinks were not inspected`,
        ),
      );
    }

    return { findings, ...(notes.length ? { undecided: notes } : {}) };
  },
});

export default dom002;

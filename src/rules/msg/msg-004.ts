/**
 * PANE-MSG-004 — `event.data` from a raw `message` listener reaching a DOM or
 * eval sink.
 *
 * Composes with PANE-DOM-001/002: those two rules report the sink
 * deterministically (any non-literal value reaching `innerHTML` etc.); this
 * rule additionally names the SOURCE when it can trace one — `event.data` from
 * `window.addEventListener('message', …)`, which per docs/SPEC-REFERENCE.md §4
 * is attacker-reachable regardless of what `PANE-MSG-001` finds, because
 * `event.source` identity is the transport's only defense and a sibling app can
 * reach it through `window.frames[]`.
 *
 * This is one of the four rules built on the shared dataflow pass
 * (src/rules/shared/dataflow.ts), and ships at MEDIUM confidence for the same
 * reason all four do: the pass is intraprocedural only, so a value handed to a
 * call it cannot resolve is an UNKNOWN, reported as `undecided()`, never
 * guessed into a finding.
 */

import type { Finding, RuleContext, RuleResult, UndecidedNote } from '../../types.js';
import { defineRule, makeFinding, structuralPath, undecided } from '../shared/helpers.js';
import { DOM_SINKS, analyseDataflow, scriptsOf } from '../shared/dataflow.js';
import { sourceOf } from '../exfil/url-shape.js';

const REMEDIATION =
  'Do not pass `event.data` from a `message` listener into `innerHTML`, `document.write`, `eval` or ' +
  'similar sinks. Validate `event.source` first (see PANE-MSG-001), and treat the payload as ' +
  'untrusted even after that check — build DOM with `textContent`/`createElement`, or sanitize.';

export const msg004 = defineRule({
  id: 'PANE-MSG-004',
  ruleClass: 'RISK',
  severity: 'CRITICAL',
  confidence: 'MEDIUM',
  title: 'postMessage event.data reaches a DOM or eval sink',
  specRef: 'docs/SPEC-REFERENCE.md §4',
  cwe: 'CWE-79',
  remediation: REMEDIATION,
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['content'],

  check(ctx: RuleContext): RuleResult {
    const scripts = scriptsOf(ctx);
    const df = analyseDataflow(scripts);
    const findings: Finding[] = [];
    const notes: UndecidedNote[] = [];
    let n = 0;

    for (const flow of df.flowsInto(DOM_SINKS, ['message-event'])) {
      const base = flow.sink.script.element ? structuralPath(flow.sink.script.element) : 'script';
      findings.push(
        makeFinding({
          ctx,
          rule: msg004,
          message:
            `\`${flow.sink.detail}\` receives a value traced back to \`${flow.source.label}\` — ` +
            "a raw `message` listener's `event.data`. Reported as a MEDIUM-confidence trace, not a " +
            'proof: this pass is intraprocedural and does not model everything a real app does.' +
            (flow.crossScope ? ' The value crosses out of the handler that received it.' : ''),
          evidence: sourceOf(flow.sink.script, flow.sink.node),
          ...(flow.sink.location ? { location: flow.sink.location } : {}),
          path: `${base}::${flow.sink.detail}#${n++}`,
        }),
      );
    }

    for (const escape of df.escapesFrom(['message-event'])) {
      notes.push(undecided(ctx, msg004, `event.data ${escape.reason}`, escape.location));
    }

    for (const script of df.unparsedScripts) {
      notes.push(
        undecided(
          ctx,
          msg004,
          `a script did not parse (${script.parseError ?? 'unknown'}); its dataflow was not inspected`,
        ),
      );
    }

    return { findings, ...(notes.length ? { undecided: notes } : {}) };
  },
});

export default msg004;

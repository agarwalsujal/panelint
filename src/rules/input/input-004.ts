/**
 * PANE-INPUT-004 — `paste` / `drop` listener reading `clipboardData` /
 * `dataTransfer` into a sink or egress channel.
 *
 * One of the four rules built on the shared dataflow pass
 * (src/rules/shared/dataflow.ts). Pasted or dropped content is
 * attacker-influenced the same way tool output is — whatever the user last
 * copied, or whatever a dragged file/text contains, is not something this app
 * authored. Feeding it straight into a DOM sink, an eval sink, or a host-RPC /
 * navigation channel reported here is capability disclosure at MEDIUM
 * confidence, for the same reason every dataflow-pass rule is MEDIUM: the pass
 * is intraprocedural, and a value handed to an unresolvable call is reported as
 * `undecided()`, never guessed into a finding.
 */

import type { Finding, RuleContext, RuleResult, UndecidedNote } from '../../types.js';
import { defineRule, makeFinding, structuralPath, undecided } from '../shared/helpers.js';
import {
  DOM_SINKS,
  HOST_RPC_SINKS,
  analyseDataflow,
  scriptsOf,
  type SinkKind,
} from '../shared/dataflow.js';
import { sourceOf } from '../exfil/url-shape.js';

const ALL_SINKS: readonly SinkKind[] = Object.freeze([...DOM_SINKS, ...HOST_RPC_SINKS, 'link-href']);

const REMEDIATION =
  'Treat pasted or dropped content as untrusted. Sanitize before it reaches a DOM sink, avoid ' +
  'evaluating it as code, and do not forward it to a host-RPC call or a navigation target without ' +
  'validating what it contains — a paste or a drop is not something this app authored.';

export const input004 = defineRule({
  id: 'PANE-INPUT-004',
  ruleClass: 'RISK',
  severity: 'MEDIUM',
  confidence: 'MEDIUM',
  title: 'Pasted or dropped content reaches a sink or egress channel',
  specRef: 'docs/RULES.md — PANE-INPUT',
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

    for (const flow of df.flowsInto(ALL_SINKS, ['clipboard', 'drop'])) {
      const base = flow.sink.script.element ? structuralPath(flow.sink.script.element) : 'script';
      findings.push(
        makeFinding({
          ctx,
          rule: input004,
          message:
            `\`${flow.sink.detail}\` receives a value traced back to \`${flow.source.label}\`. ` +
            'Reported as a MEDIUM-confidence trace, not a proof: this pass is intraprocedural and ' +
            'does not model everything a real app does.' +
            (flow.crossScope ? ' The value crosses out of the handler that received it.' : ''),
          evidence: sourceOf(flow.sink.script, flow.sink.node),
          ...(flow.sink.location ? { location: flow.sink.location } : {}),
          path: `${base}::${flow.sink.detail}#${n++}`,
        }),
      );
    }

    for (const escape of df.escapesFrom(['clipboard', 'drop'])) {
      notes.push(undecided(ctx, input004, escape.reason, escape.location));
    }

    for (const script of df.unparsedScripts) {
      notes.push(
        undecided(
          ctx,
          input004,
          `a script did not parse (${script.parseError ?? 'unknown'}); its dataflow was not inspected`,
        ),
      );
    }

    return { findings, ...(notes.length ? { undecided: notes } : {}) };
  },
});

export default input004;

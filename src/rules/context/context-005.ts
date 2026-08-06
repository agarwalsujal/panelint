/**
 * PANE-CONTEXT-005 — a model-context or DOM write reachable from tool output.
 *
 * The crown-jewel rule (docs/RULES.md § Gate eligibility, § PANE-CONTEXT). Its
 * source and sinks are concrete per docs/SPEC-REFERENCE.md §4:
 *
 *   SOURCE — the `ui/notifications/tool-result` handler: the single ingress by
 *   which hostile data reaches an app. Also `tool-input`, `tool-input-partial`
 *   and `host-context-changed`, the rest of the inbound notification set
 *   (`NOTIFICATION_SOURCES`, src/rules/shared/dataflow.ts).
 *
 *   SINKS — `ui/message`, `ui/update-model-context`, `ui/download-file`,
 *   `ui/open-link` (`HOST_RPC_SINKS`), and the DOM sinks PANE-DOM-001/002 cover
 *   (`DOM_SINKS`).
 *
 * This is the v1.1 upgrade of PANE-DOM-001's v1 approximation ("this app builds
 * DOM from strings; IF any of those strings is tool output…") into an actual
 * traced answer, and it does the same for PANE-CONTEXT-007/008's INFO-level
 * capability disclosure of `ui/download-file` / `ui/open-link` — when reachable
 * from tainted data, THIS rule reports it, at RISK/CRITICAL rather than INFO.
 *
 * MEDIUM confidence is deliberate, not a placeholder: docs/RULES.md is explicit
 * that this rule "cannot gate even though it is CRITICAL — the crown-jewel rule
 * is advisory until its false-positive rate is measured." The shared dataflow
 * pass is intraprocedural only; anything it cannot resolve is an `Escape`,
 * reported here as `undecided()`, never guessed into a finding.
 */

import type { Finding, RuleContext, RuleResult, UndecidedNote } from '../../types.js';
import { defineRule, makeFinding, structuralPath, undecided } from '../shared/helpers.js';
import {
  DOM_SINKS,
  HOST_RPC_SINKS,
  NOTIFICATION_SOURCES,
  analyseDataflow,
  scriptsOf,
  type SinkKind,
} from '../shared/dataflow.js';
import { sourceOf } from '../exfil/url-shape.js';

const ALL_SINKS: readonly SinkKind[] = Object.freeze([...HOST_RPC_SINKS, ...DOM_SINKS]);

const REMEDIATION =
  'Do not let tool output reach `ui/message`, `ui/update-model-context`, `ui/download-file`, ' +
  '`ui/open-link`, or a DOM/eval sink without validating it first. Tool output is attacker-A1 ' +
  'controlled data (docs/THREAT-MODEL.md); a write surface reachable from it is a complete ' +
  'injection or exfiltration path, whether the write lands in the model\'s context, on the user\'s ' +
  "disk, in the user's browser, or in this app's own DOM.";

export const context005 = defineRule({
  id: 'PANE-CONTEXT-005',
  ruleClass: 'RISK',
  severity: 'CRITICAL',
  confidence: 'MEDIUM',
  title: 'Model-context or DOM write reachable from tool output',
  specRef: 'docs/SPEC-REFERENCE.md §4 — tool-result is the ingress; sinks named there',
  cwe: 'CWE-74',
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

    for (const flow of df.flowsInto(ALL_SINKS, NOTIFICATION_SOURCES)) {
      const base = flow.sink.script.element ? structuralPath(flow.sink.script.element) : 'script';
      findings.push(
        makeFinding({
          ctx,
          rule: context005,
          message:
            `\`${flow.sink.detail}\` receives a value traced back to \`${flow.source.label}\` — the ` +
            'app has ingested hostile data via a host notification and this is a write surface it can ' +
            'reach. Reported as a MEDIUM-confidence trace, not a proof: this pass is intraprocedural ' +
            'and does not model everything a real app does.' +
            (flow.crossScope ? ' The value crosses out of the handler that received it.' : ''),
          evidence: sourceOf(flow.sink.script, flow.sink.node),
          ...(flow.sink.location ? { location: flow.sink.location } : {}),
          path: `${base}::${flow.sink.detail}#${n++}`,
        }),
      );
    }

    for (const escape of df.escapesFrom(NOTIFICATION_SOURCES)) {
      notes.push(undecided(ctx, context005, escape.reason, escape.location));
    }

    for (const script of df.unparsedScripts) {
      notes.push(
        undecided(
          ctx,
          context005,
          `a script did not parse (${script.parseError ?? 'unknown'}); its dataflow was not inspected`,
        ),
      );
    }

    return { findings, ...(notes.length ? { undecided: notes } : {}) };
  },
});

export default context005;

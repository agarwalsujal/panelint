/**
 * PANE-EXFIL-005 — `<a href>` to an off-origin URL with a runtime-built query
 * string.
 *
 * ── The RULES.md row is written backwards; this implements only the first
 *    clause ──────────────────────────────────────────────────────────────────
 * The catalog row as written also carries a `target="_blank"` clause
 * ("… *(The `target="_blank"` clause is withdrawn — see below)*"), and that
 * withdrawal note itself has the polarity backwards: the clause as drafted
 * would flag `target="_self"` and treat `target="_blank" rel="noopener"` as
 * the *safe* case, which is the classic reverse-tabnabbing shape read
 * upside-down — and inside the View's sandbox, which is documented to grant no
 * `allow-popups` by default (PANE-EXFIL-004's own reasoning), `target="_blank"`
 * frequently cannot open a new browsing context at all, making that half of
 * the row close to vacuous even read correctly. This implementation covers
 * ONLY the off-origin-href-with-runtime-query-string clause. The `target`
 * clause is not implemented here; it is reported as a doc bug, not silently
 * dropped.
 *
 * ── Why this is dataflow-based rather than a literal check ───────────────────
 * `PANE-EXFIL-002` (form action) and `PANE-EXFIL-004` (navigation) fire on ANY
 * non-literal value reaching their sink — that is enough there because the
 * sink itself is inherently off-document by construction (a form/navigation
 * target with no literal is assumed hostile-shaped). An anchor's `href`/
 * `.search` sink is different: assigning it a non-literal value is completely
 * ordinary (`a.search = '?id=' + rowId` inside an in-app data table). What
 * makes this specific shape worth a MEDIUM-confidence finding is BOTH that the
 * literal PREFIX of the runtime-built string is off-origin, AND that the
 * variable part of it can be traced to a source this pass tracks
 * (src/rules/shared/dataflow.ts) — not merely "is not a literal." That is the
 * "via the dataflow pass" instruction this rule follows: it consumes
 * `analyseDataflow`'s `link-href` sink and `flows`, the same pass
 * PANE-MSG-004, PANE-INPUT-004 and PANE-CONTEXT-005 use, with the same MEDIUM
 * confidence and the same escape-to-`undecided()` discipline.
 */

import type { Node } from 'acorn';
import type { Finding, RuleContext, RuleResult, UndecidedNote } from '../../types.js';
import { defineRule, makeFinding, structuralPath, undecided } from '../shared/helpers.js';
import { analyseDataflow, scriptsOf } from '../shared/dataflow.js';
import { isOffDocument, sourceOf } from './url-shape.js';

const REMEDIATION =
  'Do not build an off-origin link URL from runtime data, especially data traced back to tool ' +
  'output, a postMessage, or a paste/drop. If the destination must carry a variable query string, ' +
  'validate the value first, or route the request through `fetch()` to an origin declared in ' +
  '`connectDomains` where the CSP applies.';

/** The leading literal-string portion of a concatenation or template literal. */
function staticPrefix(node: Node): string | null {
  const n = node as unknown as {
    type: string;
    value?: unknown;
    left?: Node;
    operator?: string;
    quasis?: Array<{ value?: { cooked?: string | null } }>;
  };
  if (n.type === 'Literal') return typeof n.value === 'string' ? n.value : null;
  if (n.type === 'TemplateLiteral') {
    const cooked = n.quasis?.[0]?.value?.cooked;
    return typeof cooked === 'string' ? cooked : null;
  }
  if (n.type === 'BinaryExpression' && n.operator === '+' && n.left) return staticPrefix(n.left);
  return null;
}

export const exfil005 = defineRule({
  id: 'PANE-EXFIL-005',
  ruleClass: 'RISK',
  severity: 'MEDIUM',
  confidence: 'MEDIUM',
  title: 'Anchor href to an off-origin URL with a runtime-built query string',
  specRef: 'docs/RULES.md — PANE-EXFIL (target="_blank" clause withdrawn; see file header)',
  cwe: 'CWE-201',
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

    for (const flow of df.flowsInto(['link-href'])) {
      if (!flow.sink.valueNode) continue;
      const prefix = staticPrefix(flow.sink.valueNode);
      if (prefix === null) {
        notes.push(
          undecided(
            ctx,
            exfil005,
            `\`${flow.sink.detail}\` is built from \`${flow.source.label}\` with no static literal ` +
              'prefix visible; whether the resulting URL is off-origin cannot be determined',
            flow.sink.location,
          ),
        );
        continue;
      }
      if (!isOffDocument(prefix)) continue;

      const base = flow.sink.script.element ? structuralPath(flow.sink.script.element) : 'script';
      findings.push(
        makeFinding({
          ctx,
          rule: exfil005,
          message:
            `\`${flow.sink.detail}\` is built from a literal off-origin prefix (\`${prefix}\`) with a ` +
            `query string traced back to \`${flow.source.label}\`. No \`_meta.ui.csp\` field governs ` +
            'anchor navigation.',
          evidence: sourceOf(flow.sink.script, flow.sink.node),
          ...(flow.sink.location ? { location: flow.sink.location } : {}),
          path: `${base}::${flow.sink.detail}#${n++}`,
        }),
      );
    }

    for (const script of df.unparsedScripts) {
      notes.push(
        undecided(
          ctx,
          exfil005,
          `a script did not parse (${script.parseError ?? 'unknown'}); its dataflow was not inspected`,
        ),
      );
    }

    return { findings, ...(notes.length ? { undecided: notes } : {}) };
  },
});

export default exfil005;

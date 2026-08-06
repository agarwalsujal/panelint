/**
 * PANE-EXFIL-002 — form `action` assigned at runtime.
 *
 * PANE-EXFIL-001 reads markup. This reads the assignment that makes the markup
 * irrelevant: `form.action = sink + secret` produces the same unblockable
 * submission with a clean-looking `<form>` in the source.
 *
 * ── The literal carve-out ───────────────────────────────────────────────────
 * RULES.md's row has NO literal carve-out and needs one, exactly as
 * PANE-DOM-001 does. `form.setAttribute('action', '/search')` is a literal
 * same-document assignment; at HIGH/HIGH this rule is gate-eligible, so without
 * the carve-out it breaks a conformant build. `isLiteralExpression` is the same
 * predicate that keeps PANE-DOM-001 off pdf-server's eleven static icon-SVG
 * assignments — a template literal with no interpolation and the empty string
 * both count as literal.
 *
 * ── The receiver problem ────────────────────────────────────────────────────
 * `.action` is not an HTML-only property name. `state.action = payload` is
 * ordinary reducer code. Panelint does not do type inference, so a receiver it
 * cannot identify as a form is reported at MEDIUM confidence — visible in the
 * report, below the gate, not breaking anyone's build over a Redux store.
 * Silence would be worse: per SECURITY.md §1 a payload that reaches "no
 * finding" through a gap the attacker chooses is a bug in Panelint.
 */

import type { Node } from 'acorn';
import { simple as walkSimple } from 'acorn-walk';
import type { RuleContext, RuleResult, Confidence, Finding, SourceLocation } from '../../types.js';
import { findCalls, findMemberAssignments, isLiteralExpression } from '../../parse/js.js';
import { defineRule, makeFinding, structuralPath } from '../shared/helpers.js';
import { scriptsOf, sourceOf } from './url-shape.js';
import type { ParsedScript } from '../../parse/js.js';

const REMEDIATION =
  'Do not retarget a form at runtime. No `_meta.ui.csp` field can constrain where a form submits — ' +
  '`form-action` does not exist in the schema and does not inherit from `default-src`. Send the ' +
  "data with `fetch()` to an origin declared in `connectDomains`, where the host's CSP applies.";

/** Attribute names whose assignment retargets a submission. */
const ATTR_SINKS = new Set(['action', 'formaction']);
/** Property names for the same, in their IDL spelling. */
const PROP_SINKS = ['action', 'formAction'];

/** DOM lookups whose result is an element, whatever the receiver. */
const DOM_QUERIES =
  /^(getElementById|querySelector|querySelectorAll|createElement|closest|getElementsBy[A-Za-z]+)$/;

function isDomQuery(node: Node | undefined): boolean {
  if (!node) return false;
  const n = node as unknown as { type: string; callee?: Node; object?: Node; property?: Node; computed?: boolean };
  if (n.type === 'CallExpression') {
    const callee = n.callee as unknown as { type?: string; property?: Node; computed?: boolean };
    if (callee?.type !== 'MemberExpression' || callee.computed) return false;
    const name = (callee.property as unknown as { name?: string }).name ?? '';
    return DOM_QUERIES.test(name);
  }
  // `document.forms['report']`, `document.forms[0]`
  if (n.type === 'MemberExpression') {
    const obj = n.object as unknown as { type?: string; property?: Node; computed?: boolean };
    if (obj?.type === 'MemberExpression' && !obj.computed) {
      return ((obj.property as unknown as { name?: string }).name ?? '') === 'forms';
    }
  }
  return false;
}

/**
 * Local names bound to a DOM element in this script.
 *
 * `const f = document.getElementById('f'); f.action = sink + secret` is the
 * ordinary shape of this attack, and `f` tells a name-matching heuristic
 * nothing. One binding pass over the script closes that gap without pretending
 * to be data-flow analysis: it is scope-blind and single-level by design.
 */
function domBoundNames(script: ParsedScript): Set<string> {
  const out = new Set<string>();
  if (!script.ast) return out;

  walkSimple(script.ast, {
    VariableDeclarator(node: Node) {
      const d = node as unknown as { id: Node; init?: Node };
      const id = d.id as unknown as { type: string; name?: string };
      if (id.type === 'Identifier' && id.name && isDomQuery(d.init)) out.add(id.name);
    },
    AssignmentExpression(node: Node) {
      const a = node as unknown as { left: Node; right: Node };
      const l = a.left as unknown as { type: string; name?: string };
      if (l.type === 'Identifier' && l.name && isDomQuery(a.right)) out.add(l.name);
    },
  });
  return out;
}

/**
 * Can this receiver be identified as a form or a submit control?
 *
 * Deliberately shallow — it decides confidence, never whether to report.
 */
function looksLikeFormElement(node: Node | undefined, domBound: Set<string>): boolean {
  if (!node) return false;
  const n = node as unknown as {
    type: string;
    name?: string;
    property?: Node;
    object?: Node;
    computed?: boolean;
    callee?: Node;
    arguments?: Node[];
  };

  if (n.type === 'Identifier') {
    return domBound.has(n.name ?? '') || /form|submit/i.test(n.name ?? '');
  }
  if (n.type === 'ThisExpression') return false;

  if (n.type === 'MemberExpression') {
    const prop = n.property as unknown as { type: string; name?: string; value?: unknown };
    if (!n.computed && /form|submit/i.test(prop.name ?? '')) return true;
    // `document.forms['x']`, `this.refs.form.action`
    return looksLikeFormElement(n.object, domBound);
  }

  if (n.type === 'CallExpression') {
    const callee = n.callee as unknown as { type: string; property?: Node; computed?: boolean };
    const method =
      callee?.type === 'MemberExpression' && !callee.computed
        ? ((callee.property as unknown as { name?: string }).name ?? '')
        : '';
    const arg0 = n.arguments?.[0] as unknown as { type?: string; value?: unknown } | undefined;
    const literal = arg0?.type === 'Literal' && typeof arg0.value === 'string' ? arg0.value : '';
    if (/^(querySelector|querySelectorAll|closest|createElement)$/.test(method)) {
      return /form|button|input/i.test(literal);
    }
    if (method === 'getElementById') return true;
  }

  return false;
}

function path(script: ParsedScript, sink: string, index: number): string {
  const base = script.element ? structuralPath(script.element) : 'script';
  return `${base}::${sink}#${index}`;
}

export const exfil002 = defineRule({
  id: 'PANE-EXFIL-002',
  ruleClass: 'RISK',
  severity: 'HIGH',
  confidence: 'HIGH',
  title: 'Form action assigned at runtime',
  specRef: 'SEP-1865 apps.mdx L1733-1744 — form-action absent from the CSP construction',
  cwe: 'CWE-201',
  remediation: REMEDIATION,
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['content'],

  check(ctx: RuleContext): RuleResult {
    const scripts = scriptsOf(ctx);
    const findings: Finding[] = [];
    let n = 0;

    const report = (
      script: ParsedScript,
      node: Node,
      sink: string,
      confidence: Confidence,
      detail: string,
      location: SourceLocation | undefined,
    ): void => {
      findings.push(
        makeFinding({
          ctx,
          rule: exfil002,
          message:
            `Submission target assigned at runtime via \`${sink}\` from a non-literal expression. ` +
            'No `_meta.ui.csp` field governs where a form submits. ' +
            detail,
          evidence: sourceOf(script, node),
          ...(location ? { location } : {}),
          confidence,
          path: path(script, sink, n++),
        }),
      );
    };

    // `form.action = …`, `btn.formAction = …`
    const bound = new Map<ParsedScript, Set<string>>();
    const domBoundIn = (script: ParsedScript): Set<string> => {
      let s = bound.get(script);
      if (!s) {
        s = domBoundNames(script);
        bound.set(script, s);
      }
      return s;
    };

    for (const a of findMemberAssignments(scripts, PROP_SINKS)) {
      if (isLiteralExpression(a.right)) continue;
      const left = (a.node as unknown as { left: Node }).left as unknown as { object?: Node };
      const idlSpelling = a.property !== 'action'; // `formAction` is HTML-only
      const identified = idlSpelling || looksLikeFormElement(left.object, domBoundIn(a.script));
      report(
        a.script,
        a.node,
        `.${a.property}`,
        identified ? 'HIGH' : 'MEDIUM',
        identified
          ? 'The assigned value is built at runtime, so the destination is not visible in the resource.'
          : 'The receiver could not be identified as a form element, so this is reported below the ' +
            'gate: `.action` is also an ordinary property name on ordinary objects.',
        a.location,
      );
    }

    // `form.setAttribute('action', …)` — the attribute name is HTML-specific,
    // so the receiver question does not arise.
    for (const call of findCalls(scripts, [{ method: 'setAttribute' }])) {
      const [nameArg, valueArg] = call.args;
      const name = nameArg as unknown as { type?: string; value?: unknown } | undefined;
      if (name?.type !== 'Literal' || typeof name.value !== 'string') continue;
      if (!ATTR_SINKS.has(name.value.toLowerCase())) continue;
      if (!valueArg || isLiteralExpression(valueArg)) continue;

      report(
        call.script,
        call.node,
        `setAttribute('${name.value.toLowerCase()}')`,
        'HIGH',
        'The assigned value is built at runtime, so the destination is not visible in the resource.',
        call.location,
      );
    }

    return { findings };
  },
});

export default exfil002;

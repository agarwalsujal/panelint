/**
 * PANE-MSG-003 — `postMessage(…, "*")` to a target other than the host bridge.
 *
 * The transport's own outbound call is `postMessage(msg, "*")` to the HOST —
 * that is sanctioned and documented (docs/SPEC-REFERENCE.md §4: "Messages are
 * sent using postMessage with '*' origin … the receiver should validate the
 * message source"). This rule is not about wildcard-origin sends in general —
 * it is about sends to a target that is NOT the host bridge, i.e. an app
 * relaying or forwarding a message to some other window: `event.source`, an
 * `<iframe>.contentWindow`, `window.opener`, another frame. That is how a
 * message gets INJECTED somewhere it does not belong.
 *
 * ── Why call-site analysis alone is not enough ───────────────────────────────
 * The shipped `ext-apps` SDK bundle contains a real `postMessage(X, "*")` call
 * site: `this.eventTarget.postMessage(X, "*")`. `this.eventTarget` is not a
 * literal `window.parent` at the call site — it is a class field, assigned in
 * the constructor from a parameter that DEFAULTS to `window.parent`:
 *
 *     class Transport {
 *       constructor(target = window.parent) { this.eventTarget = target; }
 *       send(msg) { this.eventTarget.postMessage(msg, "*"); }
 *     }
 *
 * A rule that flags every `X.postMessage(_, "*")` where `X` is not literally
 * `window.parent` fires on the SDK's own transport inside every app that
 * bundles it. So this rule resolves ONE level of indirection — the
 * `this.<field> = <ctor param>` / `<ctor param> = window.parent` (default)
 * shape that the SDK actually uses — and for anything it cannot resolve that
 * way, it declines to answer rather than guess. It only fires when the
 * receiver is a STRUCTURALLY KNOWN non-bridge target: `event.source`,
 * `.contentWindow`, `.frames[…]`, `.opener` — names that are never how an app
 * refers to its own outbound channel to the host.
 */

import type { Node } from 'acorn';
import { simple as walkSimple } from 'acorn-walk';
import type { Finding, RuleContext, RuleResult, UndecidedNote } from '../../types.js';
import type { ParsedScript } from '../../parse/js.js';
import { findCalls } from '../../parse/js.js';
import { defineRule, makeFinding, structuralPath, undecided } from '../shared/helpers.js';
import { pathOf, scriptsOf } from '../shared/dataflow.js';
import { sourceOf } from '../exfil/url-shape.js';

const REMEDIATION =
  'Send outbound `postMessage` calls only to the host bridge (`window.parent`, or the value your ' +
  "transport initializes from it). Relaying a message to `event.source`, an <iframe>'s " +
  '`contentWindow`, `window.opener` or a sibling frame with a wildcard target origin hands whatever ' +
  "you send to a window you do not control the identity of.";

/** Synonyms for "the host bridge", the only sanctioned wildcard-origin target. */
const HOST_BRIDGE_PATHS = new Set([
  'window.parent',
  'parent',
  'top',
  'window.top',
  'self.parent',
  'globalThis.parent',
]);

/** Structurally known to be something other than the host bridge. */
function isDefinitelyNotBridge(path: string): boolean {
  return (
    path === 'source' ||
    path.endsWith('.source') ||
    path === 'opener' ||
    path.endsWith('.opener') ||
    path.endsWith('.contentWindow') ||
    path.includes('.frames') ||
    path === 'frames'
  );
}

/** Every `Function*` parameter with a default value, name → pathOf(default). */
function paramDefaults(script: ParsedScript): Map<string, string> {
  const map = new Map<string, string>();
  if (!script.ast) return map;
  const collect = (node: Node) => {
    const params = (node as unknown as { params?: Node[] }).params ?? [];
    for (const p of params) {
      const ap = p as unknown as { type: string; left?: Node; right?: Node };
      if (ap.type !== 'AssignmentPattern' || !ap.left || !ap.right) continue;
      const left = ap.left as unknown as { type: string; name?: string };
      if (left.type !== 'Identifier' || !left.name) continue;
      const rp = pathOf(ap.right);
      if (rp) map.set(left.name, rp);
    }
  };
  walkSimple(script.ast, {
    FunctionDeclaration: collect,
    FunctionExpression: collect,
    ArrowFunctionExpression: collect,
  });
  return map;
}

/** The right-hand side of the FIRST `this.<field> = …` assignment found. */
function thisFieldAssignmentRight(script: ParsedScript, field: string): Node | null {
  if (!script.ast) return null;
  let found: Node | null = null;
  walkSimple(script.ast, {
    AssignmentExpression(node: Node) {
      if (found) return;
      const a = node as unknown as { left: Node; right: Node };
      const l = a.left as unknown as { type: string; object?: Node; property?: Node; computed?: boolean };
      if (l.type !== 'MemberExpression' || l.computed) return;
      const obj = l.object as unknown as { type: string };
      if (obj.type !== 'ThisExpression') return;
      const prop = l.property as unknown as { type: string; name?: string };
      if (prop.type !== 'Identifier' || prop.name !== field) return;
      found = a.right;
    },
  });
  return found;
}

type Classification = 'bridge' | 'other' | 'unknown';

function classifyPath(path: string, script: ParsedScript, defaults: Map<string, string>): Classification {
  if (HOST_BRIDGE_PATHS.has(path)) return 'bridge';
  if (isDefinitelyNotBridge(path)) return 'other';

  const thisFieldMatch = /^this\.([A-Za-z_$][\w$]*)$/.exec(path);
  if (thisFieldMatch) {
    const right = thisFieldAssignmentRight(script, thisFieldMatch[1]!);
    if (!right) return 'unknown';
    const rp = pathOf(right);
    if (rp) {
      const byPath = classifyResolvedPath(rp, defaults);
      if (byPath !== 'unknown') return byPath;
    }
    const ident = right as unknown as { type: string; name?: string };
    if (ident.type === 'Identifier' && ident.name && defaults.has(ident.name)) {
      return classifyResolvedPath(defaults.get(ident.name)!, defaults);
    }
    return 'unknown';
  }

  if (!path.includes('.') && defaults.has(path)) {
    return classifyResolvedPath(defaults.get(path)!, defaults);
  }

  return 'unknown';
}

function classifyResolvedPath(path: string, defaults: Map<string, string>): Classification {
  if (HOST_BRIDGE_PATHS.has(path)) return 'bridge';
  if (isDefinitelyNotBridge(path)) return 'other';
  if (!path.includes('.') && defaults.has(path)) {
    const d = defaults.get(path)!;
    if (HOST_BRIDGE_PATHS.has(d)) return 'bridge';
    if (isDefinitelyNotBridge(d)) return 'other';
  }
  return 'unknown';
}

export const msg003 = defineRule({
  id: 'PANE-MSG-003',
  ruleClass: 'RISK',
  severity: 'MEDIUM',
  confidence: 'CERTAIN',
  title: 'postMessage sent wildcard-origin to a target other than the host bridge',
  specRef: 'docs/SPEC-REFERENCE.md §4',
  cwe: 'CWE-940',
  remediation: REMEDIATION,
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['content'],

  check(ctx: RuleContext): RuleResult {
    const scripts = scriptsOf(ctx);
    const findings: Finding[] = [];
    const notes: UndecidedNote[] = [];
    let n = 0;

    for (const call of findCalls(scripts, [{ method: 'postMessage' }])) {
      const args = call.args;
      const targetArg = args[1];
      const isWildcard =
        targetArg && (targetArg as unknown as { type: string; value?: unknown }).type === 'Literal' &&
        (targetArg as unknown as { value?: unknown }).value === '*';
      if (!isWildcard) continue;

      const raw = call.node as unknown as { callee: { object?: Node } };
      const receiver = raw.callee.object;
      if (!receiver) continue;

      const path = pathOf(receiver);
      if (!path) {
        notes.push(
          undecided(
            ctx,
            msg003,
            'a postMessage(…, "*") call\'s target is not a statically resolvable identifier or member ' +
              'chain; whether it is the host bridge cannot be determined',
            call.location,
          ),
        );
        continue;
      }

      const classification = classifyPath(path, call.script, paramDefaults(call.script));
      if (classification === 'bridge') continue;
      if (classification === 'unknown') {
        notes.push(
          undecided(
            ctx,
            msg003,
            `postMessage(…, "*") target resolves through \`${path}\`, which this pass could not trace ` +
              'back to window.parent or to a known non-bridge target',
            call.location,
          ),
        );
        continue;
      }

      const base = call.script.element ? structuralPath(call.script.element) : 'script';
      findings.push(
        makeFinding({
          ctx,
          rule: msg003,
          message:
            `\`${path}.postMessage(…, "*")\` sends to a target that is structurally NOT the host ` +
            'bridge. A wildcard target origin combined with a non-bridge receiver delivers the ' +
            'message to a window this app does not control the identity of.',
          evidence: sourceOf(call.script, call.node),
          ...(call.location ? { location: call.location } : {}),
          path: `${base}::postmessage-wrong-target#${n++}`,
        }),
      );
    }

    for (const script of scripts) {
      if (script.ast) continue;
      notes.push(
        undecided(
          ctx,
          msg003,
          `a script did not parse (${script.parseError ?? 'unknown'}); its postMessage calls were not inspected`,
        ),
      );
    }

    return { findings, ...(notes.length ? { undecided: notes } : {}) };
  },
});

export default msg003;

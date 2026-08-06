/**
 * PANE-MSG-001 — `message` listener with no origin/source check.
 *
 * ── The only rule in the catalog with INVERTED polarity ──────────────────────
 * Every other rule's finding is "this construct is present." This rule's finding
 * is "this construct is ABSENT" — there is no `event.origin` or `event.source`
 * check anywhere in the handler. That inversion means every analysis limitation
 * becomes a false-positive generator: a handler this pass cannot see into is a
 * handler that LOOKS like it has no check, whether or not it does.
 *
 * The measured case that makes this concrete: the official `ext-apps` SDK
 * registers its transport with
 *
 *     window.addEventListener("message", this.messageListener)
 *
 * a METHOD REFERENCE, not an inline function. A rule that inspects the handler
 * body for a check finds no body at all here. Reporting "no check" on that
 * would be a gate-eligible HIGH finding on the SDK's own transport, inside
 * every application that bundles it — the exact failure this catalog's
 * corpus-gate discipline exists to catch before it ships.
 *
 * `messageListenerSites` (src/rules/shared/dataflow.ts) is where this was
 * fixed: it reports EVERY `addEventListener('message', …)` call site,
 * including the ones whose handler is a name or a reference rather than an
 * inline function, and tags them `handlerKind: 'reference' | 'unknown'` with
 * `resolved: null`. This rule's whole job is to treat that null honestly:
 * unresolved means UNDECIDED, never a finding. Only a handler this pass can
 * actually read the body of, and that body demonstrably lacks both checks, is
 * reported.
 *
 * A resolved handler that never reads `event.data` at all is also left alone —
 * a listener that ignores `.data` entirely (e.g. one that only inspects
 * `event.ports`) has no path for untrusted data to reach anything, so "no
 * origin check" says nothing useful about it.
 */

import type { Finding, RuleContext, RuleResult, UndecidedNote } from '../../types.js';
import { defineRule, makeFinding, structuralPath, undecided } from '../shared/helpers.js';
import { messageListenerSites, scriptsOf } from '../shared/dataflow.js';
import { sourceOf } from '../exfil/url-shape.js';

const REMEDIATION =
  'Check `event.origin` (or `event.source`) before trusting `event.data`, on every code path. ' +
  '`window.frames[]` is cross-origin reachable, so a sibling app can deliver a message straight ' +
  "to this handler — `event.source` identity is the transport's only defense per " +
  'docs/SPEC-REFERENCE.md §4.';

/** Rough source-text check for whether a handler ever reads `<param>.data`. */
function readsEventData(code: string, start: number, end: number, paramName: string | null): boolean {
  if (!paramName) return true; // destructured / unknown param shape — cannot rule it out
  const body = code.slice(start, end);
  const re = new RegExp(`\\b${paramName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*\\.\\s*data\\b`);
  return re.test(body);
}

export const msg001 = defineRule({
  id: 'PANE-MSG-001',
  ruleClass: 'RISK',
  severity: 'HIGH',
  confidence: 'HIGH',
  title: 'message listener with no origin or source check',
  specRef: 'docs/SPEC-REFERENCE.md §4 — event.source identity is the transport\'s only defense',
  cwe: 'CWE-346',
  remediation: REMEDIATION,
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['content'],

  check(ctx: RuleContext): RuleResult {
    const scripts = scriptsOf(ctx);
    const sites = messageListenerSites(scripts);
    const findings: Finding[] = [];
    const notes: UndecidedNote[] = [];
    let n = 0;

    for (const site of sites) {
      if (site.handlerKind !== 'inline' || !site.resolved) {
        notes.push(
          undecided(
            ctx,
            msg001,
            `a message listener's handler is a ${site.handlerKind === 'reference' ? 'name/reference' : 'non-analysable expression'}, ` +
              'not an inline function; whether it checks origin or source cannot be determined statically',
            site.location,
          ),
        );
        continue;
      }

      const { resolved } = site;
      if (resolved.checksOrigin || resolved.checksSource) continue;

      const node = site.node as unknown as { start?: number; end?: number };
      const usesData =
        typeof node.start === 'number' && typeof node.end === 'number'
          ? readsEventData(site.script.code, node.start, node.end, resolved.paramName)
          : true;
      if (!usesData) continue;

      const base = site.script.element ? structuralPath(site.script.element) : 'script';
      findings.push(
        makeFinding({
          ctx,
          rule: msg001,
          message:
            "This `message` listener checks neither `event.origin` nor `event.source` before using " +
            '`event.data`. `window.frames[]` is cross-origin reachable, so a sibling app can deliver a ' +
            "message straight into this handler — `event.source` identity is the transport's only " +
            'defense, and this handler does not use it.',
          evidence: sourceOf(site.script, site.node),
          ...(site.location ? { location: site.location } : {}),
          path: `${base}::message-listener#${n++}`,
        }),
      );
    }

    for (const script of scripts) {
      if (script.ast) continue;
      notes.push(
        undecided(
          ctx,
          msg001,
          `a script did not parse (${script.parseError ?? 'unknown'}); its message listeners were not inspected`,
        ),
      );
    }

    return { findings, ...(notes.length ? { undecided: notes } : {}) };
  },
});

export default msg001;

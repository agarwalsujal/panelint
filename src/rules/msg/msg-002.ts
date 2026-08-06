/**
 * PANE-MSG-002 — weak `event.origin` check: substring match or unanchored regex.
 *
 * A check that exists but is bypassable is worse than no check at all, because
 * it reads as safe in review. Two concrete bypasses:
 *
 *   `event.origin.indexOf("https://good.example") !== -1` passes for
 *   `https://evil.example/?x=https://good.example`.
 *
 *   `event.origin.startsWith("https://good.example")` passes for
 *   `https://good.example.evil.tld`.
 *
 *   `/good\.example/.test(event.origin)` (no `^`/`$`) passes for
 *   `https://evil.example/?good.example`.
 *
 * ── Why this reads the regex LITERAL, and never constructs or runs one ───────
 * The pattern a scanned app writes is attacker-influenced input from Panelint's
 * point of view — an app author can craft a regex literal deliberately shaped
 * to be expensive. Calling `new RegExp(pattern)` or `.test()` on a pattern taken
 * from the scanned app would be ReDoS-by-proxy: the attacker supplies the
 * pattern and Panelint (or the CI runner invoking it) is who eats the CPU. This
 * rule never does that. `findMessageListeners` (src/parse/js.ts) reads the
 * anchor question straight off the acorn `RegExpLiteral` node's `.regex.pattern`
 * — the SOURCE TEXT the parser already extracted — and never evaluates the
 * pattern as a regular expression at all.
 *
 * The weak-check detection itself lives in `analyseHandler` (src/parse/js.ts),
 * reused here via `messageListenerSites`. This rule's only job is to turn
 * `weakOriginChecks` into findings and to decline to answer for handlers it
 * cannot see into — the same false-positive discipline as PANE-MSG-001, applied
 * to a narrower question.
 */

import type { Finding, RuleContext, RuleResult, UndecidedNote } from '../../types.js';
import { defineRule, makeFinding, structuralPath, undecided } from '../shared/helpers.js';
import { messageListenerSites, scriptsOf } from '../shared/dataflow.js';

const REMEDIATION =
  'Compare `event.origin` with `===` against an exact, fully-qualified origin (or a Set of them). ' +
  'Never use `indexOf`, `startsWith`, `endsWith`, `includes`, `search` or `match` — all five accept ' +
  'an attacker-chosen origin that merely contains or is prefixed/suffixed by the expected string. A ' +
  'regex check must anchor both ends: `/^https:\\/\\/example\\.com$/`.';

export const msg002 = defineRule({
  id: 'PANE-MSG-002',
  ruleClass: 'RISK',
  severity: 'HIGH',
  confidence: 'CERTAIN',
  title: 'event.origin compared with a substring method or an unanchored regex',
  specRef: 'docs/SPEC-REFERENCE.md §4',
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
            msg002,
            `a message listener's handler is a ${site.handlerKind === 'reference' ? 'name/reference' : 'non-analysable expression'}, ` +
              'not an inline function; the strength of any origin check cannot be determined statically',
            site.location,
          ),
        );
        continue;
      }

      const base = site.script.element ? structuralPath(site.script.element) : 'script';
      for (const weak of site.resolved.weakOriginChecks) {
        findings.push(
          makeFinding({
            ctx,
            rule: msg002,
            message:
              `This handler checks \`event.origin\` with ${weak.kind}. A substring or unanchored-regex ` +
              'test on `event.origin` accepts origins that merely contain, prefix, or suffix the ' +
              'expected value — it is bypassable, not a real origin check.',
            evidence: weak.kind,
            ...(weak.location ? { location: weak.location } : {}),
            path: `${base}::weak-origin-check#${n++}`,
          }),
        );
      }
    }

    for (const script of scripts) {
      if (script.ast) continue;
      notes.push(
        undecided(
          ctx,
          msg002,
          `a script did not parse (${script.parseError ?? 'unknown'}); its message listeners were not inspected`,
        ),
      );
    }

    return { findings, ...(notes.length ? { undecided: notes } : {}) };
  },
});

export default msg002;

/**
 * PANE-CONTEXT-009 — the app requests fullscreen display mode.
 *
 * Fullscreen is the precondition for whole-surface impersonation: an app that
 * fills the entire View can render a credential prompt with no host chrome
 * visible around it at all. Composes with PANE-OVERLAY-001 and
 * PANE-MIMIC-008. Only the literal `"fullscreen"` mode counts as a finding; a
 * non-literal mode argument is a real gap in what a static scanner can tell,
 * so it is reported as `undecided()` rather than guessed either way.
 */

import type { Finding, RuleContext, RuleResult, UndecidedNote } from '../../types.js';
import { defineRule, makeFinding, undecided } from '../shared/helpers.js';
import { scriptsOf, rebase, sourceOf } from '../exfil/url-shape.js';
import { findAppMethodCalls, literalStringValue, objectProp } from './shared.js';

const REMEDIATION =
  'Disclose in the resource description that this app can request the whole View surface. ' +
  'Fullscreen removes the host chrome that would otherwise bound the app visually, which is the ' +
  'precondition for whole-surface impersonation of a credential prompt.';

export const context009 = defineRule({
  id: 'PANE-CONTEXT-009',
  ruleClass: 'RISK',
  severity: 'MEDIUM',
  confidence: 'CERTAIN',
  title: 'App requests fullscreen display mode',
  specRef: 'SPEC-REFERENCE.md §4 — ui/request-display-mode',
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

    for (const call of findAppMethodCalls(scripts, ['requestDisplayMode'])) {
      const modeNode = objectProp(call.args[0] ?? null, 'mode');
      if (!modeNode) continue;

      const literalMode = literalStringValue(modeNode);
      if (literalMode !== null) {
        if (literalMode !== 'fullscreen') continue;
        const loc = rebase(call.script, call.node);
        findings.push(
          makeFinding({
            ctx,
            rule: context009,
            message:
              '`requestDisplayMode` is called with `mode: "fullscreen"`. Fullscreen removes the host ' +
              'chrome around the app, which is the precondition for whole-surface impersonation of a ' +
              'credential prompt or other host UI.',
            evidence: sourceOf(call.script, call.node),
            ...(loc ? { location: loc } : {}),
            path: `script#${n++}`,
          }),
        );
        continue;
      }

      // Neither a Literal string nor an interpolation-free TemplateLiteral —
      // whether this ever resolves to "fullscreen" cannot be determined
      // statically. Say so rather than assume either way.
      notes.push(
        undecided(
          ctx,
          context009,
          '`requestDisplayMode` is called with a non-literal `mode` argument, so whether it ever ' +
            'requests fullscreen cannot be determined statically',
          rebase(call.script, call.node),
        ),
      );
    }

    return { findings, ...(notes.length ? { undecided: notes } : {}) };
  },
});

export default context009;

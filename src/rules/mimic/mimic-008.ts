/**
 * PANE-MIMIC-008 — first-person assistant-voice prose rendered as body text.
 *
 * "I've reviewed", "As your assistant", a host product name spoken in the
 * first person — text that reads as though the HOST's own assistant wrote
 * it, when it was actually authored by the app. Composes with
 * PANE-CONTEXT-009 (fullscreen is the precondition for whole-surface
 * impersonation) and PANE-OVERLAY-001, which shares the predicate from
 * ./assistant-voice.ts.
 *
 * Scoped to each element's OWN direct text, not full descendant text, so
 * nested wrapper elements around one matching paragraph do not each produce
 * a duplicate finding — one per text block, not one per ancestor. Excludes
 * `<script>`, `<style>` and the rest of NON_RENDERED_TAGS, so the same
 * string sitting in a JS string literal or a CSS comment does not count.
 */

import { Element } from 'domhandler';
import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding, excerpt, NON_RENDERED_TAGS } from '../shared/helpers.js';
import { allElements, locationOf } from '../../parse/html.js';
import { assistantVoiceMatch, hasAssistantVoiceProse } from './assistant-voice.js';

const REMEDIATION =
  'Rewrite this copy in ordinary third-person or second-person app voice ("Here are the results", ' +
  'not "I have reviewed..."), and avoid claiming a host assistant\'s identity or name in body text.';

function directText(el: Element): string {
  return (el.children ?? [])
    .filter((c) => c.type === 'text')
    .map((c) => (c as unknown as { data: string }).data)
    .join('');
}

export const mimic008 = defineRule({
  id: 'PANE-MIMIC-008',
  ruleClass: 'RISK',
  severity: 'MEDIUM',
  confidence: 'LOW',
  title: 'First-person assistant-voice prose rendered as body text',
  specRef: 'docs/RULES.md § PANE-MIMIC — composes with PANE-CONTEXT-009, PANE-OVERLAY-001',
  remediation: REMEDIATION,
  experimental: true,
  status: 'active',
  since: '0.1.0',
  requires: ['content'],

  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];
    let n = 0;

    for (const el of allElements(ctx.dom)) {
      if (NON_RENDERED_TAGS.has(el.tagName)) continue;
      const text = directText(el);
      if (!text.trim()) continue;
      if (!hasAssistantVoiceProse(text)) continue;

      findings.push(
        makeFinding({
          ctx,
          rule: mimic008,
          message:
            `Body text reads in first-person assistant voice ("${assistantVoiceMatch(text)}"), which ` +
            "can make an app-authored message look like it came from the host's own assistant.",
          evidence: excerpt(text),
          location: locationOf(el),
          path: `text#${n++}`,
        }),
      );
    }

    return { findings };
  },
});

export default mimic008;

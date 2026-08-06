/**
 * PANE-HIDDEN-007 — an HTML comment containing prose.
 *
 * A comment is invisible to a human and fully present to anything reading the
 * markup. Most comments are not payloads, which is why this is LOW/MEDIUM and
 * why the exclusion list is long and specific:
 *
 *   - `panelint-disable*` — our own suppression syntax. Flagging it would make
 *     suppressing a finding produce a finding.
 *   - Framework hydration markers — React's `<!--$-->` / `<!--/$-->`, the
 *     `<!--[-->` / `<!--]-->` fragment anchors, Angular bindings, Vue anchors.
 *   - Licence and copyright headers.
 *   - Commented-out markup and code, which is untidy rather than hidden prose.
 */

import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding, excerpt } from '../shared/helpers.js';
import { scaleHiddenFinding } from '../shared/scale.js';
import { createHash } from 'node:crypto';
import { collapse, commentNodes, meta, nodeData } from './common.js';

const RULE = meta({
  id: 'PANE-HIDDEN-007',
  severity: 'LOW',
  confidence: 'MEDIUM',
  title: 'HTML comment containing prose',
  cwe: 'CWE-615',
  remediation: 'Remove prose comments from shipped resources, or move them to source that is not served.',
});

/** Below this a comment cannot carry an instruction worth reporting. */
const MIN_CHARS = 24;

const PANELINT_SUPPRESSION = /^\s*panelint-(disable|enable|ignore)/i;

const FRAMEWORK_MARKER =
  /^\s*(\$!?\??|\/\$|\[|\]|-|\s*|\/?\s*(ko|\/ko)\b.*|bindings=\{.*\}|container.*|teleport.*|v-if.*|\/?\$?[0-9]*)\s*$/;

const LICENCE = /\b(copyright|\(c\)\s*\d{4}|spdx-license-identifier|all rights reserved|licen[cs]ed under|licen[cs]e|@license|@preserve)\b/i;

const CONDITIONAL = /^\s*(\[if\b|<!\[endif)/i;

/** Markup or code that was commented out, rather than prose that was written. */
function looksLikeCode(text: string): boolean {
  if (/<\/?[a-z][\w-]*[\s>/]/i.test(text)) return true;
  const codeChars = (text.match(/[{};=<>()[\]]/g) ?? []).length;
  return codeChars / Math.max(text.length, 1) > 0.05;
}

/** Enough words, and enough of them letters, to be prose rather than a token. */
function looksLikeProse(text: string): boolean {
  const words = text.split(/\s+/).filter((w) => /[a-z]{2,}/i.test(w));
  if (words.length < 5) return false;
  const letters = (text.match(/[a-z]/gi) ?? []).length;
  return letters / text.length > 0.55;
}

export const paneHidden007 = defineRule({
  ...RULE,
  requires: ['content'],
  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];

    for (const node of commentNodes(ctx.dom)) {
      const raw = nodeData(node);
      if (PANELINT_SUPPRESSION.test(raw)) continue;
      // Length-guard FRAMEWORK_MARKER. Its alternation has three adjacent
      // whitespace-matching constructs, two of which match empty, so a comment
      // of spaces that fails the final anchor makes the engine enumerate the
      // splits: 1 000 spaces → 0.35 s, 4 000 → 15 s, 8 000 → 89 s. A 4 KB
      // capture file bought 15 seconds of CPU, and comments are all processed
      // inside this one check() with no deadline between them.
      //
      // Every real framework anchor — `$`, `/$`, `[`, `]`, `ko`, `v-if`,
      // `teleport` — is a handful of characters. Anything longer is not one.
      if (raw.length <= 512 && FRAMEWORK_MARKER.test(raw)) continue;
      if (CONDITIONAL.test(raw)) continue;
      if (LICENCE.test(raw)) continue;

      const text = collapse(raw);
      if (text.length < MIN_CHARS) continue;
      if (looksLikeCode(text)) continue;
      if (!looksLikeProse(text)) continue;

      const scaled = scaleHiddenFinding({ ceiling: RULE.severity, text });

      findings.push(
        makeFinding({
          ctx,
          rule: RULE,
          severity: scaled.severity,
          message: `An HTML comment carries ${text.length} characters of prose — ${scaled.rationale}.`,
          evidence: excerpt(text),
          // Comments have no element ancestry, so the fingerprint keys on the
          // comment's own content. Stable across reformatting, distinct per
          // comment, and it does not leak the text — it is a digest.
          path: `comment:${createHash('sha256').update(text).digest('hex').slice(0, 16)}`,
        }),
      );
    }

    return { findings };
  },
});

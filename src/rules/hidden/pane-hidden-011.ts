/**
 * PANE-HIDDEN-011 — ZWJ / ZWNJ / BOM / soft hyphen / word-joiner family,
 * volume-gated.
 *
 * The half of the original PANE-HIDDEN-009 that unicode.ts's split moved
 * here, because every character in `ZERO_WIDTH` has a real, common,
 * legitimate use: ZWJ builds emoji sequences and Indic conjuncts, ZWNJ is
 * orthographically required in Persian, Hindi and Malayalam, U+FEFF is a
 * legitimate leading BOM, and U+2060–U+2064 have real line-break-control and
 * math-markup uses. Presence is never the signal here — `analyzeZeroWidth`
 * fires only on a run of ≥3 consecutive zero-width characters, ≥8 occurrences
 * in one unit, or a single occurrence sitting somewhere its script does not
 * call for one (docs/RULES.md § PANE-HIDDEN-011).
 *
 * Scans the same three unit kinds as -009 — text nodes, attribute values,
 * comments — through the same `decodeInvisibleEntities` pre-pass, for the
 * same reason: entity references inside `<script>`/`<style>` raw text are
 * never decoded by the HTML parser, so a scan of the tree alone would miss
 * them. The first text node of the document is marked as such, because a
 * leading BOM is legitimate only there.
 */

import { createHash } from 'node:crypto';
import type { Element } from 'domhandler';
import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding, structuralPath, excerpt } from '../shared/helpers.js';
import { allElements, locationOf } from '../../parse/html.js';
import { collapse, commentNodes, meta, nodeData, textNodes } from './common.js';
import { analyzeZeroWidth, decodeInvisibleEntities } from './unicode.js';

const RULE = meta({
  id: 'PANE-HIDDEN-011',
  severity: 'MEDIUM',
  confidence: 'MEDIUM',
  title: 'Zero-width or invisible-formatting characters, volume-gated',
  cwe: 'CWE-838',
  remediation:
    'Remove characters outside a run of ≥3, a count of ≥8 per unit, or any occurrence outside ' +
    'a script context that needs one. A single ZWJ in an emoji sequence or a leading BOM is fine.',
});

function hashPath(prefix: string, text: string): string {
  return `${prefix}:${createHash('sha256').update(text).digest('hex').slice(0, 16)}`;
}

export const paneHidden011 = defineRule({
  ...RULE,
  requires: ['content'],
  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];

    const push = (text: string, summary: string, message: string, path: string, owner?: Element) => {
      findings.push(
        makeFinding({
          ctx,
          rule: RULE,
          message: `${message} — ${summary}.`,
          evidence: excerpt(text),
          ...(owner ? { location: locationOf(owner) } : {}),
          path,
        }),
      );
    };

    const units = textNodes(ctx.dom);
    for (let index = 0; index < units.length; index++) {
      const { node, owner } = units[index]!;
      const decoded = decodeInvisibleEntities(nodeData(node)).decoded;
      const report = analyzeZeroWidth(decoded, { unitStartsDocument: index === 0 });
      if (report.gates.length === 0) continue;
      const text = collapse(decoded);
      push(
        text,
        report.gates.join('; '),
        owner
          ? `<${owner.tagName}> carries invisible-formatting characters (${report.summary})`
          : `Document text carries invisible-formatting characters (${report.summary})`,
        owner ? structuralPath(owner) : hashPath('text', text),
        owner ?? undefined,
      );
    }

    for (const el of allElements(ctx.dom)) {
      for (const [name, value] of Object.entries(el.attribs ?? {})) {
        const decoded = decodeInvisibleEntities(value).decoded;
        const report = analyzeZeroWidth(decoded);
        if (report.gates.length === 0) continue;
        push(
          collapse(decoded),
          report.gates.join('; '),
          `<${el.tagName} ${name}> carries invisible-formatting characters in an attribute value (${report.summary})`,
          `${structuralPath(el)}@${name.toLowerCase()}`,
          el,
        );
      }
    }

    for (const node of commentNodes(ctx.dom)) {
      const decoded = decodeInvisibleEntities(nodeData(node)).decoded;
      const report = analyzeZeroWidth(decoded);
      if (report.gates.length === 0) continue;
      const text = collapse(decoded);
      push(
        text,
        report.gates.join('; '),
        `An HTML comment carries invisible-formatting characters (${report.summary})`,
        hashPath('comment', text),
      );
    }

    if (findings.length === 0) {
      const decoded = decodeInvisibleEntities(ctx.rawSource).decoded;
      const report = analyzeZeroWidth(decoded, { unitStartsDocument: true });
      if (report.gates.length > 0) {
        const text = collapse(decoded).slice(0, 200);
        push(
          text,
          report.gates.join('; '),
          `The raw resource bytes carry invisible-formatting characters not reachable through any parsed node (${report.summary})`,
          hashPath('raw-source', text),
        );
      }
    }

    return { findings };
  },
});

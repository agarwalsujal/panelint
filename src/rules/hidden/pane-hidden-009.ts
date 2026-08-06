/**
 * PANE-HIDDEN-009 — Unicode TAG characters, U+E0000–U+E007F.
 *
 * The only CERTAIN rule in either family (CLAUDE.md §3). Panelint does not
 * compute styles, but this is not a style question: a code point in the TAG
 * block has no rendering glyph in any font, on any platform, ever. That is a
 * fact about Unicode, not an inference about layout, so it survives any
 * rendering and CERTAIN is the honest confidence to claim.
 *
 * The original rule also escalated on ZWJ, ZWNJ, BOM and U+2060–U+2064.
 * unicode.ts's header explains why that was wrong: every one of those has a
 * real, common, legitimate use. TAG characters do not, so this rule alone
 * keeps escalate-on-any-occurrence; everything else moved to
 * PANE-HIDDEN-011, where it is volume-gated instead.
 *
 * Scans text nodes, attribute values and comments, all decoded through
 * `decodeInvisibleEntities` first — that one call is what catches an
 * `&#917601;`-style reference sitting inside a `<script>` or `<style>` block,
 * which the HTML parser's raw-text content model never entity-decodes (body
 * text and attribute values, by contrast, are decoded by the parser itself,
 * so the same call is a harmless no-op there). A final whole-document pass
 * over `ctx.rawSource` is a pure fallback: it only contributes a finding when
 * the per-unit scan above found nothing at all, so it can never double-count
 * something the tree scan already caught.
 */

import { createHash } from 'node:crypto';
import type { Element } from 'domhandler';
import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding, structuralPath, excerpt } from '../shared/helpers.js';
import { allElements, locationOf } from '../../parse/html.js';
import { collapse, commentNodes, meta, nodeData, textNodes } from './common.js';
import { decodeInvisibleEntities, findTagChars } from './unicode.js';

const RULE = meta({
  id: 'PANE-HIDDEN-009',
  severity: 'HIGH',
  confidence: 'CERTAIN',
  title: 'Unicode tag characters (U+E0000–U+E007F)',
  cwe: 'CWE-838',
  remediation:
    'Remove the tag characters. They have no legitimate rendering use and exist in this ' +
    'resource only to carry a payload invisibly.',
});

function hashPath(prefix: string, text: string): string {
  return `${prefix}:${createHash('sha256').update(text).digest('hex').slice(0, 16)}`;
}

export const paneHidden009 = defineRule({
  ...RULE,
  requires: ['content'],
  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];

    const push = (
      text: string,
      count: number,
      message: string,
      path: string,
      owner?: Element,
    ) => {
      findings.push(
        makeFinding({
          ctx,
          rule: RULE,
          message: `${message} — ${count} tag character${count === 1 ? '' : 's'} found.`,
          evidence: excerpt(text),
          ...(owner ? { location: locationOf(owner) } : {}),
          path,
        }),
      );
    };

    for (const { node, owner } of textNodes(ctx.dom)) {
      const decoded = decodeInvisibleEntities(nodeData(node)).decoded;
      const found = findTagChars(decoded);
      if (found.count === 0) continue;
      const text = collapse(decoded);
      push(
        text,
        found.count,
        owner
          ? `<${owner.tagName}> carries Unicode tag characters in its text`
          : 'Document text carries Unicode tag characters',
        owner ? structuralPath(owner) : hashPath('text', text),
        owner ?? undefined,
      );
    }

    for (const el of allElements(ctx.dom)) {
      for (const [name, value] of Object.entries(el.attribs ?? {})) {
        const decoded = decodeInvisibleEntities(value).decoded;
        const found = findTagChars(decoded);
        if (found.count === 0) continue;
        push(
          collapse(decoded),
          found.count,
          `<${el.tagName} ${name}> carries Unicode tag characters in an attribute value`,
          `${structuralPath(el)}@${name.toLowerCase()}`,
          el,
        );
      }
    }

    for (const node of commentNodes(ctx.dom)) {
      const decoded = decodeInvisibleEntities(nodeData(node)).decoded;
      const found = findTagChars(decoded);
      if (found.count === 0) continue;
      const text = collapse(decoded);
      push(text, found.count, 'An HTML comment carries Unicode tag characters', hashPath('comment', text));
    }

    // Fallback only: catches bytes no tree unit reached at all. Gated on the
    // per-unit scan finding nothing, so it can never duplicate a count.
    if (findings.length === 0) {
      const decoded = decodeInvisibleEntities(ctx.rawSource).decoded;
      const found = findTagChars(decoded);
      if (found.count > 0) {
        const text = collapse(decoded).slice(0, 200);
        push(
          text,
          found.count,
          'The raw resource bytes carry Unicode tag characters not reachable through any parsed node',
          hashPath('raw-source', text),
        );
      }
    }

    return { findings };
  },
});

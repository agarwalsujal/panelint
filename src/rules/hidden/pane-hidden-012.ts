/**
 * PANE-HIDDEN-012 — text inside `srcdoc`, `<template>`, or `<noscript>`: not
 * in the initial rendered tree.
 *
 * One of the two rules docs/RULES.md credits with closing "the payload that
 * scored clean on all 45 original rules" (fixtures/malicious/hidden/fixture-zero.html).
 * Three distinct carriers, one rule, because all three share the same shape:
 * text that is genuinely present in the resource bytes and genuinely absent
 * from the tree every other rule in this family walks.
 *
 *   - `srcdoc` is an ATTRIBUTE STRING, never a parsed subtree. A naive DOM
 *     walk sees no text in it at all, because there is no text node to see —
 *     the markup only becomes a document once something parses the string.
 *     So this rule is that something: it sub-parses the (already
 *     attribute-decoded) value as its own HTML document, recursively, capped
 *     at depth 2 so a self-referential srcdoc chain cannot recurse forever.
 *   - `<template>` content lives in a document-fragment node that plain
 *     `css-select` does not descend into (src/parse/html.ts's header). Every
 *     other rule in this family calls `isNonRendered`, which treats
 *     `template` as never-rendered and skips it — correctly, for THEM. This
 *     rule is the one that goes looking on purpose.
 *   - `<noscript>` is handled at the RAW SOURCE level, by regex, rather than
 *     through the parsed tree. Measured: when a `<noscript>` is the first
 *     content the parser sees (nothing else in `<head>` or `<body>` yet), the
 *     HTML5 "in head noscript" insertion mode auto-closes it as EMPTY and
 *     reprocesses its content as an ordinary sibling — so `el.children` for
 *     that `<noscript>` is `[]` even though the source plainly has content
 *     between the tags. That is real, spec'd browser behaviour (it is how a
 *     scripting-disabled user agent ends up rendering the fallback content
 *     normally), but it means a tree walk keyed on `<noscript>`'s children
 *     silently sees nothing for exactly the documents where the tag sits at
 *     the front of the page. A raw-source regex has no insertion-mode
 *     opinion, so it is used for all three positions, not only the ones the
 *     parser happens to nest correctly.
 *
 * A closed-over recursion depth also protects the ordinary, benign use of
 * `<template>` — a client-side row template with `{{mustache}}` placeholders
 * — from ever being treated as an injection: `scaleFor`/`scaleHiddenFinding`
 * still apply, so a short non-imperative template lands below the gate on
 * volume alone.
 */

import { createHash } from 'node:crypto';
import { Element } from 'domhandler';
import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding, structuralPath, excerpt } from '../shared/helpers.js';
import { NON_RENDERED_TAGS } from '../shared/helpers.js';
import { allElements, attr, locationOf, parseHtml, type AnyNode, type Document } from '../../parse/html.js';
import { scaleHiddenFinding } from '../shared/scale.js';
import { childNodes, collapse, meta, nodeData, scaleFor } from './common.js';

const RULE = meta({
  id: 'PANE-HIDDEN-012',
  severity: 'HIGH',
  confidence: 'HIGH',
  title: 'Text inside srcdoc, <template>, or <noscript> — not in the initial rendered tree',
  cwe: 'CWE-451',
  remediation:
    'Remove the text, or, if this is a genuine client-side template, keep the placeholder ' +
    'content short and free of imperative phrasing.',
});

const MAX_SRCDOC_DEPTH = 2;

/** Text content of a sub-document, respecting the same non-rendered tags as the rest of the family. */
function textOfSubDocument(root: AnyNode | Document): string {
  let out = '';
  const walk = (node: AnyNode) => {
    if (node instanceof Element) {
      if (NON_RENDERED_TAGS.has(node.tagName.toLowerCase())) return;
    }
    if (node.type === 'text') out += nodeData(node);
    for (const c of childNodes(node)) walk(c);
  };
  for (const c of childNodes(root as AnyNode)) walk(c);
  return out;
}

function hashPath(prefix: string, text: string): string {
  return `${prefix}:${createHash('sha256').update(text).digest('hex').slice(0, 16)}`;
}

/** Non-greedy: the first matching close tag ends the block, same as a browser. */
const NOSCRIPT_BLOCK = /<noscript\b[^>]*>([\s\S]*?)<\/noscript\s*>/gi;

export const paneHidden012 = defineRule({
  ...RULE,
  requires: ['content'],
  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];

    const reportOnElement = (text: string, message: string, path: string, owner: Element) => {
      const scaled = scaleFor(owner, text, ctx.styles, RULE.severity);
      findings.push(
        makeFinding({
          ctx,
          rule: RULE,
          severity: scaled.severity,
          message: `${message} — ${scaled.rationale}.`,
          evidence: excerpt(text),
          location: locationOf(owner),
          path,
        }),
      );
    };

    const reportRaw = (text: string, message: string, path: string) => {
      const scaled = scaleHiddenFinding({ ceiling: RULE.severity, text });
      findings.push(
        makeFinding({
          ctx,
          rule: RULE,
          severity: scaled.severity,
          message: `${message} — ${scaled.rationale}.`,
          evidence: excerpt(text),
          path,
        }),
      );
    };

    const walkSrcdoc = (el: Element, html: string, depth: number, pathSuffix: string): void => {
      if (depth > MAX_SRCDOC_DEPTH) return;
      const sub = parseHtml(html, ctx.limits);
      const text = collapse(textOfSubDocument(sub.dom));
      if (text.length > 0) {
        reportOnElement(
          text,
          `<iframe srcdoc> (depth ${depth}) carries text that is never a parsed subtree of the outer document`,
          `${structuralPath(el)}${pathSuffix}`,
          el,
        );
      }
      for (const inner of allElements(sub.dom)) {
        if (inner.tagName.toLowerCase() !== 'iframe') continue;
        const nested = attr(inner, 'srcdoc');
        if (nested === undefined || nested.trim().length === 0) continue;
        walkSrcdoc(el, nested, depth + 1, `${pathSuffix}/srcdoc[${depth + 1}]`);
      }
    };

    for (const el of allElements(ctx.dom)) {
      const tag = el.tagName.toLowerCase();

      if (tag === 'template') {
        const text = collapse(textOfSubDocument(el));
        if (text.length === 0) continue;
        reportOnElement(
          text,
          `<template> content (${text.length} characters) is not part of the initial rendered tree`,
          structuralPath(el),
          el,
        );
        continue;
      }

      if (tag === 'iframe') {
        const srcdoc = attr(el, 'srcdoc');
        if (srcdoc === undefined || srcdoc.trim().length === 0) continue;
        walkSrcdoc(el, srcdoc, 1, '/srcdoc[1]');
      }
    }

    // <noscript>: raw-source regex, not the parsed tree — see the header note
    // on the "in head noscript" auto-close quirk.
    for (const match of ctx.rawSource.matchAll(NOSCRIPT_BLOCK)) {
      const inner = match[1] ?? '';
      if (!inner.trim()) continue;
      const sub = parseHtml(inner, ctx.limits);
      const text = collapse(textOfSubDocument(sub.dom));
      if (text.length === 0) continue;
      reportRaw(
        text,
        `<noscript> content (${text.length} characters) is not part of the initial rendered tree when scripting is enabled`,
        hashPath('noscript', `${match.index ?? 0}:${inner}`),
      );
    }

    return { findings };
  },
});

/**
 * HTML → DOM.
 *
 * parse5 with the **htmlparser2 tree adapter**, not the default one. Rules need
 * selector matching, css-select operates on a domhandler-shaped tree, and this
 * adapter preserves both parse5's `sourceCodeLocation` (line/column/offset,
 * including per-attribute) and domhandler's `startIndex`/`endIndex` — so one
 * tree serves selector matching and SARIF provenance.
 *
 * No jsdom. We need a tree, not a runtime.
 */

import { parse } from 'parse5';
import { adapter } from 'parse5-htmlparser2-tree-adapter';
import { selectAll as cssSelectAll, selectOne as cssSelectOne } from 'css-select';
import { textContent } from 'domutils';
import { Element, type Document, type AnyNode } from 'domhandler';
import { checkLimit } from '../limits.js';
import type { Limits, ScanDiagnostic, SourceLocation } from '../types.js';

export interface ParsedHtml {
  dom: Document;
  diagnostics: ScanDiagnostic[];
  nodeCount: number;
  maxDepth: number;
}

/**
 * Parse a resource's HTML.
 *
 * This never throws on malformed markup, because the HTML5 parsing algorithm
 * has no failure mode — every byte sequence is a valid document. That fact is
 * why PANE-SPEC-004 could not be "content parses as an HTML5 document": the
 * rule as originally written could not fire.
 */
export function parseHtml(html: string, limits: Limits, resourceUri?: string): ParsedHtml {
  const diagnostics: ScanDiagnostic[] = [];

  const dom = parse(html, {
    treeAdapter: adapter,
    sourceCodeLocationInfo: true,
    scriptingEnabled: false,
  }) as unknown as Document;

  let nodeCount = 0;
  let maxDepth = 0;
  walkElements(dom, (_el, depth) => {
    nodeCount++;
    if (depth > maxDepth) maxDepth = depth;
  });

  const nodeDiag = checkLimit('maxDomNodes', nodeCount, limits, resourceUri);
  if (nodeDiag) diagnostics.push(nodeDiag);
  const depthDiag = checkLimit('maxNestingDepth', maxDepth, limits, resourceUri);
  if (depthDiag) diagnostics.push(depthDiag);

  return { dom, diagnostics, nodeCount, maxDepth };
}

/**
 * `<template>` content is a separate document fragment.
 *
 * Under the htmlparser2 tree adapter it is NOT exposed as `element.content`
 * (that is the parse5 default-tree shape). It arrives as a child node of type
 * `root` hanging off the `<template>` element. css-select does not descend
 * through that node, so a plain `selectAll` finds nothing inside a template —
 * and a walker that misses template content misses a one-line evasion of the
 * entire PANE-HIDDEN family (PANE-HIDDEN-012).
 *
 * Everything in this module descends into templates deliberately.
 */
function childrenOf(node: AnyNode): AnyNode[] {
  return (node as { children?: AnyNode[] }).children ?? [];
}

/** The document-fragment nodes holding a `<template>`'s content. */
function templateFragments(el: Element): AnyNode[] {
  if (el.tagName !== 'template') return [];
  return childrenOf(el).filter((c) => c.type === 'root');
}

/** Depth-first walk over every Element, including inside `<template>`. */
export function walkElements(
  root: AnyNode | Document,
  visit: (el: Element, depth: number) => void | false,
): void {
  const stack: Array<{ node: AnyNode; depth: number }> = [];
  for (const c of childrenOf(root as AnyNode)) stack.push({ node: c, depth: 1 });

  while (stack.length) {
    const { node, depth } = stack.pop()!;
    if (node instanceof Element) {
      if (visit(node, depth) === false) continue;
    }
    const kids = childrenOf(node);
    for (let i = kids.length - 1; i >= 0; i--) {
      stack.push({ node: kids[i]!, depth: depth + 1 });
    }
  }
}

/** Every Element in the tree, template content included. */
export function allElements(root: AnyNode | Document): Element[] {
  const out: Element[] = [];
  walkElements(root, (el) => {
    out.push(el);
  });
  return out;
}

/**
 * Selector matching.
 *
 * css-select does not descend into `<template>` content on its own, so template
 * fragments are queried separately and the results concatenated. Order follows
 * document order closely enough for reporting; rules must not depend on it.
 */
export function selectAll(selector: string, root: AnyNode | Document): Element[] {
  const direct = cssSelectAll(selector, root as AnyNode) as Element[];
  const templates = allElements(root).filter((e) => e.tagName === 'template');
  if (templates.length === 0) return direct;

  const seen = new Set<Element>(direct);
  const out = [...direct];
  for (const t of templates) {
    for (const fragment of templateFragments(t)) {
      for (const hit of cssSelectAll(selector, fragment) as Element[]) {
        if (!seen.has(hit)) {
          seen.add(hit);
          out.push(hit);
        }
      }
    }
  }
  return out;
}

export function selectOne(selector: string, root: AnyNode | Document): Element | null {
  const direct = cssSelectOne(selector, root as AnyNode) as Element | null;
  if (direct) return direct;
  return selectAll(selector, root)[0] ?? null;
}

/**
 * Concatenated text of an element, template content included.
 *
 * domutils' `textContent` already recurses through the fragment node the
 * adapter uses for template content, so no special case is needed here.
 */
export function textOf(node: AnyNode): string {
  return textContent(node);
}

/** parse5 location → the shape SARIF and the text reporter consume. */
export function locationOf(el: Element): SourceLocation | undefined {
  const loc = el.sourceCodeLocation;
  if (!loc) return undefined;
  return {
    startLine: loc.startLine,
    startCol: loc.startCol,
    endLine: loc.endLine,
    endCol: loc.endCol,
    startOffset: loc.startOffset,
    endOffset: loc.endOffset,
  };
}

/**
 * Per-attribute source locations.
 *
 * parse5 populates these under `sourceCodeLocation.attrs`, but the htmlparser2
 * adapter's `TagSourceCodeLocation` type does not declare the field. The data is
 * present — verified in test/parse.test.ts — so this is the one place the cast
 * lives, rather than at each of the four call sites.
 */
export interface AttrLocation {
  startLine: number;
  startCol: number;
  endLine: number;
  endCol: number;
  startOffset: number;
  endOffset: number;
}

export function attrLocations(el: Element): Record<string, AttrLocation> | undefined {
  const loc = el.sourceCodeLocation as unknown as
    | { attrs?: Record<string, AttrLocation> }
    | undefined;
  return loc?.attrs;
}

/** Location of one attribute, for findings that are about an attribute value. */
export function attrLocationOf(el: Element, attr: string): SourceLocation | undefined {
  const a = attrLocations(el)?.[attr.toLowerCase()];
  if (!a) return locationOf(el);
  return {
    startLine: a.startLine,
    startCol: a.startCol,
    endLine: a.endLine,
    endCol: a.endCol,
    startOffset: a.startOffset,
    endOffset: a.endOffset,
  };
}

/** Case-insensitive attribute read. HTML attribute names are ASCII-insensitive. */
export function attr(el: Element, name: string): string | undefined {
  const attrs = el.attribs ?? {};
  const direct = attrs[name];
  if (direct !== undefined) return direct;
  const lower = name.toLowerCase();
  for (const [k, v] of Object.entries(attrs)) {
    if (k.toLowerCase() === lower) return v;
  }
  return undefined;
}

export function hasAttr(el: Element, name: string): boolean {
  return attr(el, name) !== undefined;
}

/** Ancestors nearest-first. Used by rules that ask "is this inside an X?". */
export function ancestors(el: Element): Element[] {
  const out: Element[] = [];
  let p = el.parent as AnyNode | null;
  while (p) {
    if (p instanceof Element) out.push(p);
    p = (p as { parent?: AnyNode | null }).parent ?? null;
  }
  return out;
}

export { Element };
export type { Document, AnyNode };

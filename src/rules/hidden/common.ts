/**
 * Predicates shared by PANE-HIDDEN and PANE-OVERLAY.
 *
 * Two constraints govern everything in this file, and both are architectural
 * rather than stylistic:
 *
 * 1. **Declared CSS is read through `candidatesFor`, never `declaredStyle`.**
 *    Resolution is additive-only (parse/style-index.ts): a declaration that LOST
 *    the cascade still counts as a carrier, because `@layer` inverts the
 *    precedence the resolver sorts by. A winner-only read would hand an attacker
 *    a one-line evasion of this entire family, and per SECURITY.md §1 a targeted
 *    evasion is a reportable vulnerability in Panelint, not a limitation.
 *    The one exception is reading a property *name* — `declaredPropNames` — which
 *    is unaffected, because a property appears in the winner map if and only if
 *    at least one candidate declared it.
 *
 * 2. **No rule here may claim CERTAIN.** Panelint does not compute styles.
 *    PANE-HIDDEN-009 is the only CERTAIN rule in the family, and it reads code
 *    points, not CSS.
 */

import { Element, type AnyNode } from 'domhandler';
import type { RuleContext, RuleMeta, Severity, StyleIndexLike } from '../../types.js';
import { NON_RENDERED_TAGS } from '../shared/helpers.js';
import { declaredPropNames } from '../shared/carriers.js';
import { scaleHiddenFinding, hasImperativePhrasing, type ScaleResult } from '../shared/scale.js';
import { attr, ancestors, allElements } from '../../parse/html.js';

// ---------------------------------------------------------------------------
// Tree access
// ---------------------------------------------------------------------------

export function childNodes(node: AnyNode): AnyNode[] {
  return (node as { children?: AnyNode[] }).children ?? [];
}

export function nodeData(node: AnyNode): string {
  return (node as unknown as { data?: string }).data ?? '';
}

/**
 * Text an element contributes to the rendered page.
 *
 * Skips subtrees that never render — `<script>`, `<style>`, `<template>`,
 * `<noscript>` and friends. Template and noscript content is PANE-HIDDEN-012's
 * subject, and counting it here would report the same bytes twice under two
 * different theories.
 */
export function renderedText(el: Element): string {
  let out = '';
  const walk = (node: AnyNode) => {
    if (node instanceof Element) {
      if (NON_RENDERED_TAGS.has(node.tagName.toLowerCase())) return;
    }
    if (node.type === 'text') out += nodeData(node);
    for (const c of childNodes(node)) walk(c);
  };
  for (const c of childNodes(el)) walk(c);
  return out;
}

export function collapse(text: string): string {
  return text.replace(/\s+/g, ' ').trim();
}

/** True when this element, or an ancestor, never renders its text. */
export function isNonRendered(el: Element): boolean {
  if (NON_RENDERED_TAGS.has(el.tagName.toLowerCase())) return true;
  return ancestors(el).some((a) => NON_RENDERED_TAGS.has(a.tagName.toLowerCase()));
}

/** Every text node in the document, with the element that contains it. */
export function textNodes(root: AnyNode): Array<{ node: AnyNode; owner: Element | null }> {
  const out: Array<{ node: AnyNode; owner: Element | null }> = [];
  const walk = (node: AnyNode, owner: Element | null) => {
    if (node.type === 'text') out.push({ node, owner });
    const nextOwner = node instanceof Element ? node : owner;
    for (const c of childNodes(node)) walk(c, nextOwner);
  };
  walk(root, null);
  return out;
}

/** Every comment node in the document, template content included. */
export function commentNodes(root: AnyNode): AnyNode[] {
  const out: AnyNode[] = [];
  const walk = (node: AnyNode) => {
    if (node.type === 'comment') out.push(node);
    for (const c of childNodes(node)) walk(c);
  };
  walk(root);
  return out;
}

// ---------------------------------------------------------------------------
// Severity scaling
// ---------------------------------------------------------------------------

const ORDER: Severity[] = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

export function atMost(severity: Severity, ceiling: Severity): Severity {
  return ORDER.indexOf(severity) > ORDER.indexOf(ceiling) ? ceiling : severity;
}

/**
 * class + id + role + the accessibility attributes, for scale.ts.
 *
 * scale.ts looks for an accessibility-shaped class name here. Including `role`
 * and `aria-label` means `<span role="status" class="live">` reads the same way
 * a `.sr-only` class does, which is the intent rather than an accident.
 */
export function signatureOf(el: Element): string {
  return [
    attr(el, 'class') ?? '',
    attr(el, 'id') ?? '',
    attr(el, 'role') ?? '',
    attr(el, 'aria-live') ?? '',
  ]
    .filter(Boolean)
    .join(' ');
}

/**
 * Scale one hidden-text finding by volume and shape.
 *
 * Every text-hiding rule in this family routes through here. Presence alone is
 * never the signal — `sr-only` accessibility text and SEO copy are structurally
 * identical to an injection carrier, and only volume and shape tell them apart
 * (docs/RULES.md § False-positive control).
 */
export function scaleFor(
  el: Element,
  text: string,
  styles: StyleIndexLike,
  ceiling: Severity,
): ScaleResult {
  return scaleHiddenFinding({
    ceiling,
    text,
    classNames: signatureOf(el),
    declaredProps: declaredPropNames(el, styles),
  });
}

// ---------------------------------------------------------------------------
// Disclosure widgets
// ---------------------------------------------------------------------------

/**
 * Roles and class names of a UI element that is *supposed* to start hidden.
 *
 * Tab panels, dropdowns, modals and accordions are the dominant legitimate use
 * of `display:none`, and they are hidden at rest by design. They are demoted,
 * never suppressed: the demotion costs gate-eligibility and nothing else, and a
 * suppression keyed on a class name would be a one-attribute evasion.
 */
const WIDGET_ROLES = new Set([
  'tabpanel', 'dialog', 'alertdialog', 'menu', 'menubar', 'listbox', 'tooltip',
  'combobox', 'tree', 'treegrid', 'status', 'alert', 'log',
]);

const WIDGET_CLASS =
  /\b(tab|tabs|tabpanel|tab-panel|panel|dropdown|drop-down|modal|dialog|popover|popup|menu|submenu|flyout|accordion|collaps\w*|offcanvas|off-canvas|drawer|toast|tooltip|carousel|slide\w*|step|wizard|backdrop|overlay|sheet|disclosure)\b/i;

/** Attributes that mark a node as the hidden half of a disclosure widget. */
const WIDGET_ATTRS = [
  'aria-expanded', 'aria-controls', 'aria-labelledby', 'aria-modal',
  'data-toggle', 'data-tab', 'data-panel', 'data-state', 'data-collapse',
  'x-show', 'x-cloak', 'v-if', 'v-show', 'ng-if', 'ng-show', '*ngif',
];

export function widgetShaped(el: Element): boolean {
  const role = (attr(el, 'role') ?? '').toLowerCase();
  if (WIDGET_ROLES.has(role)) return true;
  if (el.tagName.toLowerCase() === 'details' || el.tagName.toLowerCase() === 'dialog') return true;
  if (WIDGET_CLASS.test(`${attr(el, 'class') ?? ''} ${attr(el, 'id') ?? ''}`)) return true;
  return WIDGET_ATTRS.some((a) => attr(el, a) !== undefined);
}

/**
 * Demote a widget-shaped node, unless the text is instruction-shaped.
 *
 * Shape beats volume in both directions. A tab panel holding 400 characters of
 * product copy is LOW; a tab panel holding "SYSTEM: ignore prior instructions"
 * keeps whatever severity scale.ts assigned it, because a class name is not
 * evidence about the text inside.
 */
export function demoteIfWidget(el: Element, text: string, scaled: ScaleResult): ScaleResult {
  if (!widgetShaped(el)) return scaled;
  if (hasImperativePhrasing(text)) return scaled;
  return {
    severity: atMost(scaled.severity, 'LOW'),
    rationale: `${scaled.rationale}; node is shaped like a disclosure widget hidden at rest`,
  };
}

// ---------------------------------------------------------------------------
// Declared-value helpers — all additive
// ---------------------------------------------------------------------------

/** Every declared value of `prop` on this node, winner or not. */
export function valuesOf(el: Element, styles: StyleIndexLike, prop: string): string[] {
  return styles.candidatesFor(el, prop).map((d) => d.value.trim().toLowerCase());
}

export function hasValue(
  el: Element,
  styles: StyleIndexLike,
  prop: string,
  test: (v: string) => boolean,
): boolean {
  return valuesOf(el, styles, prop).some(test);
}

export function firstNumber(value: string): number | null {
  const m = /^-?[\d.]+/.exec(value.trim());
  if (!m) return null;
  const n = Number(m[0]);
  return Number.isFinite(n) ? n : null;
}

/**
 * Does this node declare a transition or animation?
 *
 * The signal that a hidden state is a transition start rather than a resting
 * state. scale.ts consumes the same set for text-bearing rules; PANE-OVERLAY-002
 * needs it directly because it deliberately fires on nodes with no text and
 * scale.ts short-circuits those to INFO.
 */
export function declaresAnimation(el: Element, styles: StyleIndexLike): boolean {
  for (const p of ['transition', 'transition-property', 'animation', 'animation-name']) {
    if (styles.candidatesFor(el, p).length > 0) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Interactivity and geometry — shared with PANE-OVERLAY
// ---------------------------------------------------------------------------

const INTERACTIVE_TAGS = new Set(['a', 'button', 'input', 'select', 'textarea', 'summary', 'label', 'option']);
const INTERACTIVE_ROLES = new Set(['button', 'link', 'checkbox', 'radio', 'switch', 'menuitem', 'tab', 'option', 'textbox', 'slider']);

export function isInteractive(el: Element): boolean {
  const tag = el.tagName.toLowerCase();
  if (tag === 'a') return attr(el, 'href') !== undefined;
  if (INTERACTIVE_TAGS.has(tag)) return true;
  if (INTERACTIVE_ROLES.has((attr(el, 'role') ?? '').toLowerCase())) return true;
  if (attr(el, 'tabindex') !== undefined) return true;
  if (attr(el, 'contenteditable') !== undefined) return true;
  return Object.keys(el.attribs ?? {}).some((k) => /^on(click|mousedown|mouseup|pointerdown|pointerup|touchstart|submit)$/i.test(k));
}

/** This element or any descendant, template content included. */
export function containsInteractive(el: Element): boolean {
  if (isInteractive(el)) return true;
  return allElements(el).some(isInteractive);
}

/** Attribute-borne pointer handlers on the element itself. */
export function hasPointerHandler(el: Element): boolean {
  return Object.keys(el.attribs ?? {}).some((k) =>
    /^on(click|mousedown|mouseup|mouseover|pointerdown|pointerup|touchstart|touchend)$/i.test(k),
  );
}

const FILLING_LENGTH = /^(0(px|%|em|rem|vh|vw)?|100%|100vh|100vw|100dvh|100dvw|-?\d+px)$/;

function zeroOrNegative(v: string): boolean {
  const n = firstNumber(v);
  return n !== null && n <= 0;
}

/**
 * Does declared CSS make this element cover the viewport?
 *
 * Necessary but nowhere near sufficient for PANE-OVERLAY-001 — a modal
 * confirmation dialog and a fullscreen container have exactly this geometry.
 * The second signal is what makes the rule shippable.
 */
export function fillsViewport(el: Element, styles: StyleIndexLike): boolean {
  const positioned = hasValue(el, styles, 'position', (v) => v === 'fixed' || v === 'absolute');
  if (!positioned) return false;

  if (hasValue(el, styles, 'inset', (v) => /^0(px|%)?( 0(px|%)?)*$/.test(v))) return true;

  const sides = ['top', 'left', 'right', 'bottom'];
  if (sides.every((s) => hasValue(el, styles, s, zeroOrNegative))) return true;

  const wide = hasValue(el, styles, 'width', (v) => v === '100%' || v === '100vw' || v === '100dvw');
  const tall = hasValue(el, styles, 'height', (v) => v === '100%' || v === '100vh' || v === '100dvh');
  if (wide && tall) return true;

  return false;
}

/** Keeps `FILLING_LENGTH` referenced for future geometry work without widening it now. */
export function isFillingLength(v: string): boolean {
  return FILLING_LENGTH.test(v.trim().toLowerCase());
}

/**
 * The largest positive declared `z-index`, or null.
 *
 * **A missing `z-index` is `auto`, never elevated.** threejs-server's
 * `.error-overlay` fills the viewport with no `z-index` declared at all, and
 * treating absent as elevated reacquires the measured false positive through
 * the back door. `auto` and negative values are equally not elevated.
 *
 * Read through `candidatesFor` so a value declared inside an unmodelled
 * `@layer` still counts.
 */
export function elevatedZIndex(el: Element, styles: StyleIndexLike): number | null {
  let best: number | null = null;
  for (const v of valuesOf(el, styles, 'z-index')) {
    if (v === 'auto' || v === '') continue;
    const n = firstNumber(v);
    if (n === null || n <= 0) continue;
    if (best === null || n > best) best = n;
  }
  return best;
}

// ---------------------------------------------------------------------------
// Rule metadata boilerplate
// ---------------------------------------------------------------------------

export function meta(
  m: Omit<RuleMeta, 'experimental' | 'status' | 'since' | 'ruleClass'> & Partial<RuleMeta>,
): RuleMeta {
  return {
    ruleClass: 'RISK',
    experimental: false,
    status: 'active',
    since: '0.1.0',
    ...m,
  } as RuleMeta;
}

/** Every rule in these two families needs the resource body and nothing else. */
export const REQUIRES_CONTENT = ['content'] as const;

export function noFindings(): { findings: [] } {
  return { findings: [] };
}

/** Panelint never says a server is malicious — only what the bytes contain. */
export function carrierMessage(what: string, rationale: string): string {
  return `${what}; ${rationale}.`;
}

export type { RuleContext };

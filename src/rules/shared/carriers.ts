/**
 * Hidden-content carrier detection, shared across families.
 *
 * PANE-HIDDEN owns these predicates, but PANE-INPUT-001 (credential field
 * hidden by any carrier), PANE-MIMIC-005, and PANE-OVERLAY all compose with
 * them. One implementation means "hidden" means the same thing everywhere, and
 * that a carrier added for one family is immediately seen by the others.
 *
 * Every predicate reads DECLARED CSS. Panelint does not compute styles, so
 * nothing here may claim CERTAIN confidence — see docs/RULES.md § Classification.
 *
 * All lookups go through `candidatesFor`, never `declaredStyle`. Resolution is
 * additive-only: a declaration that LOST the cascade still counts as a carrier,
 * because @layer inverts the precedence the resolver sorts by and a
 * winner-only read would hand an attacker a one-line evasion of the family.
 */

import { Element } from 'domhandler';
import type { DeclaredValue, StyleIndexLike } from '../../types.js';
import { attr } from '../../parse/html.js';
import { hasSubstitution, resolveDeclaredValues } from '../../parse/css-values.js';

export type CarrierKind =
  | 'display-none'
  | 'visibility-hidden'
  | 'opacity-zero'
  | 'font-size-zero'
  | 'offscreen'
  | 'clipped'
  | 'aria-hidden'
  | 'hidden-attr'
  | 'inert'
  | 'content-visibility'
  | 'text-indent'
  | 'transform-collapsed'
  | 'zero-size'
  | 'filter-opacity'
  | 'color-transparent'
  | 'details-closed';

export interface Carrier {
  kind: CarrierKind;
  /** The declaration or attribute that produced it, for evidence. */
  evidence: string;
  /** True when the carrier came from a declaration that lost the cascade. */
  losing?: boolean;
}

const NEAR_ZERO = 0.05;

function numeric(v: string): number | null {
  const m = /^-?[\d.]+/.exec(v.trim());
  if (!m) return null;
  const n = Number(m[0]);
  return Number.isFinite(n) ? n : null;
}

/** Is this length effectively zero or sub-pixel? */
function isZeroish(v: string): boolean {
  const t = v.trim().toLowerCase();
  if (t === '0') return true;
  const n = numeric(t);
  if (n === null) return false;
  if (/px$/.test(t)) return n < 1;
  if (/(em|rem)$/.test(t)) return n < 0.06;
  if (/%$/.test(t)) return n < 1;
  return n === 0;
}

/**
 * Every declared-CSS and attribute carrier applying to a node.
 *
 * Returns all of them rather than the first, so a caller can report the set and
 * so the dedup pass can collapse the `.sr-only` recipe — which trips offscreen,
 * clipped, and zero-size simultaneously — into one finding.
 */
export function carriersOn(el: Element, styles: StyleIndexLike): Carrier[] {
  const out: Carrier[] = [];

  // Every candidate is resolved before it is compared to a literal, so a value
  // written as `var(--o)` is read as what it substitutes to. A candidate that
  // cannot be reduced is DROPPED from the comparison and reported separately by
  // `unevaluableProps` — never silently treated as a value that fails to match.
  const all = (prop: string): DeclaredValue[] => {
    const out: DeclaredValue[] = [];
    for (const d of styles.candidatesFor(el, prop)) {
      if (!hasSubstitution(d.value)) {
        out.push(d);
        continue;
      }
      // EVERY value the property could take, expanded into its own candidate.
      // Collapsing to one re-created the `@layer`, `!important` and specificity
      // evasions this module's additive-only posture exists to prevent.
      const resolved = resolveDeclaredValues(el, styles, d.value);
      // Unresolvable values pass through as written. They match no literal, so
      // they raise no carrier — which is why `unevaluableProps` exists to say
      // so out loud rather than letting the absence stand unexplained.
      if (resolved.length === 0) out.push(d);
      else for (const v of resolved) out.push({ ...d, value: v });
    }
    return out;
  };
  const push = (kind: CarrierKind, evidence: string, losing?: boolean) => {
    out.push({ kind, evidence, ...(losing ? { losing: true } : {}) });
  };

  for (const d of all('display')) {
    if (d.value.trim().toLowerCase() === 'none') push('display-none', `display:${d.value}`);
  }
  for (const d of all('visibility')) {
    const v = d.value.trim().toLowerCase();
    if (v === 'hidden' || v === 'collapse') push('visibility-hidden', `visibility:${d.value}`);
  }
  for (const d of all('opacity')) {
    const n = numeric(d.value);
    if (n !== null && n <= NEAR_ZERO) push('opacity-zero', `opacity:${d.value}`);
  }
  for (const d of all('font-size')) {
    if (isZeroish(d.value)) push('font-size-zero', `font-size:${d.value}`);
  }
  for (const prop of ['left', 'top', 'right', 'bottom', 'margin-left', 'margin-top', 'text-indent']) {
    for (const d of all(prop)) {
      const n = numeric(d.value);
      if (n !== null && n <= -1000) {
        push(prop === 'text-indent' ? 'text-indent' : 'offscreen', `${prop}:${d.value}`);
      }
    }
  }
  for (const d of all('clip-path')) {
    const v = d.value.trim().toLowerCase();
    if (v.includes('inset(100%') || v === 'circle(0)' || v.includes('polygon(0px 0px, 0px 0px')) {
      push('clipped', `clip-path:${d.value}`);
    }
  }
  for (const d of all('clip')) {
    if (/rect\(\s*0[a-z%]*[\s,]+0/.test(d.value)) push('clipped', `clip:${d.value}`);
  }
  for (const d of all('content-visibility')) {
    if (d.value.trim().toLowerCase() === 'hidden') push('content-visibility', `content-visibility:${d.value}`);
  }
  for (const d of all('filter')) {
    if (/opacity\(\s*0*(\.0+)?\s*\)/.test(d.value)) push('filter-opacity', `filter:${d.value}`);
  }
  for (const d of all('color')) {
    if (d.value.trim().toLowerCase() === 'transparent') push('color-transparent', `color:${d.value}`);
  }
  for (const d of all('-webkit-text-fill-color')) {
    if (d.value.trim().toLowerCase() === 'transparent') {
      push('color-transparent', `-webkit-text-fill-color:${d.value}`);
    }
  }
  for (const d of all('transform')) {
    const v = d.value.replace(/\s+/g, '').toLowerCase();
    if (/scale\(0[,)]/.test(v) || /scale\(0\.0*[,)]/.test(v) || /translate[xy]?\(-?\d{4,}/.test(v)) {
      push('transform-collapsed', `transform:${d.value}`);
    }
  }

  // Zero-size only counts as a carrier alongside overflow:hidden — a 0-height
  // element without it still paints its overflowing text.
  const widths = all('width');
  const heights = all('height');
  const overflowHidden = all('overflow').some((d) =>
    ['hidden', 'clip'].includes(d.value.trim().toLowerCase()),
  );
  if (overflowHidden && (widths.some((d) => isZeroish(d.value)) || heights.some((d) => isZeroish(d.value)))) {
    push('zero-size', 'width/height ~0 with overflow:hidden');
  }

  // Attribute-borne carriers. These are structural facts, not declared CSS.
  if (attr(el, 'hidden') !== undefined) push('hidden-attr', 'hidden attribute');
  if (attr(el, 'inert') !== undefined) push('inert', 'inert attribute');
  if ((attr(el, 'aria-hidden') ?? '').toLowerCase() === 'true') push('aria-hidden', 'aria-hidden="true"');
  if (el.tagName === 'details' && attr(el, 'open') === undefined) {
    push('details-closed', '<details> without open');
  }

  return out;
}

/** Convenience: is this node concealed by anything at all? */
export function isConcealed(el: Element, styles: StyleIndexLike): boolean {
  return carriersOn(el, styles).length > 0;
}

/** Property names that produced a carrier, for the animation check in scale.ts. */
export function declaredPropNames(el: Element, styles: StyleIndexLike): string[] {
  return [...styles.declaredStyle(el).keys()];
}

/**
 * Properties whose declared value could not be reduced to a literal.
 *
 * `carriersOn` drops these rather than comparing a `calc(…)` string to `none`
 * and concluding the node is visible. Dropping them silently would be the same
 * bug in a new place, so this reports them and the caller marks the node
 * undecided: the cascade said something about this property and we could not
 * read it, which is not the same as it saying nothing.
 */
export function unevaluableProps(el: Element, styles: StyleIndexLike): string[] {
  const out: string[] = [];
  for (const prop of CARRIER_PROPS) {
    for (const d of styles.candidatesFor(el, prop)) {
      if (!hasSubstitution(d.value)) continue;
      if (resolveDeclaredValues(el, styles, d.value).length > 0) continue;
      out.push(`${prop}:${d.value.trim()}`);
      break;
    }
  }
  return out;
}

/** Every property the carriers above read, for the unevaluable sweep. */
const CARRIER_PROPS = [
  'display', 'visibility', 'opacity', 'font-size', 'left', 'top', 'right', 'bottom',
  'margin-left', 'margin-top', 'text-indent', 'clip', 'clip-path', 'transform', 'filter',
  'color', '-webkit-text-fill-color', 'width', 'height', 'overflow', 'content-visibility',
] as const;

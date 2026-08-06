/**
 * Volume-and-shape severity scaling.
 *
 * This is the entire false-positive control for the PANE-HIDDEN family, and it
 * is why those rules are shippable at all. `sr-only` accessibility text and SEO
 * copy are legitimate, common, and structurally identical to an injection
 * carrier. The difference is not presence — it is volume and shape.
 *
 * From docs/RULES.md § False-positive control:
 *   - Under 100 characters with an accessibility-shaped class name → INFO,
 *     suppressed by default
 *   - Over 500 characters, or containing imperative second-person phrasing →
 *     escalate
 *
 * Severity is therefore a property of the FINDING, not only of the rule
 * (DESIGN.md §5). A rule declares its ceiling; this function decides where a
 * given instance lands under it.
 */

import type { Severity } from '../../types.js';

/** Class and attribute names that mark deliberate screen-reader-only content. */
const ACCESSIBILITY_SHAPED = /\b(sr-only|visually-?hidden|screen-?reader|a11y-only|assistive)\b/i;

/**
 * Second-person imperative phrasing, the shape of an instruction aimed at a
 * model rather than prose aimed at a person.
 *
 * Deliberately narrow. "You can filter this table" is ordinary UI copy; the
 * signal is an instruction directed at an assistant about what to do next.
 */
const IMPERATIVE_PHRASING = new RegExp(
  [
    '\\b(ignore|disregard|forget)\\b[^.]{0,40}\\b(previous|prior|above|earlier|all)\\b',
    '\\byou (must|should|will|are to|need to)\\b',
    '\\b(system|assistant|user)\\s*:',
    '\\bbefore (answering|responding|replying)\\b',
    '\\b(do not|don\'t) (tell|mention|reveal|show|inform)\\b',
    '\\bnew instructions?\\b',
    '\\byour (instructions|rules|system prompt)\\b',
    '\\b(call|invoke|run|execute) the \\w+ tool\\b',
  ].join('|'),
  'i',
);

/** Animation properties that make a transient `opacity:0` the resting state. */
const ANIMATION_PROPS = ['transition', 'transition-property', 'animation', 'animation-name'];

/**
 * Below this, hidden text is a UI label rather than a payload.
 *
 * Calibrated against the reference corpus: the longest legitimate hidden string
 * observed was a 50-character PDF toolbar. Imperative phrasing bypasses this
 * band entirely, so raising it does not blind the family to short attacks.
 */
const LOW_VOLUME_CHARS = 120;

export interface ScaleInput {
  /** The rule's declared severity — the ceiling this instance cannot exceed. */
  ceiling: Severity;
  /** The text the carrier conceals. */
  text: string;
  /** class + id + any accessibility-signalling attribute values on the node. */
  classNames?: string;
  /**
   * Declarations on the node that indicate the hidden state is a transition
   * start rather than a resting state. `.x{opacity:0;transition:opacity .3s}`
   * with `.x.visible{opacity:1}` is the most common fade-in idiom in modern UI,
   * and it is not an injection carrier.
   */
  declaredProps?: Iterable<string>;
}

export interface ScaleResult {
  severity: Severity;
  /** Why this instance landed where it did — goes into the finding message. */
  rationale: string;
}

const ORDER: Severity[] = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

function cap(s: Severity, ceiling: Severity): Severity {
  return ORDER.indexOf(s) > ORDER.indexOf(ceiling) ? ceiling : s;
}

/**
 * Scale one hidden-content finding.
 *
 * Demotion, never suppression. A fade-in still produces a finding — it is just
 * not one worth breaking a build over. That distinction matters because the
 * cascade resolver is additive-only (see parse/style-index.ts): suppressing on
 * the presence of a `transition` declaration would hand an attacker a one-line
 * evasion, while demoting costs only gate-eligibility.
 */
export function scaleHiddenFinding(input: ScaleInput): ScaleResult {
  const text = input.text.replace(/\s+/g, ' ').trim();
  const len = text.length;
  const looksAccessible = ACCESSIBILITY_SHAPED.test(input.classNames ?? '');
  const imperative = IMPERATIVE_PHRASING.test(text);

  const props = new Set(Array.from(input.declaredProps ?? []).map((p) => p.toLowerCase()));
  const animated = ANIMATION_PROPS.some((p) => props.has(p));

  if (len === 0) {
    return { severity: 'INFO', rationale: 'carrier conceals no text' };
  }

  if (imperative) {
    // Shape beats volume. A 40-character "SYSTEM: ignore prior instructions" is
    // the payload this family exists to find.
    return {
      severity: cap('HIGH', input.ceiling),
      rationale: `hidden text contains imperative second-person phrasing (${len} chars)`,
    };
  }

  if (animated) {
    return {
      severity: cap('LOW', input.ceiling),
      rationale: 'node declares a transition or animation on the hiding property — likely a fade-in',
    };
  }

  if (looksAccessible && len < 100) {
    return {
      severity: 'INFO',
      rationale: `accessibility-shaped class name and only ${len} chars of text`,
    };
  }

  // Low volume, no instruction shape.
  //
  // MEASURED against the real ext-apps reference corpus: without this band the
  // rule fired MEDIUM on "⚠️ An error occurred" (pdf-server), "Error loading
  // video" (video-resource-server) and "▲ ▼ ✕" — five characters of button
  // glyphs. Every one is an ordinary panel hidden by default, and at
  // `--fail-on medium` they would break a build against the specification's own
  // example servers.
  //
  // The principle is the family's stated one: severity scales with VOLUME and
  // SHAPE, not presence. Fifty characters is not volume, and an injection that
  // redirects a model needs room to say something. Imperative phrasing is
  // handled above and still escalates at any length, so the short payload
  // "SYSTEM: ignore all prior instructions" is unaffected by this band.
  if (len < LOW_VOLUME_CHARS) {
    return {
      severity: cap('LOW', input.ceiling),
      rationale: `only ${len} chars of hidden text, with no instruction-shaped phrasing`,
    };
  }

  if (len > 500) {
    return {
      severity: cap('HIGH', input.ceiling),
      rationale: `${len} chars of hidden text`,
    };
  }

  if (looksAccessible) {
    return {
      severity: cap('LOW', input.ceiling),
      rationale: `accessibility-shaped class name, but ${len} chars of hidden text`,
    };
  }

  return { severity: cap('MEDIUM', input.ceiling), rationale: `${len} chars of hidden text` };
}

/** Exposed so PANE-MIMIC-008 and PANE-OVERLAY-001 can reuse the same signal. */
export function hasImperativePhrasing(text: string): boolean {
  return IMPERATIVE_PHRASING.test(text);
}

export function isAccessibilityShaped(classNames: string): boolean {
  return ACCESSIBILITY_SHAPED.test(classNames);
}

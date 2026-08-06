/**
 * Invisible-code-point scanning, shared by PANE-HIDDEN-009 and -011.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * The split between the two rules is the correction that made them shippable.
 *
 * The original `-009` escalated on any of U+200B–200D, U+FEFF and the tag
 * characters. That was factually wrong about three of them:
 *
 *   - **U+200D (ZWJ) is required** in emoji sequences (👩‍💻, family emoji, the
 *     rainbow flag) and in Indic conjuncts.
 *   - **U+200C (ZWNJ) is required** in Persian, Hindi and Malayalam.
 *   - **U+FEFF is a legitimate leading BOM.**
 *
 * As written, the rule fired HIGH on every internationalized or emoji-using app.
 *
 * `-009` now covers only the characters with genuinely no rendering use —
 * Unicode TAG characters U+E0000–U+E007F — and keeps escalate-on-any-occurrence.
 * Everything else, **including U+2060–U+2064** (WORD JOINER has legitimate
 * line-break-control use and U+2064 appears in math markup), moves to `-011` and
 * is volume-gated.
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Both rules scan text nodes, `<script>` text, attribute values **and the raw
 * source bytes** — `&#8203;` inside a `<script>` element is never entity-decoded
 * by the parser, so a tree-only scan misses it, while `&#8203;` in body text is
 * decoded away from a raw-source regex. Neither scan alone is sufficient.
 */

export const TAG_START = 0xe0000;
export const TAG_END = 0xe007f;

/** Characters that are invisible but have legitimate uses. PANE-HIDDEN-011. */
export const ZERO_WIDTH = new Set([
  0x200b, // ZERO WIDTH SPACE
  0x200c, // ZERO WIDTH NON-JOINER — required in Persian, Hindi, Malayalam
  0x200d, // ZERO WIDTH JOINER — required in emoji sequences and Indic conjuncts
  0x00ad, // SOFT HYPHEN
  0xfeff, // BYTE ORDER MARK / ZERO WIDTH NO-BREAK SPACE
  0x2060, // WORD JOINER
  0x2061, // FUNCTION APPLICATION
  0x2062, // INVISIBLE TIMES
  0x2063, // INVISIBLE SEPARATOR
  0x2064, // INVISIBLE PLUS
]);

export function isTagChar(cp: number): boolean {
  return cp >= TAG_START && cp <= TAG_END;
}

function inAny(cp: number, ranges: Array<[number, number]>): boolean {
  return ranges.some(([lo, hi]) => cp >= lo && cp <= hi);
}

/** Emoji, variation selectors and skin-tone modifiers — the ZWJ neighbourhood. */
function isPictographic(cp: number): boolean {
  return inAny(cp, [
    [0x00a9, 0x00a9], [0x00ae, 0x00ae], [0x203c, 0x203c], [0x2049, 0x2049],
    [0x2190, 0x21ff], [0x2300, 0x23ff], [0x2460, 0x24ff], [0x25a0, 0x27bf],
    [0x2b00, 0x2bff], [0x20e3, 0x20e3],
    [0xfe00, 0xfe0f], // variation selectors
    [0x1f000, 0x1faff],
    [0x1f3fb, 0x1f3ff], // skin tone modifiers
    [0x1f1e6, 0x1f1ff], // regional indicators
  ]);
}

/** Scripts in which ZWJ / ZWNJ are orthographically required. */
function isJoiningScript(cp: number): boolean {
  return inAny(cp, [
    [0x0590, 0x05ff], // Hebrew
    [0x0600, 0x06ff], // Arabic
    [0x0700, 0x074f], // Syriac
    [0x0750, 0x077f], // Arabic Supplement
    [0x0780, 0x07bf], // Thaana
    [0x0840, 0x085f], // Mandaic
    [0x08a0, 0x08ff], // Arabic Extended-A
    [0x0900, 0x0dff], // Devanagari … Sinhala (all Indic blocks)
    [0x0e00, 0x0e7f], // Thai
    [0x0e80, 0x0eff], // Lao
    [0x0f00, 0x0fff], // Tibetan
    [0x1000, 0x109f], // Myanmar
    [0x1780, 0x17ff], // Khmer
    [0xa9e0, 0xa9ff], // Myanmar Extended-B
    [0xfb1d, 0xfdff], // Hebrew/Arabic presentation forms
    [0xfe70, 0xfefe], // Arabic presentation forms-B
  ]);
}

/** Ideographic scripts, where a bare ZWSP is an ordinary line-break opportunity. */
function isIdeographic(cp: number): boolean {
  return inAny(cp, [
    [0x2e80, 0x303f], [0x3040, 0x30ff], [0x3100, 0x312f], [0x3400, 0x4dbf],
    [0x4e00, 0x9fff], [0xac00, 0xd7af], [0xf900, 0xfaff],
  ]);
}

function isCasedLetter(cp: number): boolean {
  return /\p{L}/u.test(String.fromCodePoint(cp)) && !isIdeographic(cp) && !isJoiningScript(cp);
}

export interface Occurrence {
  cp: number;
  /** Index into the code-point array of the unit. */
  index: number;
  /** Length of the consecutive zero-width run this occurrence belongs to. */
  runLength: number;
  /** False when the character sits where its script genuinely needs it. */
  outOfContext: boolean;
}

export interface ZeroWidthReport {
  occurrences: Occurrence[];
  /** Longest consecutive run in this unit. */
  longestRun: number;
  outOfContextCount: number;
  /** Which gate(s) this unit trips. Empty means it is clean. */
  gates: string[];
  /** `U+200B ×9` style summary, for the finding message. */
  summary: string;
}

/**
 * Is this zero-width character where its script needs it?
 *
 * Deliberately generous: **one** appropriate neighbour is enough. A Malayalam
 * chillu ends with ZWJ followed by a space, and a rainbow-flag ZWJ is preceded
 * by a variation selector rather than by the pictograph itself. Requiring both
 * neighbours would report both as injections.
 */
function inContext(cp: number, prev: number | null, next: number | null, atDocumentStart: boolean): boolean {
  const near = (test: (c: number) => boolean) =>
    (prev !== null && test(prev)) || (next !== null && test(next));

  switch (cp) {
    case 0x200d: // ZWJ
      return near(isPictographic) || near(isJoiningScript);
    case 0x200c: // ZWNJ
      return near(isJoiningScript);
    case 0xfeff: // BOM — legitimate only as the very first code point
      return atDocumentStart;
    case 0x00ad: // SOFT HYPHEN — a hyphenation hint inside a word
      return prev !== null && next !== null && isCasedLetter(prev) && isCasedLetter(next);
    case 0x200b: // ZWSP — a line-break opportunity, not an in-word separator
      return !(prev !== null && next !== null && isCasedLetter(prev) && isCasedLetter(next));
    default:
      // U+2060–U+2064: word joiner and the invisible math operators. Isolated
      // use is legitimate; runs are caught by the run gate.
      return true;
  }
}

/** Volume-and-context gates for one unit of text. docs/RULES.md § PANE-HIDDEN-011. */
export const RUN_GATE = 3;
export const COUNT_GATE = 8;

export function analyzeZeroWidth(
  text: string,
  opts: { unitStartsDocument?: boolean } = {},
): ZeroWidthReport {
  const points = Array.from(text).map((c) => c.codePointAt(0)!);
  const occurrences: Occurrence[] = [];

  let i = 0;
  while (i < points.length) {
    if (!ZERO_WIDTH.has(points[i]!)) {
      i++;
      continue;
    }
    let end = i;
    while (end < points.length && ZERO_WIDTH.has(points[end]!)) end++;
    const runLength = end - i;
    for (let k = i; k < end; k++) {
      const cp = points[k]!;
      const prev = k > 0 ? points[k - 1]! : null;
      const next = k + 1 < points.length ? points[k + 1]! : null;
      const atStart = k === 0 && opts.unitStartsDocument === true;
      occurrences.push({
        cp,
        index: k,
        runLength,
        outOfContext: !inContext(cp, prev, next, atStart),
      });
    }
    i = end;
  }

  const longestRun = occurrences.reduce((m, o) => Math.max(m, o.runLength), 0);
  const outOfContextCount = occurrences.filter((o) => o.outOfContext).length;

  const gates: string[] = [];
  if (longestRun >= RUN_GATE) gates.push(`a run of ${longestRun} consecutive zero-width characters`);
  if (outOfContextCount > 0) {
    gates.push(`${outOfContextCount} occurrence(s) outside any script-appropriate context`);
  }
  // The count gate deliberately counts only out-of-context occurrences. Volume
  // of *legitimate* joiners is not a signal — an emoji picker holds dozens of
  // ZWJ in one text node, and docs/RULES.md's plain "≥8 occurrences in one text
  // node" would fire on it. This is strictly narrower than the catalog text.
  if (outOfContextCount >= COUNT_GATE) {
    gates.push(`${outOfContextCount} out-of-context occurrences in a single unit`);
  }

  const counts = new Map<number, number>();
  for (const o of occurrences) counts.set(o.cp, (counts.get(o.cp) ?? 0) + 1);
  const summary = [...counts.entries()]
    .map(([cp, n]) => `U+${cp.toString(16).toUpperCase().padStart(4, '0')} ×${n}`)
    .join(', ');

  return { occurrences, longestRun, outOfContextCount, gates, summary };
}

/** Every tag character in a string, with a short code-point summary. */
export function findTagChars(text: string): { count: number; summary: string } {
  const hits = Array.from(text)
    .map((c) => c.codePointAt(0)!)
    .filter(isTagChar);
  if (hits.length === 0) return { count: 0, summary: '' };
  const first = hits.slice(0, 6).map((cp) => `U+${cp.toString(16).toUpperCase()}`).join(' ');
  return { count: hits.length, summary: hits.length > 6 ? `${first} …` : first };
}

/**
 * Character references in raw source that decode to an invisible character.
 *
 * parse5 decodes these inside body text and attribute values, but **not** inside
 * `<script>` or `<style>` text, where the tree scan therefore cannot see them.
 */
const ENTITY = /&#(\d+);|&#x([0-9a-f]+);|&(zwj|zwnj|shy|ZeroWidthSpace|NoBreak);/gi;

const NAMED: Record<string, number> = {
  zwj: 0x200d,
  zwnj: 0x200c,
  shy: 0x00ad,
  zerowidthspace: 0x200b,
  nobreak: 0x2060,
};

/** Replace invisible-character references with the characters themselves. */
export function decodeInvisibleEntities(raw: string): { decoded: string; replaced: number } {
  let replaced = 0;
  const decoded = raw.replace(ENTITY, (match, dec: string | undefined, hex: string | undefined, name: string | undefined) => {
    let cp: number | undefined;
    if (dec !== undefined) cp = Number.parseInt(dec, 10);
    else if (hex !== undefined) cp = Number.parseInt(hex, 16);
    else if (name !== undefined) cp = NAMED[name.toLowerCase()];
    if (cp === undefined || !Number.isFinite(cp)) return match;
    if (!ZERO_WIDTH.has(cp) && !isTagChar(cp)) return match;
    replaced++;
    return String.fromCodePoint(cp);
  });
  return { decoded, replaced };
}

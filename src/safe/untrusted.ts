/**
 * Every string that came from a scanned server passes through here.
 *
 * Panelint's output goes into CI logs, into GitHub's Security tab via SARIF,
 * into the public directory, and increasingly into agent contexts. Evidence
 * excerpts from the PANE-HIDDEN family are, by construction, prompt-injection
 * payloads — that is what the family detects. Server names, resource URIs, tool
 * descriptions and parser error text are equally attacker-authored.
 *
 * The control is escaping, not stripping. Stripping a zero-width character
 * destroys the evidence the finding is about; escaping it to `​` renders it
 * inert in every sink while keeping it legible to the person reading the report.
 * One pass neutralizes ANSI escapes, OSC 52 clipboard writes, `\r` line
 * overwrites, and Trojan Source bidi overrides together.
 *
 * `Untrusted` is a branded type. A Finding, a diagnostic, or a report header
 * field cannot be constructed from a bare `string`, so "did we escape this?"
 * becomes a compile error rather than a review comment.
 */

declare const UNTRUSTED: unique symbol;

/** A string that has been escaped and capped. Construct only via `sanitize`. */
export type Untrusted = string & { readonly [UNTRUSTED]: true };

export interface SanitizeResult {
  text: Untrusted;
  truncated: boolean;
  /** Length in code points before capping. */
  originalLength: number;
}

/** The printable ASCII range plus tab. Everything else is escaped. */
function isSafePrintable(cp: number): boolean {
  return (cp >= 0x20 && cp <= 0x7e) || cp === 0x09;
}

/**
 * Escape a hostile string and cap it.
 *
 * Escapes everything outside printable ASCII as `\uXXXX` (or `\u{XXXXX}` for
 * astral code points), including the U+E0000 tag characters PANE-HIDDEN-009
 * exists to find. Backslash is doubled so the escaping is unambiguous.
 */
export function sanitize(raw: string, cap: number): SanitizeResult {
  const points = Array.from(raw);
  const originalLength = points.length;
  const truncated = originalLength > cap;
  const kept = truncated ? points.slice(0, cap) : points;

  let out = '';
  for (const ch of kept) {
    const cp = ch.codePointAt(0)!;
    if (ch === '\\') {
      out += '\\\\';
    } else if (isSafePrintable(cp)) {
      out += ch;
    } else if (cp <= 0xffff) {
      out += `\\u${cp.toString(16).padStart(4, '0')}`;
    } else {
      out += `\\u{${cp.toString(16)}}`;
    }
  }
  if (truncated) out += '…';

  return { text: out as Untrusted, truncated, originalLength };
}

/** Sanitize and keep only the text — the common case. */
export function safe(raw: string, cap: number): Untrusted {
  return sanitize(raw, cap).text;
}

/**
 * A string Panelint itself authored, asserted trusted.
 *
 * Use only for literals in Panelint's own source. Never for anything that
 * transited a scanned resource, a capture file, or a spawned process.
 */
export function trusted(literal: string): Untrusted {
  return literal as Untrusted;
}

/**
 * JSON-envelope encoding.
 *
 * The public directory inlines the envelope into a `<script>` tag, where a
 * literal `</script>` inside a JSON string ends the element regardless of JSON
 * quoting. U+2028 and U+2029 are also escaped because they are raw newlines to
 * a JavaScript parser but legal inside a JSON string.
 */
export function encodeForJson(text: Untrusted): string {
  return text
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

/**
 * SARIF `message.text` encoding.
 *
 * SARIF gives `[text](target)` a link meaning inside message strings, so square
 * brackets and backslashes are escaped per the embedded-link syntax. Panelint
 * never populates `message.markdown` from untrusted text at all.
 */
export function encodeForSarif(text: Untrusted): string {
  return text.replace(/\\/g, '\\\\').replace(/\[/g, '\\[').replace(/\]/g, '\\]');
}

/**
 * Turn a thrown value into a diagnostic-safe description.
 *
 * `String(error)` must never reach an output channel. postcss's
 * `CssSyntaxError.toString()` embeds a source code frame — measured, it
 * reproduces the offending CSS verbatim, which under directory mode can be an
 * arbitrary file's contents. acorn and JSON.parse are better behaved, but the
 * rule is uniform so no future dependency reintroduces the leak.
 *
 * Only the error's class name and a structural position survive.
 */
export function describeError(e: unknown): { kind: string; line?: number; column?: number } {
  if (!(e instanceof Error)) return { kind: 'UnknownError' };

  const kind = e.constructor?.name ?? 'Error';
  const withPos = e as Error & { line?: unknown; column?: unknown; loc?: { line?: number; column?: number } };

  const line = numeric(withPos.line) ?? numeric(withPos.loc?.line);
  const column = numeric(withPos.column) ?? numeric(withPos.loc?.column);

  return {
    kind,
    ...(line !== undefined ? { line } : {}),
    ...(column !== undefined ? { column } : {}),
  };
}

function numeric(v: unknown): number | undefined {
  return typeof v === 'number' && Number.isFinite(v) ? v : undefined;
}

/** A one-line, already-escaped rendering of an error, for a diagnostic message. */
export function errorSummary(e: unknown): Untrusted {
  const d = describeError(e);
  const pos = d.line !== undefined ? ` at ${d.line}:${d.column ?? 0}` : '';
  return trusted(`${d.kind}${pos}`);
}

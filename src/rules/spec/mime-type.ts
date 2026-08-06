/**
 * PANE-SPEC-002 and PANE-SPEC-009 — the MIME declaration, normalized first.
 *
 * ── The correction that keeps this pair off conformant servers ───────────────
 * The canonical literal is `text/html;profile=mcp-app`, with no space, and it
 * is the only spelling that appears anywhere in `schema.json`. But RFC 9110 §8.3
 * makes media-type parameters whitespace-tolerant and makes the type, subtype
 * and parameter NAMES case-insensitive, and it permits a `quoted-string`
 * parameter value. So all of these are the SAME declaration:
 *
 *     text/html; profile=mcp-app
 *     TEXT/HTML;profile=mcp-app
 *     text/html;PROFILE=mcp-app
 *     text/html;profile="mcp-app"
 *     text/html;charset=utf-8;profile=mcp-app
 *
 * A byte-for-byte comparison flags every one at SPEC/HIGH/CERTAIN — gate
 * eligible, so it fails the build. RULES.md calls that "the second-most-likely
 * way to ship a discredited scanner after the two poisoned rules."
 *
 * So the split is:
 *   -002  fires only when the declaration is semantically WRONG — wrong essence,
 *         no `profile` parameter (bare `text/html`), or a different profile.
 *   -009  fires at LOW when it is semantically right but not the canonical
 *         spelling, because some hosts may string-compare.
 *
 * The parameter VALUE is compared case-sensitively. SPEC-REFERENCE.md §1 is
 * explicit that normalization "preserve[s] the parameter *value* case", and RFC
 * 9110 leaves value case-sensitivity to the individual parameter. `profile` is
 * an opaque identifier, so `profile=MCP-App` is a different value, not a
 * different spelling of the same one.
 */

import { defineRule, makeFinding, undecided, NO_FINDINGS } from '../shared/helpers.js';
import type { RuleContext, RuleResult } from '../../types.js';

/** The literal from SPEC-REFERENCE.md §1. No space, all lowercase. */
export const CANONICAL_MIME = 'text/html;profile=mcp-app';
export const MCP_APP_ESSENCE = 'text/html';
export const MCP_APP_PROFILE = 'mcp-app';

// ---------------------------------------------------------------------------
// RFC 9110 §5.6.6 / §8.3 media-type parsing
// ---------------------------------------------------------------------------

export interface MediaType {
  /** Lowercased `type/subtype`. */
  essence: string;
  /** Parameter names lowercased; values unquoted with their case preserved. */
  params: Map<string, string>;
  /** True when any parameter arrived as a `quoted-string`. */
  hadQuotedValue: boolean;
  /** True when the same parameter name appeared more than once. */
  hadDuplicateParam: boolean;
}

/** RFC 9110 §5.6.2 token characters. */
const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

/** Split on `;` while respecting `quoted-string` and its `quoted-pair`. */
function splitOnSemicolons(s: string): string[] {
  const parts: string[] = [];
  let cur = '';
  let inQuotes = false;
  let escaped = false;

  for (const ch of s) {
    if (escaped) {
      cur += ch;
      escaped = false;
      continue;
    }
    if (inQuotes && ch === '\\') {
      cur += ch;
      escaped = true;
      continue;
    }
    if (ch === '"') {
      inQuotes = !inQuotes;
      cur += ch;
      continue;
    }
    if (ch === ';' && !inQuotes) {
      parts.push(cur);
      cur = '';
      continue;
    }
    cur += ch;
  }
  parts.push(cur);
  return parts;
}

function unquote(v: string): { value: string; quoted: boolean } | null {
  if (!v.startsWith('"')) {
    return TOKEN.test(v) ? { value: v, quoted: false } : null;
  }
  if (v.length < 2 || !v.endsWith('"')) return null;
  const body = v.slice(1, -1);
  let out = '';
  let escaped = false;
  for (const ch of body) {
    if (escaped) {
      out += ch;
      escaped = false;
      continue;
    }
    if (ch === '\\') {
      escaped = true;
      continue;
    }
    if (ch === '"') return null; // an unescaped quote inside the string
    out += ch;
  }
  if (escaped) return null;
  return { value: out, quoted: true };
}

/** Parse a media type per RFC 9110. Returns null when it is not one. */
export function parseMediaType(raw: string): MediaType | null {
  const segments = splitOnSemicolons(raw.trim());
  const first = segments[0];
  if (first === undefined) return null;

  const essenceRaw = first.trim();
  const slash = essenceRaw.indexOf('/');
  if (slash <= 0 || slash === essenceRaw.length - 1) return null;
  const type = essenceRaw.slice(0, slash);
  const subtype = essenceRaw.slice(slash + 1);
  if (!TOKEN.test(type) || !TOKEN.test(subtype)) return null;

  const params = new Map<string, string>();
  let hadQuotedValue = false;
  let hadDuplicateParam = false;

  for (const seg of segments.slice(1)) {
    const p = seg.trim();
    // A trailing `;` with nothing after it is not a legal parameter. Treating it
    // as harmless would let `text/html;;;` through as canonical-adjacent.
    if (p === '') return null;
    const eq = p.indexOf('=');
    if (eq <= 0) return null;
    const name = p.slice(0, eq).trim().toLowerCase();
    if (!TOKEN.test(name)) return null;
    const parsed = unquote(p.slice(eq + 1).trim());
    if (parsed === null) return null;
    if (parsed.quoted) hadQuotedValue = true;
    if (params.has(name)) hadDuplicateParam = true;
    else params.set(name, parsed.value);
  }

  return { essence: `${type.toLowerCase()}/${subtype.toLowerCase()}`, params, hadQuotedValue, hadDuplicateParam };
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

export type MimeVerdict =
  /** Byte-for-byte the canonical literal. */
  | { kind: 'canonical' }
  /** RFC 9110-identical to the canonical literal, spelled differently. */
  | { kind: 'equivalent'; detail: string }
  /** Not a declaration of an MCP App resource. */
  | { kind: 'wrong'; detail: string }
  /** No declaration was supplied at all. */
  | { kind: 'absent' };

export function classifyMimeType(raw: string | undefined): MimeVerdict {
  if (raw === undefined || raw.trim() === '') return { kind: 'absent' };

  const parsed = parseMediaType(raw);
  if (parsed === null) return { kind: 'wrong', detail: 'not a parseable media type' };

  if (parsed.essence !== MCP_APP_ESSENCE) {
    return { kind: 'wrong', detail: `type is ${parsed.essence}, expected ${MCP_APP_ESSENCE}` };
  }

  const profile = parsed.params.get('profile');
  if (profile === undefined) {
    return {
      kind: 'wrong',
      detail: 'the profile parameter is absent — bare text/html does not declare an MCP App resource',
    };
  }
  if (profile !== MCP_APP_PROFILE) {
    return { kind: 'wrong', detail: `profile parameter is not ${MCP_APP_PROFILE}` };
  }

  if (raw === CANONICAL_MIME) return { kind: 'canonical' };
  return { kind: 'equivalent', detail: describeSpelling(raw, parsed) };
}

function describeSpelling(raw: string, parsed: MediaType): string {
  const reasons: string[] = [];
  if (raw !== raw.trim()) reasons.push('surrounding whitespace');
  if (/\s*;\s/.test(raw) || /\s;/.test(raw)) reasons.push('whitespace around the parameter separator');
  if (raw.trim().slice(0, MCP_APP_ESSENCE.length).toLowerCase() === MCP_APP_ESSENCE &&
      raw.trim().slice(0, MCP_APP_ESSENCE.length) !== MCP_APP_ESSENCE) {
    reasons.push('non-lowercase type');
  }
  if (/;\s*[A-Z]/.test(raw)) reasons.push('non-lowercase parameter name');
  if (parsed.hadQuotedValue) reasons.push('quoted parameter value');
  if (parsed.hadDuplicateParam) reasons.push('a repeated parameter');
  const extras = [...parsed.params.keys()].filter((k) => k !== 'profile');
  if (extras.length) reasons.push(`extra parameter${extras.length > 1 ? 's' : ''}: ${extras.join(', ')}`);
  return reasons.length ? reasons.join('; ') : 'differs from the canonical literal';
}

/**
 * The declaration to judge.
 *
 * The `resources/read` content item is authoritative. The `resources/list` entry
 * is the fallback, because directory mode and some capture paths only ever see
 * that one.
 */
function declaredMime(ctx: RuleContext): { value: string | undefined; pointer: string } {
  const read = ctx.resource.mimeType;
  if (read !== undefined && read.trim() !== '') return { value: read, pointer: '/mimeType' };
  const listed = ctx.resource.listedMimeType;
  if (listed !== undefined && listed.trim() !== '') return { value: listed, pointer: '/listedMimeType' };
  return { value: undefined, pointer: '/mimeType' };
}

// ---------------------------------------------------------------------------
// PANE-SPEC-002
// ---------------------------------------------------------------------------

export const paneSpec002 = defineRule({
  id: 'PANE-SPEC-002',
  ruleClass: 'SPEC',
  severity: 'HIGH',
  confidence: 'CERTAIN',
  title: 'mimeType is not text/html;profile=mcp-app after RFC 9110 normalization',
  specRef: 'SPEC-REFERENCE.md §1 — Exact identifiers',
  remediation:
    'Declare the resource as text/html;profile=mcp-app. The profile parameter is what tells a ' +
    'host the HTML is an MCP App rather than an ordinary HTML resource.',
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: [],

  check(ctx): RuleResult {
    const { value, pointer } = declaredMime(ctx);
    const verdict = classifyMimeType(value);

    if (verdict.kind === 'absent') {
      // Undecided is not clean. Directory mode frequently cannot recover a
      // declared MIME type, and guessing "it must be fine" would let a silent
      // gap look identical to a checked pass.
      return {
        findings: [],
        undecided: [undecided(ctx, paneSpec002, 'no mimeType was supplied by this acquire path')],
      };
    }

    if (verdict.kind !== 'wrong') return NO_FINDINGS;

    return {
      findings: [
        makeFinding({
          ctx,
          rule: paneSpec002,
          message: `Resource mimeType does not declare an MCP App: ${verdict.detail}.`,
          evidence: value,
          jsonPointer: pointer,
          path: pointer,
        }),
      ],
    };
  },
});

// ---------------------------------------------------------------------------
// PANE-SPEC-009
// ---------------------------------------------------------------------------

export const paneSpec009 = defineRule({
  id: 'PANE-SPEC-009',
  ruleClass: 'SPEC',
  severity: 'LOW',
  confidence: 'CERTAIN',
  title: 'mimeType is semantically correct but not the canonical spelling',
  specRef: 'SPEC-REFERENCE.md §1 — Exact identifiers, [v2] note on matching the MIME type',
  remediation:
    'Emit the literal text/html;profile=mcp-app. The declaration is valid under RFC 9110 as ' +
    'written, but the canonical form is the only spelling in the schema and a host that ' +
    'string-compares will not match it.',
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: [],

  check(ctx): RuleResult {
    const { value, pointer } = declaredMime(ctx);
    const verdict = classifyMimeType(value);
    if (verdict.kind !== 'equivalent') return NO_FINDINGS;

    return {
      findings: [
        makeFinding({
          ctx,
          rule: paneSpec009,
          message:
            `mimeType is RFC 9110-identical to text/html;profile=mcp-app but not spelled ` +
            `canonically (${verdict.detail}). Valid as written; a host that string-compares ` +
            `will not match it.`,
          evidence: value,
          jsonPointer: pointer,
          path: pointer,
        }),
      ],
    };
  },
});

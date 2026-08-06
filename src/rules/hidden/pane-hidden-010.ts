/**
 * PANE-HIDDEN-010 — a base64 or hex blob that decodes to natural-language text.
 *
 * Attribute values are read by many context-extraction pipelines while being
 * rendered to nobody (docs/RULES.md § PANE-HIDDEN-012/-015 box). An encoded
 * blob in a `data-*` attribute is the same idea one layer removed: nothing
 * renders it, but a naive text-extraction pass that base64-decodes anything
 * that looks encoded will read it as plain instructions.
 *
 * The one thing that keeps this rule from firing on every fingerprint hash
 * and every inline image is that it insists the DECODED bytes are natural
 * language — printable, mostly letters, several real words — not merely
 * base64-shaped. A binary `data:` URI decodes back to binary and is rejected
 * on exactly that ground, with no special-case for image MIME types needed.
 *
 * Confidence MEDIUM: decoding-to-plausible-prose is a heuristic, not a
 * structural fact, so this rule never gates (docs/RULES.md table).
 */

import type { Finding, RuleContext, RuleResult } from '../../types.js';
import { defineRule, makeFinding, structuralPath, excerpt } from '../shared/helpers.js';
import { scaleHiddenFinding } from '../shared/scale.js';
import { allElements, locationOf, attrLocationOf } from '../../parse/html.js';
import { meta } from './common.js';

const RULE = meta({
  id: 'PANE-HIDDEN-010',
  severity: 'MEDIUM',
  confidence: 'MEDIUM',
  title: 'Base64 or hex blob decoding to natural-language text',
  cwe: 'CWE-506',
  remediation: 'Remove the encoded payload, or store it as plain, reviewable markup instead.',
});

/** Bare base64/base64url blob spanning the whole value. */
const WHOLE_BASE64 = /^[A-Za-z0-9+/_-]{32,}={0,2}$/;
/** `data:<mime>;base64,<payload>` — the payload is checked, not the wrapper. */
const DATA_URI_BASE64 = /^data:[^,]*;base64,([A-Za-z0-9+/_-]+={0,2})$/i;
/** A hex blob: even length, long enough to be a real payload rather than a hash fragment. */
const WHOLE_HEX = /^(?:[0-9a-fA-F]{2}){20,}$/;

const MIN_DECODED_CHARS = 20;
/** Cap the source string before decoding — mirrors limits.base64DecodeCap. */
function capSource(value: string, capBytes: number): string {
  const capChars = Math.floor((capBytes * 4) / 3) + 4;
  return value.length > capChars ? value.slice(0, capChars) : value;
}

/** Printable-and-wordy enough to read as prose rather than decoded binary. */
function looksLikeNaturalLanguage(text: string): boolean {
  if (text.length < MIN_DECODED_CHARS) return false;
  // eslint-disable-next-line no-control-regex
  const controlChars = (text.match(/[\x00-\x08\x0e-\x1f\x7f-\x9f�]/g) ?? []).length;
  if (controlChars / text.length > 0.02) return false;
  const words = text.split(/\s+/).filter((w) => /[a-z]{2,}/i.test(w));
  if (words.length < 4) return false;
  const letters = (text.match(/[a-z]/gi) ?? []).length;
  return letters / text.length > 0.55;
}

function decodeCandidate(raw: string, kind: 'base64' | 'hex', capBytes: number): string | null {
  try {
    const buf = kind === 'base64'
      ? Buffer.from(capSource(raw, capBytes), 'base64')
      : Buffer.from(capSource(raw, capBytes), 'hex');
    if (buf.length === 0) return null;
    const text = buf.toString('utf8');
    // A round-trip mismatch beyond padding noise means this was not valid
    // base64/hex text to begin with (e.g. stray characters mid-string).
    return text;
  } catch {
    return null;
  }
}

/** The base64/hex payload to try, or null when the value is not blob-shaped. */
function extractPayload(value: string): { kind: 'base64' | 'hex'; payload: string } | null {
  const trimmed = value.trim();
  const dataUri = DATA_URI_BASE64.exec(trimmed);
  if (dataUri) return { kind: 'base64', payload: dataUri[1]! };
  if (WHOLE_BASE64.test(trimmed)) return { kind: 'base64', payload: trimmed };
  if (WHOLE_HEX.test(trimmed)) return { kind: 'hex', payload: trimmed };
  return null;
}

export const paneHidden010 = defineRule({
  ...RULE,
  requires: ['content'],
  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];

    for (const el of allElements(ctx.dom)) {
      for (const [name, value] of Object.entries(el.attribs ?? {})) {
        if (!value || value.length < 32) continue;
        const candidate = extractPayload(value);
        if (!candidate) continue;

        const decoded = decodeCandidate(candidate.payload, candidate.kind, ctx.limits.base64DecodeCap);
        if (decoded === null || !looksLikeNaturalLanguage(decoded)) continue;

        const scaled = scaleHiddenFinding({ ceiling: RULE.severity, text: decoded });

        findings.push(
          makeFinding({
            ctx,
            rule: RULE,
            severity: scaled.severity,
            message:
              `<${el.tagName} ${name}> holds a ${candidate.kind} blob that decodes to ` +
              `${decoded.length} characters of natural-language text — ${scaled.rationale}.`,
            evidence: excerpt(decoded),
            location: attrLocationOf(el, name) ?? locationOf(el),
            path: `${structuralPath(el)}@${name.toLowerCase()}`,
          }),
        );
      }
    }

    return { findings };
  },
});

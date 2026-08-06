/**
 * The rule-authoring contract.
 *
 * Every rule is a pure function from RuleContext to RuleResult. No shared
 * state, no ordering dependency, independently testable. These helpers exist so
 * that the parts a rule must not get wrong — evidence escaping, fingerprint
 * stability, the CSP-synthesis assumption sentence — are written once.
 */

import { createHash } from 'node:crypto';
import type {
  Confidence,
  Finding,
  Rule,
  RuleClass,
  RuleContext,
  RuleMeta,
  RuleRequirement,
  RuleResult,
  Severity,
  SourceLocation,
  UndecidedNote,
} from '../../types.js';
import { safe, type Untrusted } from '../../safe/untrusted.js';
import { Element } from 'domhandler';
import { ancestors } from '../../parse/html.js';

/**
 * Which inputs a rule needs.
 *
 * Directory mode cannot supply `_meta` — it scrapes source, and a source-level
 * walker cannot tell a declaration from an example of one. Measured: three of
 * 21 servers' only apparent `_meta.ui.csp` declarations were
 * `https://api.example.com` placeholders in READMEs and tests. So a rule that
 * needs `meta` is SKIPPED in directory mode with a diagnostic, never run
 * against scraped values.
 */
export type { RuleRequirement } from '../../types.js';

export interface RuleDefinition extends RuleMeta {
  requires: RuleRequirement[];
  check(ctx: RuleContext): RuleResult;
}

/** Declare a rule. The metadata here is what `panelint rules --json` publishes. */
export function defineRule(def: RuleDefinition): Rule & { requires: RuleRequirement[] } {
  return def;
}

export const NO_FINDINGS: RuleResult = Object.freeze({ findings: [] });

// ---------------------------------------------------------------------------
// Fingerprints
// ---------------------------------------------------------------------------

/**
 * A stable identity for a finding, for the baseline file.
 *
 * Deliberately NOT line numbers, so a baseline does not need rebuilding the
 * first time someone runs a formatter over their HTML. The structural path is
 * the element ancestry with sibling indices, which survives reformatting and
 * changes when the document actually changes.
 */
export function structuralPath(el: Element): string {
  const chain = [el, ...ancestors(el)].reverse();
  const parts: string[] = [];
  for (let i = 1; i < chain.length; i++) {
    const node = chain[i]!;
    const parent = chain[i - 1]!;
    const siblings = (parent.children ?? []).filter(
      (c): c is Element => c instanceof Element && c.tagName === node.tagName,
    );
    const idx = siblings.indexOf(node);
    parts.push(idx > 0 ? `${node.tagName}[${idx}]` : node.tagName);
  }
  return parts.join('/');
}

export function fingerprint(ruleId: string, resourceUri: string, path: string): string {
  return createHash('sha256').update(`${ruleId}\u0000${resourceUri}\u0000${path}`).digest('hex').slice(0, 32);
}

// ---------------------------------------------------------------------------
// Finding construction
// ---------------------------------------------------------------------------

/**
 * The synthesis assumption, attached to every CSP finding.
 *
 * `_meta.ui.csp` is four arrays; `csp_evaluator` takes a serialized policy
 * string. The exact policy a host builds from a NON-EMPTY `_meta.ui.csp` is not
 * specified anywhere, so Panelint synthesizes the policy the spec's construction
 * block describes. That synthesis is an assumption, and a finding that rests on
 * it says so rather than presenting it as a fact about the host.
 */
export const CSP_SYNTHESIS_ASSUMPTION =
  'Rests on the policy Panelint synthesizes from _meta.ui.csp per the spec\'s CSP ' +
  'construction block. The exact policy a host builds from a non-empty csp is not ' +
  'specified, and host enforcement is out of scope.';

/** Every rule in the PANE-SANDBOX family carries this. */
export const HOST_SANDBOX_ASSUMPTION =
  'Conditional on the host\'s View-iframe sandbox value, which the specification ' +
  'does not enumerate. A nested frame can never exceed its ancestor\'s sandbox flags.';

export interface FindingInput {
  ctx: RuleContext;
  rule: RuleMeta;
  message: string;
  /** Raw, attacker-authored. Escaped and capped here — never before. */
  evidence?: string;
  location?: SourceLocation;
  jsonPointer?: string;
  /** Structural path for the fingerprint. Falls back to the JSON pointer. */
  path?: string;
  /** Override the rule's default severity — see DESIGN.md §5 on volume scaling. */
  severity?: Severity;
  confidence?: Confidence;
  assumption?: string;
}

/**
 * Build a finding.
 *
 * Evidence is escaped and capped HERE, at construction, so no output format can
 * bypass it. A hidden-text finding must not reproduce the injection payload in
 * full into a CI log — and evidence from the PANE-HIDDEN family is, by
 * construction, a prompt-injection payload aimed at whoever reads the report.
 */
export function makeFinding(input: FindingInput): Finding {
  const { ctx, rule } = input;
  const path = input.path ?? input.jsonPointer ?? '';

  return {
    ruleId: rule.id,
    ruleClass: rule.ruleClass,
    severity: input.severity ?? rule.severity,
    confidence: input.confidence ?? rule.confidence,
    experimental: rule.experimental,
    message: input.message,
    resourceUri: ctx.resource.uri,
    ...(input.evidence !== undefined
      ? { evidence: safe(input.evidence, ctx.limits.maxEvidenceChars) }
      : {}),
    ...(input.location ? { location: input.location } : {}),
    ...(input.jsonPointer ? { jsonPointer: input.jsonPointer } : {}),
    fingerprint: fingerprint(rule.id, ctx.resource.uri, path),
    ...(input.assumption ? { assumption: input.assumption } : {}),
  };
}

/**
 * Record that a rule could not evaluate a case.
 *
 * Undecided is not clean. A rule that silently returns no findings when it
 * could not answer is indistinguishable from a rule that checked and found
 * nothing — and per SECURITY.md §1, a payload that reaches "no finding" through
 * a gap the attacker chooses is a reportable vulnerability in Panelint, not a
 * documented limitation.
 */
export function undecided(
  ctx: RuleContext,
  rule: RuleMeta,
  reason: string,
  location?: SourceLocation,
): UndecidedNote {
  return {
    ruleId: rule.id,
    resourceUri: ctx.resource.uri,
    reason,
    ...(location ? { location } : {}),
  };
}

// ---------------------------------------------------------------------------
// Shared predicates
// ---------------------------------------------------------------------------

/** Elements whose text is never rendered, so "hidden" says nothing about them. */
export const NON_RENDERED_TAGS = new Set([
  'script', 'style', 'meta', 'link', 'title', 'head', 'base', 'noscript', 'template',
]);

/**
 * Is this an absolute http(s) URL, and if so is it off-origin?
 *
 * The app document's URL is `about:srcdoc`, a `blob:` URL, or an opaque origin.
 * There is no origin to be "same" as, so EVERY absolute URL is off-document and
 * every relative URL is same-document. That is why an empty or relative `action`
 * is the benign case in an MCP App, and it inverts the classic web-phishing
 * heuristic that treats an empty action as suspicious.
 */
/**
 * A base the app document can never be, used to resolve candidates the way a
 * browser will. A resolved host that is still this one means the URL stayed on
 * the document; anything else left it.
 */
const RESOLUTION_BASE = 'https://document.invalid/panelint/';
const RESOLUTION_HOST = 'document.invalid';

/**
 * Resolve a URL the way the browser rendering the app will, or null if it does
 * not leave the document over http(s).
 *
 * **This must not go back to matching the raw attribute string.** The previous
 * implementation rejected anything starting with `/` as same-document and
 * pattern-matched `//host` with a regex that excluded backslashes and
 * whitespace. The WHATWG URL parser treats `\` as `/` and strips tab, LF and
 * CR, so every one of these reached a foreign origin while the rule saw a
 * relative path:
 *
 *     /\collector.example/c      \\collector.example/c
 *     //collector.example\c      //collector.exa<LF>mple/c
 *
 * All four resolve to `https://collector.example/…`, and all four produced zero
 * findings from PANE-EXFIL-001 — the CRITICAL/CERTAIN rule the catalog calls
 * the unblockable-egress check. Resolving against a sentinel base and comparing
 * hosts is what a browser actually does, so there is no spelling to enumerate.
 */
export function resolveOffDocument(url: string): URL | null {
  const trimmed = url.trim();
  if (!trimmed) return null;
  let resolved: URL;
  try {
    resolved = new URL(trimmed, RESOLUTION_BASE);
  } catch {
    return null;
  }
  if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') return null;
  // Still on the sentinel host — the URL is relative, a fragment, or a query.
  if (resolved.host === RESOLUTION_HOST) return null;
  return resolved;
}

/**
 * Is this URL absolute-or-authority-bearing, and does it leave the document?
 *
 * The app document's URL is `about:srcdoc`, a `blob:` URL, or an opaque origin.
 * There is no origin to be "same" as, so every URL carrying an authority is
 * off-document and every relative URL is same-document. That is why an empty or
 * relative `action` is the benign case in an MCP App, and it inverts the classic
 * web-phishing heuristic that treats an empty action as suspicious.
 */
export function isAbsoluteOffOrigin(url: string): boolean {
  return resolveOffDocument(url) !== null;
}

/** Origin of an absolute URL, or null when it is not absolute http(s). */
export function originOf(url: string): string | null {
  try {
    const u = new URL(url.trim());
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    return u.origin;
  } catch {
    return null;
  }
}

/** A short, already-capped excerpt for evidence. Never the whole node. */
export function excerpt(text: string, max = 80): string {
  const collapsed = text.replace(/\s+/g, ' ').trim();
  return collapsed.length > max ? `${collapsed.slice(0, max)}…` : collapsed;
}

export type { Untrusted };
export type { RuleClass, Severity, Confidence };

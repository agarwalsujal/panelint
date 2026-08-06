/**
 * The cross-resource rule contract.
 *
 * `shared/helpers.ts` supplies `defineRule` for per-resource rules. Rules that
 * need the whole `ResourceSet` — the tool list, the server's declared
 * capabilities — are `SetRule`s (types.ts), and there was no factory for them.
 * This module is that factory.
 *
 * ⚠ It lives under `spec/` because `PANE-SPEC-005` is the canonical
 * cross-resource rule, and `schema/tool-meta.ts` imports it from here. If a
 * future revision moves `defineSetRule` into `shared/helpers.ts` alongside
 * `defineRule` — where it arguably belongs — this file should become a
 * re-export rather than a second implementation.
 *
 * ── Why tool-scoped findings use a `tool:` resource URI ──────────────────────
 * `Finding.resourceUri` names the subject of the finding. Four rules
 * (`PANE-SPEC-005`, `-006`, `-011`, `PANE-SCHEMA-005`) are about a TOOL, not
 * about a resource, and three of them fire precisely when the resource the tool
 * names is missing or contradictory. Borrowing the referenced `ui://` URI would
 * attribute a tool's defect to a resource that may not exist. `tool:<name>` is
 * unambiguous, cannot collide with a `ui://` resource, and makes the subject
 * obvious in a SARIF viewer.
 */

import type {
  Finding,
  ResourceSet,
  RuleContext,
  RuleMeta,
  SetRule,
  Severity,
  SourceLocation,
  UIResource,
} from '../../types.js';
import type { RuleRequirement } from '../shared/helpers.js';
import { makeFinding } from '../shared/helpers.js';
import { DEFAULT_LIMITS } from '../../limits.js';

export interface SetRuleDefinition extends RuleMeta {
  requires: RuleRequirement[];
  checkSet(set: ResourceSet, perResource: Finding[]): Finding[];
}

export function defineSetRule(def: SetRuleDefinition): SetRule & { requires: RuleRequirement[] } {
  return def;
}

/** The `tool:` subject URI. One place, so the four rules cannot drift. */
export function toolSubject(toolName: string): string {
  return `tool:${toolName}`;
}

export interface SetFindingInput {
  rule: RuleMeta;
  /** Subject of the finding. Use `toolSubject(name)` for tool-scoped rules. */
  resourceUri: string;
  message: string;
  /** Raw, server-authored. Escaped and capped by `makeFinding`, never before. */
  evidence?: string;
  jsonPointer?: string;
  path?: string;
  severity?: Severity;
  location?: SourceLocation;
}

/**
 * Build a finding from a `checkSet` pass.
 *
 * `makeFinding` reads exactly two things from the context — the resource URI and
 * the evidence cap — and a `SetRule` has neither a `RuleContext` nor a `Limits`
 * in its signature. Rather than let four rules assemble `Finding` literals by
 * hand (and each get the escaping subtly different), the minimal context is
 * synthesized HERE, once, so every finding still goes through the one function
 * that escapes and caps evidence.
 */
export function makeSetFinding(input: SetFindingInput): Finding {
  const ctx = {
    resource: { uri: input.resourceUri } as UIResource,
    limits: DEFAULT_LIMITS,
  } as unknown as RuleContext;

  return makeFinding({
    ctx,
    rule: input.rule,
    message: input.message,
    ...(input.evidence !== undefined ? { evidence: input.evidence } : {}),
    ...(input.jsonPointer !== undefined ? { jsonPointer: input.jsonPointer } : {}),
    ...(input.path !== undefined ? { path: input.path } : {}),
    ...(input.severity !== undefined ? { severity: input.severity } : {}),
    ...(input.location !== undefined ? { location: input.location } : {}),
  });
}

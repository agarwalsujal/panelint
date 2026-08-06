/**
 * Core types for Panelint.
 *
 * Shapes here follow docs/DESIGN.md §3 exactly, including the five corrections
 * that section records. In particular: `dom` is a domhandler Document (not the
 * parse5 default tree), `styles` is node-indexed, `location` exists because
 * SARIF requires provenance, `undecided` exists so a rule can decline to answer,
 * and `set` is absent from RuleContext — cross-resource rules are `SetRule`s.
 */

import type { ConfigDiagnosticCode } from './config/types.js';
import type { Document, Element, AnyNode } from 'domhandler';
import type { ErrorObject } from 'ajv';

// ---------------------------------------------------------------------------
// Classification — three independent axes. Collapsing them is how scanners
// lose trust (docs/RULES.md § Classification model).
// ---------------------------------------------------------------------------

/** Is this actually wrong? */
export type RuleClass =
  /** Violates a MUST in SEP-1865. Objectively non-conformant. */
  | 'SPEC'
  /** Fails JSON Schema validation. Objectively invalid. */
  | 'SCHEMA'
  /** Permitted by the spec, expands attack surface. A judgment call. */
  | 'RISK'
  /** Neither good nor bad. Reported so an operator knows what they enable. */
  | 'INFO';

/** How bad if real? */
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

/**
 * How sure are we?
 *
 * CERTAIN is reserved for facts that survive any rendering — schema validation,
 * string equality, the presence of an element or attribute. Any rule that reads
 * *declared* CSS caps at HIGH, because Panelint does not compute styles.
 */
export type Confidence = 'CERTAIN' | 'HIGH' | 'MEDIUM' | 'LOW';

export type RuleStatus = 'active' | 'retired';

export const SEVERITY_ORDER: Readonly<Record<Severity, number>> = Object.freeze({
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0,
});

export const ALL_SEVERITIES: readonly Severity[] = Object.freeze([
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'INFO',
] as const);

// ---------------------------------------------------------------------------
// Resources
// ---------------------------------------------------------------------------

/** `_meta.ui` on a resource. Four fields; `additionalProperties: false`. */
export interface UIResourceMeta {
  csp?: UIResourceCsp;
  permissions?: UIResourcePermissions;
  /** Dedicated origin for the view sandbox. Host-defined format. */
  domain?: string;
  /** Requests a visible border + background from the host. */
  prefersBorder?: boolean;
  [key: string]: unknown;
}

/** `_meta.ui.csp`. Exactly four fields, all mapping to CSP *fetch* directives. */
export interface UIResourceCsp {
  /** → `connect-src` */
  connectDomains?: string[];
  /** → `img-src`, `script-src`, `style-src`, `font-src`, `media-src` */
  resourceDomains?: string[];
  /** → `frame-src`. Omitted ⇒ `frame-src 'none'` */
  frameDomains?: string[];
  /** → `base-uri`. Omitted ⇒ `base-uri 'self'` */
  baseUriDomains?: string[];
  [key: string]: unknown;
}

/** `_meta.ui.permissions`. Exactly four; the complete Stable enumeration. */
export interface UIResourcePermissions {
  camera?: Record<string, never>;
  microphone?: Record<string, never>;
  geolocation?: Record<string, never>;
  clipboardWrite?: Record<string, never>;
  [key: string]: unknown;
}

/** `_meta.ui` on a *tool*. `csp` and `permissions` are `{"not":{}}` — must be absent. */
export interface UIToolMeta {
  resourceUri?: string;
  visibility?: Array<'model' | 'app'>;
  csp?: unknown;
  permissions?: unknown;
  [key: string]: unknown;
}

export type AcquireSource = 'directory' | 'stdio' | 'http' | 'capture';

/**
 * A single `ui://` resource.
 *
 * `_meta.ui` arrives from TWO places with a precedence rule, and a single field
 * silently loses it. The `resources/list` entry is the "static default for hosts
 * to review at connection time"; the `resources/read` content item takes
 * precedence. A server whose list-level CSP is narrow and whose read-level CSP
 * is broad presents a misleading review surface — that is PANE-SPEC-010, and it
 * is invisible unless both are retained.
 */
export interface UIResource {
  /** Must start with `ui://`. */
  uri: string;
  /** From the `resources/read` content item. */
  mimeType: string;
  /** From the `resources/list` entry; may differ. */
  listedMimeType?: string;
  content: string;
  /** True when content arrived base64-encoded in `blob` rather than `text`. */
  fromBlob?: boolean;
  metaFromList?: UIResourceMeta;
  metaFromRead?: UIResourceMeta;
  /** Resolved: read wins, per ext-apps `McpUiAppResourceConfig`. */
  meta?: UIResourceMeta;
  schemaErrors: ErrorObject[];
  /** sha256 — defined precisely in docs/DESIGN.md §7. A one-way door. */
  contentHash: string;
  source: AcquireSource;
  /** Where the content came from on disk, when it came from disk. */
  filePath?: string;
  /**
   * How this resource was found.
   *
   * `resources/list` is not the complete set. The spec explicitly permits a
   * server to omit a tool-referenced app resource from the listing (apps.mdx
   * L395), so a scan that reads only what was listed reports NO_RESOURCES_FOUND
   * and exit 0 against an entire sanctioned class of conformant server. A
   * resource reached only through a tool's `_meta.ui.resourceUri` is marked
   * `tool-reference` so the report can say the listing did not mention it.
   */
  discoveredVia?: 'list' | 'tool-reference';
}

export interface ToolWithUIMeta {
  name: string;
  description?: string;
  annotations?: { readOnlyHint?: boolean; [key: string]: unknown };
  meta?: UIToolMeta;
  /** The raw `_meta` object, so the flat deprecated key stays visible. */
  rawMeta?: Record<string, unknown>;
  schemaErrors: ErrorObject[];
}

/**
 * Config, suppression and baseline diagnostics are scan diagnostics too.
 *
 * They were computed and then dropped: `src/cli.ts` merged `set.diagnostics`
 * and `analysis.diagnostics` and never `suppression.diagnostics`, so a scanned
 * tree attempting to silence the scanner produced no visible evidence at all —
 * including `INLINE_SUPPRESSION_IGNORED`, which carries "would have hidden N
 * findings". Unioning the code sets keeps every code exactly as it was rather
 * than flattening them into one lossy value.
 *
 * `import type` cycles are erased at runtime, so this costs nothing.
 */
export type DiagnosticCode =
  | ConfigDiagnosticCode
  | 'UNRESOLVED_URI'
  | 'LIMIT_EXCEEDED'
  | 'PARSE_FAILED'
  | 'NO_RESOURCES_FOUND'
  | 'UNDECIDED_CASCADE'
  | 'SELECTOR_SKIPPED'
  | 'CAPABILITY_NOT_DECLARED'
  /** Read because a tool referenced it, though `resources/list` omitted it. */
  | 'UNLISTED_RESOURCE'
  /**
   * A WHOLE analysis input degraded to empty — the style index could not be
   * built, or script collection failed. Distinct from `PARSE_FAILED`, which
   * covers a partial loss such as one unparseable `<style>` block.
   *
   * The distinction earns its keep at the exit code. Every CSS rule seeing no
   * declarations, or every JS rule seeing no scripts, means "0 findings" is an
   * absence of analysis rather than an absence of findings — and that was
   * reported as a plain diagnostic, so a resource whose stylesheet Panelint
   * could not parse exited 0 with a clean report.
   */
  | 'INPUT_DEGRADED'
  | 'SPAWN_REFUSED';

export interface ScanDiagnostic {
  code: DiagnosticCode;
  message: string;
  resourceUri?: string;
  detail?: string;
}

export interface ScanError {
  code: DiagnosticCode | 'ACQUIRE_FAILED' | 'INTERNAL_ERROR';
  message: string;
  resourceUri?: string;
}

export interface ResourceSet {
  serverName?: string;
  serverVersion?: string;
  protocolVersion?: string;
  /** Whether the server declared `io.modelcontextprotocol/ui` at initialize. */
  declaresUiExtension?: boolean;
  /** The MIME types the server declared for that extension, if any. */
  declaredMimeTypes?: string[];
  resources: UIResource[];
  tools: ToolWithUIMeta[];
  diagnostics: ScanDiagnostic[];
  errors: ScanError[];
  scannedAt: string;
  source: AcquireSource;
  /** Directory mode only. A scan that resolved 2 of 9 is not a clean bill of health. */
  resolvedCount?: number;
  declaredCount?: number;
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

export interface SourceLocation {
  startLine: number;
  startCol: number;
  endLine?: number;
  endCol?: number;
  startOffset?: number;
  endOffset?: number;
}

export interface Finding {
  ruleId: string;
  ruleClass: RuleClass;
  severity: Severity;
  confidence: Confidence;
  experimental: boolean;
  message: string;
  resourceUri: string;
  /** Truncated and escaped at construction. Never the full payload. */
  evidence?: string;
  location?: SourceLocation;
  /** A JSON pointer, for findings about `_meta` rather than about markup. */
  jsonPointer?: string;
  /**
   * Stable across reformatting: ruleId + resource URI + a structural path.
   * Deliberately NOT line numbers, so a baseline survives someone running
   * a formatter over their HTML.
   */
  fingerprint: string;
  /** Set when the finding rests on the CSP-synthesis assumption. */
  assumption?: string;
}

/** A rule that could not evaluate a case. Undecided is not clean. */
export interface UndecidedNote {
  ruleId: string;
  resourceUri: string;
  reason: string;
  location?: SourceLocation;
}

export interface RuleResult {
  findings: Finding[];
  undecided?: UndecidedNote[];
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

export interface Limits {
  maxResourceBytes: number;
  maxDomNodes: number;
  maxCssRules: number;
  selectorMatchBudget: number;
  perResourceMs: number;
  maxTotalResources: number;
  maxNestingDepth: number;
  base64DecodeCap: number;
  maxScriptBytes: number;
  maxEvidenceChars: number;
  /**
   * Entries permitted in one `_meta.ui.csp` domain array.
   *
   * `_meta` was covered by no limit key at all. Rules in the PANE-EXFIL and
   * PANE-CSP families compare every declared domain against every candidate
   * element, so the cost is `domains x elements` and a server controls both
   * factors. Measured: 10,000 domains against 4,000 `<img>` ran 17 s.
   */
  maxMetaDomains: number;
}

/** Node-indexed declared style. Returns what applies to *this* node. */
export interface DeclaredValue {
  value: string;
  important: boolean;
  /** 'inline' for a `style=` attribute, 'sheet' for a `<style>` block. */
  origin: 'inline' | 'sheet';
  location?: SourceLocation;
  /** The selector that bound this declaration, for evidence. */
  selector?: string;
}

export interface StyleIndexLike {
  /**
   * The resolved winner per property. Does not inherit, does not compute.
   *
   * Use for evidence, and for rules that genuinely need "the" value. NEVER use
   * it to conclude something is *not* hidden — that is what `candidatesFor` is
   * for, and the distinction is what keeps `@layer` from being a one-line
   * evasion of the whole PANE-HIDDEN family.
   */
  declaredStyle(node: Element): Map<string, DeclaredValue>;
  /**
   * EVERY declaration of `prop` that applies to this node, winner or not.
   *
   * The PANE-HIDDEN family asks this question, because resolution is
   * additive-only: it may raise a finding, never suppress one.
   */
  candidatesFor(node: Element, prop: string): DeclaredValue[];
  /** True when an unmodelled at-rule means the cascade cannot be trusted here. */
  isUndecided(node: Element): boolean;
  /** Reason strings for the report footer. */
  undecidedReasons(): string[];
  /** Every rule in every stylesheet, for rules that inspect CSS text directly. */
  allDeclarations(): Array<{ selector: string; prop: string; value: string; location?: SourceLocation }>;
}

export interface ScriptSource {
  /** Text of the script, whether inline or from an event-handler attribute. */
  code: string;
  /** The element the script came from, when it came from one. */
  element?: Element;
  /** Byte offset of the script text within the resource, for provenance. */
  offset: number;
  /** Parsed AST, or null when the script did not parse. */
  ast: unknown | null;
  parseError?: string;
}

export interface RuleContext {
  resource: UIResource;
  /** domhandler Document — NOT the parse5 default tree. */
  dom: Document;
  styles: StyleIndexLike;
  /** Resolved, read-wins. */
  meta: UIResourceMeta | null;
  schemaErrors: ErrorObject[];
  scripts: ScriptSource[];
  /** The raw resource text, for carriers parse5 normalizes away. */
  rawSource: string;
  /**
   * The server's tool list, or empty when the scan mode cannot supply one.
   *
   * A per-resource rule that reasons about tools needs this. It used to be
   * reachable only through `options['tools']`, which nothing ever populated —
   * `analyzeResourceSet` is called with no `ruleOptions` on every code path,
   * so PANE-CONTEXT-004 and PANE-CONTEXT-010 could not fire at all. Rules that
   * need tools declare `requires: ['tools']` and are skipped with a diagnostic
   * in modes that have none, so an empty array here means "this set has no
   * tools", never "this mode could not tell you".
   */
  tools: readonly ToolWithUIMeta[];
  options: Record<string, unknown>;
  limits: Limits;
  /** Emit a diagnostic without emitting a finding. */
  diagnostic(code: DiagnosticCode, message: string, detail?: string): void;
}

/**
 * Which inputs a rule needs before it can run.
 *
 * Directory mode cannot supply `_meta` — it scrapes source, and a source-level
 * walker cannot tell a declaration from an example of one. Measured: three of
 * 21 servers' only apparent `_meta.ui.csp` declarations were
 * `https://api.example.com` placeholders in READMEs and tests. So a rule that
 * needs `meta` is SKIPPED in directory mode with a diagnostic, never run
 * against scraped values.
 *
 * Declared here rather than in `rules/shared/helpers.ts` because `RuleMeta`
 * carries it, and helpers imports from this file — the other direction would
 * be a cycle. helpers re-exports it, so rule modules are unaffected.
 */
export type RuleRequirement = 'meta' | 'listMeta' | 'tools' | 'content' | 'capabilities';

export interface RuleMeta {
  /** Permanent, never reused. SARIF `rules[].id` is a public contract. */
  id: string;
  ruleClass: RuleClass;
  severity: Severity;
  confidence: Confidence;
  title: string;
  specRef?: string;
  cwe?: string;
  remediation: string;
  experimental: boolean;
  status: RuleStatus;
  /** semver of first release. */
  since: string;
  /**
   * What a rule needs before it can run at all.
   *
   * A rule requiring `meta` cannot run in directory mode, because there is no
   * server to ask — it is reported as skipped rather than silently passing.
   * Declared here rather than read through a cast so the field is visible to
   * anything that consumes the registry, including `panelint rules --json`.
   */
  requires?: readonly RuleRequirement[];
}

export interface Rule extends RuleMeta {
  check(ctx: RuleContext): RuleResult;
}

/** Cross-resource rules run once after the per-resource pass. */
export interface SetRule extends RuleMeta {
  checkSet(set: ResourceSet, perResource: Finding[]): Finding[];
}

export type AnyRule = Rule | SetRule;

export function isSetRule(r: AnyRule): r is SetRule {
  return typeof (r as SetRule).checkSet === 'function';
}

// Re-exported so rule modules import DOM types from one place.
export type { Document, Element, AnyNode };

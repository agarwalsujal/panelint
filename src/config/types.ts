/**
 * Types for configuration, suppression, and baselines (docs/DESIGN.md §5).
 *
 * The section exists because `PANE-CSP-003` (any non-empty `frameDomains`) and
 * `PANE-CSP-004` (any non-empty `baseUriDomains`) are gate-eligible and fire on
 * LEGITIMATE use of documented features. Without a suppression path, the first
 * team that legitimately nests a frame turns Panelint off entirely.
 *
 * Every type here is shaped by one fact: **a suppression is a way to make a
 * finding disappear, and the party who most wants a finding to disappear is the
 * one Panelint is pointed at.** So suppression carries provenance, is counted,
 * and is printed. A suppression you cannot see is a suppression an attacker can
 * use.
 *
 * These diagnostics are deliberately NOT `ScanDiagnostic` (src/types.ts). That
 * union is about acquiring and parsing a resource; a refused config key is a
 * fact about the operator's own tree, and conflating the two would put "your
 * config tried to set a spawn command" in the same channel as "this resource
 * exceeded a limit".
 */

import type { AcquireSource, Finding, Severity, UIResource } from '../types.js';
import type { Untrusted } from '../safe/untrusted.js';

// ---------------------------------------------------------------------------
// Severity overrides
// ---------------------------------------------------------------------------

/** `off | info | low | medium | high | critical`, normalized. */
export type SeverityOverride = Severity | 'OFF';

export interface RuleConfig {
  severity?: SeverityOverride;
  /** Passed through to `RuleContext.options`. Never interpreted here. */
  options?: Record<string, unknown>;
}

/** The raw file shape, before any validation. Every field is untrusted. */
export interface PanelintConfigFile {
  $schema?: unknown;
  rules?: unknown;
  failOn?: unknown;
  onError?: unknown;
  [key: string]: unknown;
}

export type ConfigOriginKind = 'default' | 'file' | 'package';

export interface ConfigOrigin {
  kind: ConfigOriginKind;
  /** Absolute path, when one was read. */
  path?: string;
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

export type ConfigDiagnosticCode =
  /** The file exists but is not readable, or escapes the scanned root. */
  | 'CONFIG_READ_FAILED'
  | 'CONFIG_PARSE_FAILED'
  /** A CLI-only key appeared in a config file. Fatal. */
  | 'CONFIG_KEY_REJECTED'
  /** A key that needs `--allow-repo-config` and did not get it. Ignored. */
  | 'CONFIG_KEY_REFUSED'
  | 'CONFIG_UNKNOWN_KEY'
  | 'CONFIG_INVALID_VALUE'
  /** A repo config tried to lower a severity or switch a rule off. */
  | 'CONFIG_OVERRIDE_REFUSED'
  /** Directives were found in content Panelint does not trust. */
  | 'INLINE_SUPPRESSION_IGNORED'
  | 'INLINE_SUPPRESSION_MALFORMED'
  | 'INLINE_SUPPRESSION_LIMIT'
  | 'BASELINE_READ_FAILED'
  | 'BASELINE_PARSE_FAILED'
  | 'BASELINE_INVALID_ENTRY'
  /** Fingerprint matched, content hash did not. First-class, never silent. */
  | 'BASELINE_CONTENT_CHANGED'
  /** Fingerprint matched an entry describing a different rule or resource. */
  | 'BASELINE_FINGERPRINT_MISMATCH'
  /** An accepted finding that no longer occurs. */
  | 'BASELINE_STALE';

export interface ConfigDiagnostic {
  code: ConfigDiagnosticCode;
  /**
   * Already escaped and capped. `Untrusted` is branded, so a message cannot be
   * built from a bare string — including from `String(error)`, which is how a
   * postcss code frame reproduces an arbitrary file into a CI log.
   */
  message: Untrusted;
  detail?: string;
  resourceUri?: string;
  ruleId?: string;
  fingerprint?: string;
  configPath?: string;
}

// ---------------------------------------------------------------------------
// Resolved config
// ---------------------------------------------------------------------------

export interface ResolvedConfig {
  origin: ConfigOrigin;
  /** Keyed by rule id. Only ids matching `PANE-<FAMILY>-<NNN>` survive. */
  rules: Record<string, RuleConfig>;
  /** Only set when `allowRepoConfig` was passed. CLI wins in every case. */
  failOn?: Severity;
  onError?: 'fail' | 'warn';
  /**
   * Passed by the CLI, never by the file. A repo config that could set this
   * would be a repo config that could grant itself the right to silence
   * findings — so the key is hard-rejected on sight.
   */
  allowRepoConfig: boolean;
  /** Same reasoning. Defaults to off; only a CLI flag turns it on. */
  trustInlineSuppressions: boolean;
  /** CLI-only keys that appeared in the file. Non-empty implies `fatal`. */
  rejectedKeys: string[];
  /** The config is unusable and the CLI must exit 2 rather than scan on. */
  fatal: boolean;
  diagnostics: ConfigDiagnostic[];
}

// ---------------------------------------------------------------------------
// Suppression
// ---------------------------------------------------------------------------

export type SuppressionChannel = 'inline' | 'config' | 'baseline';

export interface SuppressedFinding {
  finding: Finding;
  by: SuppressionChannel;
  /** Why it was suppressed, in words a report header can print. */
  detail: string;
}

/**
 * Printed in every report header.
 *
 * Not a nicety. A scan whose headline is "0 findings" and whose header says
 * "17 suppressed inline" is a different statement about a server than a scan
 * with no suppressions at all, and the reader has to be able to tell them apart.
 */
export interface SuppressionCounts {
  inline: number;
  config: number;
  baseline: number;
}

export interface InlineDirective {
  kind: 'next-line' | 'file';
  /** `null` means every rule on that line. */
  ruleIds: string[] | null;
  /** 1-based line the directive itself sits on. */
  line: number;
  /** 1-based line it guards, or `null` for a file directive. */
  targetLine: number | null;
}

export interface InlineScan {
  directives: InlineDirective[];
  /** Directives that looked like ours and did not parse. Counted, never guessed. */
  malformed: number;
  /** Every `panelint-disable*` token seen, well-formed or not. */
  total: number;
  /** True when the directive cap was hit. */
  truncated: boolean;
}

export interface OverrideOutcome {
  findings: Finding[];
  suppressed: SuppressedFinding[];
  diagnostics: ConfigDiagnostic[];
  raised: number;
  lowered: number;
}

export interface SuppressionOutcome {
  /** What survives. Feed THIS to `selectExitCode`. */
  findings: Finding[];
  suppressed: SuppressedFinding[];
  counts: SuppressionCounts;
  diagnostics: ConfigDiagnostic[];
  /** Directives found in trusted content. */
  inlineDirectivesHonoured: number;
  /** Directives found in content Panelint refused to trust. Tamper evidence. */
  inlineDirectivesIgnored: number;
  /** Baseline entries that no longer match anything in a scanned resource. */
  staleBaselineEntries: BaselineEntry[];
}

// ---------------------------------------------------------------------------
// Baseline
// ---------------------------------------------------------------------------

/**
 * One accepted finding.
 *
 * `fingerprint` is `ruleId` + resource URI + a structural path, and the
 * ATTACKER CONTROLS the URI and the path. A new malicious resource can be shaped
 * to collide with a baselined fingerprint and be auto-suppressed. So an entry is
 * bound to the resource's `contentHash` AT ACCEPTANCE TIME, and a changed hash
 * produces a diagnostic instead of a silent suppression.
 */
export interface BaselineEntry {
  fingerprint: string;
  ruleId: string;
  resourceUri: string;
  /** sha256 of the resource when the finding was accepted. Required. */
  contentHash: string;
  acceptedAt?: string;
  reason?: string;
}

export interface BaselineFile {
  version: number;
  generatedAt?: string;
  panelintVersion?: string;
  entries: BaselineEntry[];
}

export interface LoadedBaseline {
  entries: BaselineEntry[];
  path?: string;
  diagnostics: ConfigDiagnostic[];
  /** The file could not be read or parsed at all. */
  fatal: boolean;
}

export interface BaselineOutcome {
  findings: Finding[];
  suppressed: SuppressedFinding[];
  diagnostics: ConfigDiagnostic[];
  count: number;
  stale: BaselineEntry[];
}

export interface SuppressionInput {
  findings: Finding[];
  resources: UIResource[];
  config: ResolvedConfig;
  baseline?: BaselineEntry[];
}

export type { AcquireSource, Finding, Severity, UIResource };

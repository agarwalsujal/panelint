/**
 * The input every reporter takes, and the small amount of shared machinery
 * all three need.
 *
 * `ScanReport` is deliberately plain data. The CLI constructs it; no reporter
 * imports the rule registry or the runner, so a reporter can be exercised from
 * a literal in a test — which is what test/report.test.ts does, and what keeps
 * the golden envelope honest.
 *
 * Two things in this file are load-bearing beyond typing:
 *
 *   - `neutralize()` is a second escaping pass. Evidence is already escaped by
 *     `safe()` at Finding construction, and this pass is idempotent over that
 *     output — it does NOT double backslashes. It exists because a reporter
 *     must not depend on its caller having done the right thing. Output lands
 *     in CI logs, in GitHub's Security tab, and in agent contexts, and evidence
 *     from the PANE-HIDDEN family *is* a prompt-injection payload by
 *     construction.
 *   - the mode limitation sentences. DESIGN.md §7 requires every report to
 *     carry the limitation of the mode it ran in, in the place a reader hits
 *     it rather than in a footnote. None of them says a server "is safe."
 */

import type {
  AcquireSource,
  Finding,
  RuleClass,
  ScanDiagnostic,
  ScanError,
  Severity,
  UndecidedNote,
} from '../types.js';

// ---------------------------------------------------------------------------
// The envelope version
// ---------------------------------------------------------------------------

/**
 * The JSON envelope's schema version.
 *
 * A one-way door: the public directory consumes this envelope and it is frozen
 * before the census runs. Adding a key is a minor bump; removing or retyping
 * one is a major bump and a directory migration.
 */
export const SCHEMA_VERSION = '1.0.0';

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

export type ScanMode = AcquireSource;

/**
 * Where each suppression came from.
 *
 * Carried by every format and printed unconditionally by the text reporter,
 * including when every count is zero. A suppression you cannot see is a
 * suppression an attacker can use.
 */
export interface SuppressionCounts {
  /** `<!-- panelint-disable-next-line ... -->` in the scanned resource. */
  inline: number;
  /** `panelint.config.json` severity overrides set to `off`. */
  config: number;
  /** Fingerprints accepted in the baseline file. */
  baseline: number;
}

/** One scanned resource, reduced to what a report needs to say about it. */
export interface ReportResource {
  uri: string;
  /** sha256 over the bytes exactly as received. docs/DESIGN.md §7. */
  contentHash: string;
  mimeType?: string;
  byteLength?: number;
  /**
   * Repo-relative path, when the content came from disk.
   *
   * SARIF's `artifactLocation.uri` must be repo-relative; anything absolute or
   * traversing is dropped rather than emitted, so a hostile source path cannot
   * become an artifact URI uploaded to code scanning.
   */
  filePath?: string;
}

/** The point-in-time facts every format's header carries. docs/DESIGN.md §7. */
export interface ScanHeader {
  panelintVersion: string;
  /** From `ruleEngineFingerprint()` in src/acquire/hash.ts. */
  ruleEngineFingerprint: string;
  mode: ScanMode;
  /** ISO 8601. */
  scannedAt: string;
  /** What the user named — a directory, a command, a URL, a capture file. */
  target: string;
  serverName?: string;
  serverVersion?: string;
  protocolVersion?: string;
  /** The `--fail-on` threshold this run used. */
  failOn: Severity;
  suppressed: SuppressionCounts;
  /** Directory mode only. A scan that resolved 2 of 9 is not a clean run. */
  resolvedCount?: number;
  declaredCount?: number;
  /**
   * Prepended to every `filePath` before it becomes a SARIF `artifactLocation`.
   *
   * `ReportResource.filePath` is relative to the **scan root**, but GitHub
   * resolves SARIF paths against the **repository root**. Scanning
   * `packages/server` therefore produced `demo/board.html` for a file that
   * lives at `packages/server/demo/board.html` — alerts pointing at a path
   * that does not exist, or worse, at a same-named file elsewhere in the tree.
   *
   * The prefix closes that gap. It is validated as part of the joined path, so
   * a traversing or absolute prefix is refused exactly like a traversing
   * filePath. Set by `--path-prefix`, which the GitHub Action passes
   * automatically.
   */
  pathPrefix?: string;
}

export interface ScanReport {
  header: ScanHeader;
  resources: ReportResource[];
  findings: Finding[];
  undecided: UndecidedNote[];
  diagnostics: ScanDiagnostic[];
  errors: ScanError[];
}

// ---------------------------------------------------------------------------
// Mode limitations
// ---------------------------------------------------------------------------

const LIMITATIONS: Readonly<Record<ScanMode, string>> = Object.freeze({
  directory:
    'Directory mode reads source files only. It cannot see runtime-generated HTML, and a build ' +
    'entry point is not what the server serves — these findings describe a repository, not a ' +
    'served resource.',
  stdio:
    'Live stdio mode spawned the target server and read what it returned at this moment. The ' +
    'protocol carries no integrity mechanism, so a resource can change between this scan and its ' +
    'execution with no signal to anyone.',
  http:
    'Live HTTP mode read what the target returned at this moment. The protocol carries no ' +
    'integrity mechanism, so a resource can change between this scan and its execution with no ' +
    'signal to anyone.',
  capture:
    'Capture replay reports what one recorded session contained. The live server may have ' +
    'changed since the capture was taken.',
});

export function limitationFor(mode: ScanMode): string {
  return LIMITATIONS[mode];
}

/**
 * The sentence that fences the whole product.
 *
 * GOALS.md N1: Panelint reports properties of a content hash at a point in
 * time. It never issues a verdict about a server, and no output may imply one.
 */
export const DISCLAIMER =
  'Panelint reports properties of a content hash at a point in time. It issues no verdict about ' +
  'a server or a vendor.';

/**
 * Where a reader goes to check a finding.
 *
 * SARIF puts this in `tool.driver.informationUri`, which GitHub code scanning
 * renders as the tool's link in every consuming repository's Security tab. It
 * previously pointed at `github.com/panelint/panelint`, which 404s — a dead
 * link shipped in every report Panelint has ever emitted.
 *
 * `test/report.test.ts` pins this to package.json `homepage` so the two cannot
 * drift apart silently.
 */
export const HOMEPAGE = 'https://github.com/agarwalsujal/panelint';

// ---------------------------------------------------------------------------
// Ordering
// ---------------------------------------------------------------------------

/** SPEC before RISK, so a developer sees violations before observations. */
export const CLASS_ORDER: readonly RuleClass[] = Object.freeze([
  'SPEC',
  'SCHEMA',
  'RISK',
  'INFO',
] as const);

const SEVERITY_RANK: Readonly<Record<Severity, number>> = Object.freeze({
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
});

/** Findings for one class, most severe first, then stable by rule and URI. */
export function findingsInClass(findings: readonly Finding[], cls: RuleClass): Finding[] {
  return findings
    .filter((f) => f.ruleClass === cls)
    .sort(
      (a, b) =>
        SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
        a.ruleId.localeCompare(b.ruleId) ||
        a.resourceUri.localeCompare(b.resourceUri) ||
        a.fingerprint.localeCompare(b.fingerprint),
    );
}

// ---------------------------------------------------------------------------
// Undecided
// ---------------------------------------------------------------------------

export interface UndecidedCause {
  ruleId: string;
  reason: string;
  count: number;
}

/**
 * Undecided notes grouped by cause, biggest first.
 *
 * If PANE-HIDDEN-004 is undecided on 90% of nodes because the host supplies
 * colours via `var()`, an operator has to be able to see that. A bare total
 * hides exactly the case that matters.
 */
export function undecidedByCause(notes: readonly UndecidedNote[]): UndecidedCause[] {
  const counts = new Map<string, UndecidedCause>();
  for (const note of notes) {
    const key = `${note.ruleId}\u0000${note.reason}`;
    const existing = counts.get(key);
    if (existing) existing.count += 1;
    else counts.set(key, { ruleId: note.ruleId, reason: note.reason, count: 1 });
  }
  return [...counts.values()].sort(
    (a, b) => b.count - a.count || a.ruleId.localeCompare(b.ruleId) || a.reason.localeCompare(b.reason),
  );
}

// ---------------------------------------------------------------------------
// Escaping — the second pass
// ---------------------------------------------------------------------------

/** Evidence excerpt cap, in code points, applied by every reporter. */
export const EVIDENCE_CAP = 200;

/** Message cap. Messages are Panelint templates, but they embed server text. */
export const MESSAGE_CAP = 500;

/** Cap for short identifier-shaped strings: URIs, hashes, paths, targets. */
export const IDENT_CAP = 300;

function isRenderable(cp: number): boolean {
  // Printable ASCII plus tab. Everything else — ANSI CSI and OSC introducers,
  // CR, bidi overrides, zero-width joiners, the U+E0000 tag block — is escaped
  // to a visible `\uXXXX` so it is legible without being executable.
  return (cp >= 0x20 && cp <= 0x7e) || cp === 0x09;
}

/**
 * Escape and cap an untrusted string, idempotently.
 *
 * Deliberately does NOT double backslashes, unlike `safe()` in
 * src/safe/untrusted.ts. That is what makes running this over already-escaped
 * evidence a no-op instead of a slow march to `\\\\\\\\u000a`. The cost is that
 * a literal backslash from an unsanitized producer is indistinguishable from an
 * escape introducer, which is a legibility loss and never a safety one.
 */
export function neutralize(raw: string, cap: number): string {
  // Slice by code unit first so a 10 MB payload is never fully expanded.
  // `cap * 2` code units contain at least `cap` code points, so the code-point
  // slice below can never keep a lone surrogate created by this cut.
  const overLong = raw.length > cap * 2;
  const head = overLong ? raw.slice(0, cap * 2) : raw;

  const points = Array.from(head);
  const truncated = overLong || points.length > cap;
  const kept = truncated ? points.slice(0, cap) : points;

  let out = '';
  for (const ch of kept) {
    const cp = ch.codePointAt(0)!;
    if (isRenderable(cp)) out += ch;
    else if (cp <= 0xffff) out += `\\u${cp.toString(16).padStart(4, '0')}`;
    else out += `\\u{${cp.toString(16)}}`;
  }
  return truncated ? `${out}…` : out;
}

export const evidenceText = (raw: string): string => neutralize(raw, EVIDENCE_CAP);
export const messageText = (raw: string): string => neutralize(raw, MESSAGE_CAP);
export const identText = (raw: string): string => neutralize(raw, IDENT_CAP);

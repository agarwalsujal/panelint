/**
 * SARIF 2.1.0.
 *
 * GitHub code scanning renders this natively in the Security tab, which makes
 * it the distribution mechanism rather than a checkbox. That is also why the
 * class × severity → level mapping below is specified rather than inferred: a
 * naive `severity → level` mapping renders `PANE-CONTEXT-001` (INFO/HIGH) as an
 * `error`, and a capability disclosure shown as a vulnerability in someone's
 * Security tab is the exact failure GOALS.md N1 forbids.
 *
 * Four SARIF decisions, all from DESIGN.md §3.4:
 *
 *   - `artifactLocation.uri` is repo-relative, and anything absolute or
 *     traversing is refused rather than emitted. A hostile repository must not
 *     be able to name `/etc/passwd` in a SARIF file uploaded to code scanning.
 *   - a live-scanned resource has no file on disk, so it gets
 *     `logicalLocations` carrying the `ui://` URI and accepts that GitHub
 *     renders it without source context.
 *   - `partialFingerprints` comes from `Finding.fingerprint`, so findings
 *     survive someone running a formatter over their HTML.
 *   - `tool.driver.rules[]` comes from the registry, passed in as a parameter.
 *     This module does not import the registry: a reporter that imports the
 *     rule set cannot be tested from a literal, and the registry is the largest
 *     and most-churned module in the tree.
 *
 * `message.markdown` is never populated from untrusted text — not capped, not
 * escaped, never. `message.text` goes through `encodeForSarif` because SARIF
 * gives `[text](target)` a link meaning inside message strings.
 */

import { isGating } from '../exit.js';
import { encodeForSarif, type Untrusted } from '../safe/untrusted.js';
import type { Finding, RuleClass, RuleMeta, Severity } from '../types.js';
import {
  DISCLAIMER,
  evidenceText,
  identText,
  limitationFor,
  messageText,
  undecidedByCause,
  type ReportResource,
  type ScanReport,
} from './types.js';

export type SarifLevel = 'none' | 'note' | 'warning' | 'error';

/**
 * Class × severity → SARIF level. DESIGN.md §3.4, verbatim.
 *
 * | SPEC, SCHEMA | error at CRITICAL/HIGH, else warning |
 * | RISK         | error at CRITICAL/HIGH, warning at MEDIUM, note below |
 * | INFO         | note, always — regardless of severity |
 *
 * The INFO row is the one that carries the product's positioning. Do not
 * "improve" it by letting severity through.
 */
export function sarifLevel(ruleClass: RuleClass, severity: Severity): SarifLevel {
  if (ruleClass === 'INFO') return 'note';

  const isTopSeverity = severity === 'CRITICAL' || severity === 'HIGH';
  if (ruleClass === 'SPEC' || ruleClass === 'SCHEMA') {
    return isTopSeverity ? 'error' : 'warning';
  }
  // RISK
  if (isTopSeverity) return 'error';
  if (severity === 'MEDIUM') return 'warning';
  return 'note';
}

/**
 * A rough GitHub `security-severity` band, so the Security tab sorts sensibly.
 *
 * INFO-class findings get no band at all rather than a low one: they are not
 * weak vulnerabilities, they are not vulnerabilities.
 */
const SECURITY_SEVERITY: Readonly<Record<Severity, string>> = {
  CRITICAL: '9.0',
  HIGH: '7.5',
  MEDIUM: '5.0',
  LOW: '3.0',
  INFO: '1.0',
};

function esc(s: string): string {
  return encodeForSarif(s as Untrusted);
}

// ---------------------------------------------------------------------------
// Repo-relative paths
// ---------------------------------------------------------------------------

/**
 * A repo-relative URI, or null if the path cannot be trusted as one.
 *
 * Directory mode resolves file paths out of attacker-authored source. Refusing
 * here means the worst case is a finding rendered without source context, not
 * an absolute path leaked into a SARIF upload.
 */
export function repoRelativeUri(filePath: string | undefined): string | null {
  if (!filePath) return null;
  const normalized = filePath.replace(/\\/g, '/');
  if (normalized.includes('\0')) return null;
  if (normalized.startsWith('/')) return null;
  if (/^[A-Za-z]:/.test(normalized)) return null;
  if (normalized.startsWith('~')) return null;

  const segments = normalized.split('/').filter((s) => s !== '' && s !== '.');
  if (segments.length === 0) return null;
  if (segments.some((s) => s === '..')) return null;

  return segments.map(encodeURIComponent).join('/');
}

// ---------------------------------------------------------------------------

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  help: { text: string };
  defaultConfiguration: { level: SarifLevel };
  properties: Record<string, unknown>;
}

/**
 * @param rules the rule registry, passed in rather than imported.
 */
export function renderSarif(report: ScanReport, rules: readonly RuleMeta[]): string {
  const { header } = report;
  const isDirectory = header.mode === 'directory';

  // --- rules[] and the id → index map --------------------------------------
  const sarifRules: SarifRule[] = rules.map(toSarifRule);
  const ruleIndex = new Map<string, number>();
  sarifRules.forEach((r, i) => ruleIndex.set(r.id, i));

  // A finding whose rule is not in the registry still gets reported. The
  // registry can lag; a scanner that silently drops findings cannot.
  for (const f of report.findings) {
    if (ruleIndex.has(f.ruleId)) continue;
    ruleIndex.set(f.ruleId, sarifRules.length);
    sarifRules.push(synthesizedRule(f));
  }

  // --- artifacts[], on-disk resources only ---------------------------------
  const artifacts: Array<Record<string, unknown>> = [];
  const artifactIndex = new Map<string, number>();
  for (const r of report.resources) {
    const uri = repoRelativeUri(r.filePath);
    if (uri === null) continue;
    artifactIndex.set(r.uri, artifacts.length);
    artifacts.push({
      location: { uri, uriBaseId: '%SRCROOT%' },
      ...(r.byteLength !== undefined ? { length: r.byteLength } : {}),
      ...(r.mimeType ? { mimeType: esc(identText(r.mimeType)) } : {}),
      hashes: { 'sha-256': esc(identText(r.contentHash)) },
      properties: { resourceUri: esc(identText(r.uri)) },
    });
  }

  const byUri = new Map(report.resources.map((r) => [r.uri, r]));

  const results = report.findings.map((f) =>
    toResult(f, {
      ruleIndex: ruleIndex.get(f.ruleId) ?? 0,
      resource: byUri.get(f.resourceUri),
      artifactIndex: artifactIndex.get(f.resourceUri),
      failOn: header.failOn,
    }),
  );

  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Panelint',
            informationUri: 'https://github.com/panelint/panelint',
            version: esc(identText(header.panelintVersion)),
            semanticVersion: esc(identText(header.panelintVersion)),
            rules: sarifRules,
          },
        },
        // Stable across runs of the same rule engine, so GitHub can correlate
        // one scan configuration's results over time.
        automationDetails: {
          id: `panelint/${header.mode}/${esc(identText(header.ruleEngineFingerprint))}`,
        },
        invocations: [
          {
            executionSuccessful: report.errors.length === 0,
            ...(header.scannedAt ? { endTimeUtc: esc(identText(header.scannedAt)) } : {}),
            toolConfigurationNotifications: report.diagnostics.map((d) => ({
              level: 'note' as const,
              descriptor: { id: d.code },
              message: { text: esc(messageText(d.message)) },
              ...(d.resourceUri
                ? {
                    properties: { resourceUri: esc(identText(d.resourceUri)) },
                  }
                : {}),
            })),
            toolExecutionNotifications: report.errors.map((e) => ({
              level: 'error' as const,
              descriptor: { id: e.code },
              message: { text: esc(messageText(e.message)) },
              ...(e.resourceUri
                ? { properties: { resourceUri: esc(identText(e.resourceUri)) } }
                : {}),
            })),
          },
        ],
        artifacts,
        results,
        // DESIGN.md §7: every report header carries these, in every format.
        properties: {
          panelintVersion: esc(identText(header.panelintVersion)),
          ruleEngineFingerprint: esc(identText(header.ruleEngineFingerprint)),
          mode: header.mode,
          scannedAt: esc(identText(header.scannedAt)),
          target: esc(identText(header.target)),
          failOn: header.failOn,
          limitation: limitationFor(header.mode),
          disclaimer: DISCLAIMER,
          suppressed: {
            inline: header.suppressed.inline,
            config: header.suppressed.config,
            baseline: header.suppressed.baseline,
          },
          resolvedResources: isDirectory ? header.resolvedCount ?? null : null,
          declaredResources: isDirectory ? header.declaredCount ?? null : null,
          undecidedCount: report.undecided.length,
          undecidedByCause: undecidedByCause(report.undecided).map((cause) => ({
            ruleId: esc(identText(cause.ruleId)),
            reason: esc(messageText(cause.reason)),
            count: cause.count,
          })),
          resources: report.resources.map(toPropertyResource),
        },
      },
    ],
  };

  return `${JSON.stringify(sarif, null, 2)}\n`;
}

// ---------------------------------------------------------------------------

function toSarifRule(meta: RuleMeta): SarifRule {
  return {
    id: esc(identText(meta.id)),
    name: esc(identText(meta.title)),
    shortDescription: { text: esc(messageText(meta.title)) },
    fullDescription: { text: esc(messageText(meta.title)) },
    help: { text: esc(messageText(meta.remediation)) },
    defaultConfiguration: { level: sarifLevel(meta.ruleClass, meta.severity) },
    properties: {
      class: meta.ruleClass,
      severity: meta.severity,
      confidence: meta.confidence,
      experimental: meta.experimental,
      status: meta.status,
      since: esc(identText(meta.since)),
      ...(meta.specRef ? { specRef: esc(messageText(meta.specRef)) } : {}),
      ...(meta.cwe ? { cwe: esc(identText(meta.cwe)) } : {}),
      ...(meta.ruleClass === 'INFO' ? {} : { 'security-severity': SECURITY_SEVERITY[meta.severity] }),
      tags: [
        'panelint',
        `class/${meta.ruleClass}`,
        `confidence/${meta.confidence}`,
        ...(meta.experimental ? ['experimental'] : []),
        ...(meta.cwe ? [esc(identText(meta.cwe))] : []),
      ],
    },
  };
}

/** A placeholder for a finding whose rule the registry did not carry. */
function synthesizedRule(f: Finding): SarifRule {
  return {
    id: esc(identText(f.ruleId)),
    name: esc(identText(f.ruleId)),
    shortDescription: { text: esc(identText(f.ruleId)) },
    fullDescription: {
      text: 'This rule id was not present in the registry this report was rendered with.',
    },
    help: { text: 'See the rule catalog for this id.' },
    defaultConfiguration: { level: sarifLevel(f.ruleClass, f.severity) },
    properties: {
      class: f.ruleClass,
      severity: f.severity,
      confidence: f.confidence,
      experimental: f.experimental,
      synthesized: true,
      tags: ['panelint', `class/${f.ruleClass}`, 'unregistered'],
    },
  };
}

interface ResultContext {
  ruleIndex: number;
  resource: ReportResource | undefined;
  artifactIndex: number | undefined;
  failOn: Severity;
}

function toResult(f: Finding, ctx: ResultContext) {
  const uri = repoRelativeUri(ctx.resource?.filePath);

  const logicalLocations = [
    {
      name: esc(identText(f.resourceUri)),
      fullyQualifiedName: esc(identText(f.resourceUri)),
      kind: 'resource',
    },
  ];

  const location =
    uri !== null
      ? {
          physicalLocation: {
            artifactLocation: {
              uri,
              uriBaseId: '%SRCROOT%',
              ...(ctx.artifactIndex !== undefined ? { index: ctx.artifactIndex } : {}),
            },
            ...(f.location ? { region: toRegion(f) } : {}),
          },
          logicalLocations,
        }
      : { logicalLocations };

  return {
    ruleId: esc(identText(f.ruleId)),
    ruleIndex: ctx.ruleIndex,
    level: sarifLevel(f.ruleClass, f.severity),
    // text only. `markdown` is never populated from untrusted input.
    message: { text: esc(messageText(f.message)) },
    locations: [location],
    partialFingerprints: {
      panelintFingerprint_v1: esc(identText(f.fingerprint)),
    },
    properties: {
      class: f.ruleClass,
      severity: f.severity,
      confidence: f.confidence,
      experimental: f.experimental,
      gating: isGating(f, ctx.failOn),
      resourceUri: esc(identText(f.resourceUri)),
      ...(ctx.resource ? { contentHash: esc(identText(ctx.resource.contentHash)) } : {}),
      ...(f.jsonPointer ? { jsonPointer: esc(identText(f.jsonPointer)) } : {}),
      ...(f.assumption ? { assumption: esc(messageText(f.assumption)) } : {}),
      // Evidence stays out of `message.text`: it is quoted hostile input, and
      // the Security tab renders the message where a reader reads it as ours.
      ...(f.evidence !== undefined ? { evidence: esc(evidenceText(f.evidence)) } : {}),
    },
  };
}

function toRegion(f: Finding) {
  const loc = f.location!;
  return {
    startLine: Math.max(1, loc.startLine),
    startColumn: Math.max(1, loc.startCol),
    ...(loc.endLine !== undefined ? { endLine: Math.max(1, loc.endLine) } : {}),
    ...(loc.endCol !== undefined ? { endColumn: Math.max(1, loc.endCol) } : {}),
  };
}

function toPropertyResource(r: ReportResource) {
  const uri = repoRelativeUri(r.filePath);
  return {
    uri: esc(identText(r.uri)),
    contentHash: esc(identText(r.contentHash)),
    ...(r.mimeType ? { mimeType: esc(identText(r.mimeType)) } : {}),
    ...(r.byteLength !== undefined ? { byteLength: r.byteLength } : {}),
    ...(uri !== null ? { filePath: uri } : {}),
  };
}

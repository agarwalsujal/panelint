/**
 * The JSON envelope.
 *
 * This is a versioned envelope and a one-way door. The public directory
 * consumes it, the census keys on it, and it is frozen *before* the census runs
 * rather than after. Three consequences the shape below encodes deliberately:
 *
 *   - `undecided[]` ships in 1.0.0 even though it is often empty. Adding it
 *     later would be a breaking change for every consumer that validated the
 *     top-level key set.
 *   - every finding carries all three classification axes plus `experimental`
 *     and `gating`. A consumer that only got `severity` would have to guess the
 *     other two, and guessing them is exactly the collapse that makes scanners
 *     untrustworthy.
 *   - `resolvedResources` / `declaredResources` are `null` rather than absent
 *     outside directory mode, so the key set never varies by mode.
 *
 * Every string goes through `encodeForJson`. The directory inlines this
 * envelope into a `<script>` tag, where a literal `</script>` inside a JSON
 * string ends the element regardless of JSON quoting.
 */

import { isGating } from '../exit.js';
import { encodeForJson, type Untrusted } from '../safe/untrusted.js';
import type { Finding, ScanDiagnostic, ScanError, UndecidedNote } from '../types.js';
import {
  DISCLAIMER,
  SCHEMA_VERSION,
  evidenceText,
  identText,
  limitationFor,
  messageText,
  undecidedByCause,
  type ReportResource,
  type ScanReport,
} from './types.js';

/**
 * Encode a string for the envelope.
 *
 * Applied to every string, not only to ones known to be server-controlled.
 * The distinction is exactly the thing that goes wrong under maintenance, and
 * `encodeForJson` is a no-op on Panelint's own prose.
 */
function enc(s: string): string {
  return encodeForJson(s as Untrusted);
}

export function renderJson(report: ScanReport): string {
  const { header } = report;
  const isDirectory = header.mode === 'directory';
  const gating = report.findings.filter((f) => isGating(f, header.failOn));

  const envelope = {
    schemaVersion: SCHEMA_VERSION,
    tool: {
      name: 'panelint',
      version: enc(identText(header.panelintVersion)),
      ruleEngineFingerprint: enc(identText(header.ruleEngineFingerprint)),
    },
    scan: {
      mode: header.mode,
      scannedAt: enc(identText(header.scannedAt)),
      target: enc(identText(header.target)),
      serverName: header.serverName ? enc(identText(header.serverName)) : null,
      serverVersion: header.serverVersion ? enc(identText(header.serverVersion)) : null,
      protocolVersion: header.protocolVersion ? enc(identText(header.protocolVersion)) : null,
      failOn: header.failOn,
      limitation: enc(limitationFor(header.mode)),
      disclaimer: enc(DISCLAIMER),
      resolvedResources: isDirectory ? header.resolvedCount ?? null : null,
      declaredResources: isDirectory ? header.declaredCount ?? null : null,
      suppressed: {
        inline: header.suppressed.inline,
        config: header.suppressed.config,
        baseline: header.suppressed.baseline,
      },
      counts: {
        resources: report.resources.length,
        findings: report.findings.length,
        gating: gating.length,
        undecided: report.undecided.length,
        diagnostics: report.diagnostics.length,
        errors: report.errors.length,
      },
      // Undecided is not clean, and a bare total hides the case that matters:
      // one rule undecided on almost every node for one reason.
      undecidedByCause: undecidedByCause(report.undecided).map((cause) => ({
        ruleId: enc(identText(cause.ruleId)),
        reason: enc(messageText(cause.reason)),
        count: cause.count,
      })),
    },
    findings: report.findings.map((f) => jsonFinding(f, header.failOn)),
    undecided: report.undecided.map(jsonUndecided),
    diagnostics: report.diagnostics.map(jsonDiagnostic),
    errors: report.errors.map(jsonError),
    resources: report.resources.map(jsonResource),
  };

  return `${JSON.stringify(envelope, null, 2)}\n`;
}

function jsonFinding(f: Finding, failOn: Parameters<typeof isGating>[1]) {
  return {
    ruleId: enc(identText(f.ruleId)),
    class: f.ruleClass,
    severity: f.severity,
    confidence: f.confidence,
    experimental: f.experimental,
    gating: isGating(f, failOn),
    message: enc(messageText(f.message)),
    resourceUri: enc(identText(f.resourceUri)),
    evidence: f.evidence !== undefined ? enc(evidenceText(f.evidence)) : null,
    location: f.location
      ? {
          startLine: f.location.startLine,
          startCol: f.location.startCol,
          endLine: f.location.endLine ?? null,
          endCol: f.location.endCol ?? null,
          startOffset: f.location.startOffset ?? null,
          endOffset: f.location.endOffset ?? null,
        }
      : null,
    jsonPointer: f.jsonPointer ? enc(identText(f.jsonPointer)) : null,
    assumption: f.assumption ? enc(messageText(f.assumption)) : null,
    fingerprint: enc(identText(f.fingerprint)),
  };
}

function jsonUndecided(u: UndecidedNote) {
  return {
    ruleId: enc(identText(u.ruleId)),
    resourceUri: enc(identText(u.resourceUri)),
    reason: enc(messageText(u.reason)),
    location: u.location
      ? { startLine: u.location.startLine, startCol: u.location.startCol }
      : null,
  };
}

function jsonDiagnostic(d: ScanDiagnostic) {
  return {
    code: d.code,
    message: enc(messageText(d.message)),
    resourceUri: d.resourceUri ? enc(identText(d.resourceUri)) : null,
    detail: d.detail ? enc(messageText(d.detail)) : null,
  };
}

function jsonError(e: ScanError) {
  return {
    code: e.code,
    message: enc(messageText(e.message)),
    resourceUri: e.resourceUri ? enc(identText(e.resourceUri)) : null,
  };
}

function jsonResource(r: ReportResource) {
  return {
    uri: enc(identText(r.uri)),
    contentHash: enc(identText(r.contentHash)),
    mimeType: r.mimeType ? enc(identText(r.mimeType)) : null,
    byteLength: r.byteLength ?? null,
    filePath: r.filePath ? enc(identText(r.filePath)) : null,
  };
}

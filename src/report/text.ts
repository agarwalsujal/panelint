/**
 * The default reporter.
 *
 * Grouped by class so a developer sees SPEC violations before RISK
 * observations — the classification is the product, and a flat list collapses
 * it back into the undifferentiated noise every other scanner emits.
 *
 * Two rules shape the layout beyond taste:
 *
 *   - **Evidence never appears on the summary line.** It goes in a delimited
 *     block with a fixed `|` prefix, one that a reader — or an agent reading a
 *     CI log — can recognise as quoted hostile input rather than as Panelint
 *     speaking. Evidence from the PANE-HIDDEN family is a prompt-injection
 *     payload by construction; that is what the family detects.
 *   - **The footer is not optional.** Suppression counts print even when they
 *     are all zero, and undecided prints its breakdown by cause. Undecided is
 *     not clean, and a suppression you cannot see is one an attacker can use.
 */

import { gatingFindings, isGating } from '../exit.js';
import type { Finding, RuleClass, Severity } from '../types.js';
import {
  CLASS_ORDER,
  DISCLAIMER,
  evidenceText,
  findingsInClass,
  identText,
  limitationFor,
  messageText,
  undecidedByCause,
  type ReportResource,
  type ScanReport,
} from './types.js';

export interface TextOptions {
  /** Force colour on or off. Omitted: derived from the environment. */
  color?: boolean;
  env?: Record<string, string | undefined>;
  isTTY?: boolean;
}

/**
 * Colour decision, extracted so it is testable without a terminal.
 *
 * `NO_COLOR` wins over `FORCE_COLOR`: the user asking for less output always
 * beats a tool asking for more.
 */
export function shouldColor(env: Record<string, string | undefined>, isTTY: boolean): boolean {
  if (env['NO_COLOR']) return false;
  if (env['FORCE_COLOR']) return true;
  return isTTY;
}

// ---------------------------------------------------------------------------

const CODES = {
  reset: '\u001b[0m',
  bold: '\u001b[1m',
  dim: '\u001b[2m',
  red: '\u001b[31m',
  yellow: '\u001b[33m',
  blue: '\u001b[34m',
  cyan: '\u001b[36m',
} as const;

type Paint = (s: string, code: keyof typeof CODES) => string;

const painted: Paint = (s, code) => `${CODES[code]}${s}${CODES.reset}`;
const plain: Paint = (s) => s;

const SEVERITY_COLOR: Readonly<Record<Severity, keyof typeof CODES>> = {
  CRITICAL: 'red',
  HIGH: 'red',
  MEDIUM: 'yellow',
  LOW: 'blue',
  INFO: 'dim',
};

const CLASS_COLOR: Readonly<Record<RuleClass, keyof typeof CODES>> = {
  SPEC: 'red',
  SCHEMA: 'red',
  RISK: 'yellow',
  INFO: 'cyan',
};

// ---------------------------------------------------------------------------

export function renderText(report: ScanReport, opts: TextOptions = {}): string {
  const color =
    opts.color ?? shouldColor(opts.env ?? process.env, opts.isTTY ?? Boolean(process.stdout?.isTTY));
  const c = color ? painted : plain;

  const { header, findings, resources } = report;
  const out: string[] = [];

  // --- header: the point-in-time facts, DESIGN.md §7 ----------------------
  out.push(
    c(
      `panelint ${identText(header.panelintVersion)} · rule-engine ${identText(
        header.ruleEngineFingerprint,
      )} · mode ${header.mode}`,
      'bold',
    ),
  );
  out.push(
    `scanned ${identText(header.scannedAt)} · target ${identText(header.target)} · fail-on ${
      header.failOn
    }`,
  );
  if (header.serverName) {
    out.push(`server ${identText(header.serverName)}${header.serverVersion ? ` ${identText(header.serverVersion)}` : ''}`);
  }

  // Directory mode: the ratio, before anything else can read as a result.
  if (header.mode === 'directory' && header.declaredCount !== undefined) {
    out.push(
      c(
        `resolved ${header.resolvedCount ?? 0} of ${header.declaredCount} declared resources`,
        header.resolvedCount === header.declaredCount ? 'dim' : 'yellow',
      ),
    );
  }

  out.push(`limitation: ${limitationFor(header.mode)}`);
  out.push(c(DISCLAIMER, 'dim'));
  // Unconditional. Zeroes are information too.
  out.push(
    `suppressed: ${header.suppressed.inline} inline · ${header.suppressed.config} config · ${header.suppressed.baseline} baseline`,
  );

  // --- resources -----------------------------------------------------------
  out.push('');
  out.push(c(`resources (${resources.length})`, 'bold'));
  if (resources.length === 0) {
    out.push('  none — no UI resource was read');
  }
  for (const r of resources) {
    out.push(`  ${identText(r.uri)}`);
    out.push(`    sha256 ${identText(r.contentHash)}${where(r)}`);
  }

  // --- findings, grouped by class -----------------------------------------
  for (const cls of CLASS_ORDER) {
    const group = findingsInClass(findings, cls);
    if (group.length === 0) continue;
    out.push('');
    out.push(c(`${cls} — ${count(group.length, 'finding')}`, CLASS_COLOR[cls]));
    for (const f of group) out.push(...renderFinding(f, report, c, header.failOn));
  }

  // --- footer: undecided, diagnostics, errors ------------------------------
  out.push('');
  const causes = undecidedByCause(report.undecided);
  out.push(
    c(
      `undecided: ${report.undecided.length} across ${count(causes.length, 'cause')} — undecided is not clean`,
      report.undecided.length > 0 ? 'yellow' : 'dim',
    ),
  );
  for (const cause of causes) {
    out.push(`  ${cause.ruleId}  ×${cause.count}  ${messageText(cause.reason)}`);
  }

  out.push(`diagnostics: ${report.diagnostics.length}`);
  for (const d of report.diagnostics) {
    const uri = d.resourceUri ? `  ${identText(d.resourceUri)}` : '';
    out.push(`  ${d.code}${uri}  ${messageText(d.message)}`);
  }

  out.push(c(`errors: ${report.errors.length}`, report.errors.length > 0 ? 'red' : 'dim'));
  for (const e of report.errors) {
    const uri = e.resourceUri ? `  ${identText(e.resourceUri)}` : '';
    out.push(`  ${e.code}${uri}  ${messageText(e.message)}`);
  }

  // --- summary -------------------------------------------------------------
  const gating = gatingFindings(findings, header.failOn).length;
  out.push('');
  out.push(
    c(
      `${findings.length} findings reported · ${gating} gate at --fail-on ${header.failOn}`,
      gating > 0 ? 'red' : 'bold',
    ),
  );

  return `${out.join('\n')}\n`;
}

// ---------------------------------------------------------------------------

function renderFinding(
  f: Finding,
  report: ScanReport,
  c: Paint,
  failOn: Severity,
): string[] {
  const lines: string[] = [];
  const gates = isGating(f, failOn);

  // Summary line. Rule id, the three axes, and whether it gates. No evidence.
  lines.push(
    `  ${c(f.ruleId, 'bold')}  ${c(f.severity, SEVERITY_COLOR[f.severity])}  ${f.confidence}${
      f.experimental ? '  experimental' : ''
    }${gates ? c('  gating', 'red') : ''}`,
  );
  lines.push(`    ${locationLabel(f, report)}`);
  lines.push(`    ${messageText(f.message)}`);
  if (f.jsonPointer) lines.push(`    at ${identText(f.jsonPointer)}`);
  if (f.assumption) lines.push(`    ${c(`assumption: ${messageText(f.assumption)}`, 'dim')}`);

  // Evidence, delimited and prefixed. Never on the line above.
  if (f.evidence !== undefined && f.evidence !== '') {
    lines.push(`    ${c('+-- evidence (untrusted, escaped) --', 'dim')}`);
    lines.push(`    | ${evidenceText(f.evidence)}`);
    lines.push(`    ${c('+-- end evidence --', 'dim')}`);
  }
  return lines;
}

/** `path:line:col` when the resource is on disk, the `ui://` URI otherwise. */
function locationLabel(f: Finding, report: ScanReport): string {
  const resource = report.resources.find((r) => r.uri === f.resourceUri);
  const base = resource?.filePath ? identText(resource.filePath) : identText(f.resourceUri);
  if (!f.location) return base;
  return `${base}:${f.location.startLine}:${f.location.startCol}`;
}

function where(r: ReportResource): string {
  const parts: string[] = [];
  if (r.filePath) parts.push(identText(r.filePath));
  if (r.mimeType) parts.push(identText(r.mimeType));
  if (r.byteLength !== undefined) parts.push(`${r.byteLength} bytes`);
  return parts.length > 0 ? `  ${parts.join('  ')}` : '';
}

function count(n: number, noun: string): string {
  return `${n} ${noun}${n === 1 ? '' : 's'}`;
}

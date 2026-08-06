#!/usr/bin/env node
/**
 * The Panelint command line.
 *
 *   panelint scan <target> [--format text|json|sarif] [--fail-on <severity>]
 *                          [--experimental] [--allow-spawn] [--on-error fail|warn]
 *                          [--baseline <file>]
 *   panelint capture <target> -o <file.json>
 *   panelint rules [--json]
 *
 * This file only wires stages together. Every decision it appears to make is
 * made somewhere else on purpose: the gate formula lives in src/exit.ts, the
 * suppression trust model in src/config/suppress.ts, and the mode limitation
 * sentences in src/report/types.ts. A CLI that re-derives any of those is how
 * three documents ended up specifying three different gates.
 */

import { Command } from 'commander';
import { readFileSync, statSync } from 'node:fs';
import { resolve as resolvePath } from 'node:path';

import { scanDirectory } from './acquire/directory.js';
import { loadCapture, captureFromResourceSet, writeCapture } from './acquire/capture.js';
import { acquireStdio } from './acquire/stdio.js';
import { ruleEngineFingerprint } from './acquire/hash.js';
import { analyzeResourceSet } from './analyze.js';
import { ALL_RULES, selectRules } from './rules/registry.js';
import { loadConfig } from './config/load.js';
import { applySuppressions } from './config/suppress.js';
import { loadBaseline } from './config/baseline.js';
import { renderText } from './report/text.js';
import { renderJson } from './report/json.js';
import { renderSarif } from './report/sarif.js';
import { selectExitCode, type OnError } from './exit.js';
import { resolveLimits } from './limits.js';
import { ALL_SEVERITIES, type ResourceSet, type RuleMeta, type Severity } from './types.js';
import type { ReportResource, ScanReport, ScanMode } from './report/types.js';

const PKG = JSON.parse(
  readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
) as { version: string; dependencies?: Record<string, string> };

const program = new Command();

program
  .name('panelint')
  .description(
    'Static analyzer for MCP Apps (SEP-1865) UI resources.\n' +
      'Reports properties of a content hash at a point in time. It never says a server is safe.',
  )
  .version(PKG.version);

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------

program
  .command('scan')
  .argument('[target]', 'a directory to scan, or a capture file to replay')
  .option('--stdio', 'scan a live server; the command follows a literal `--`', false)
  .option(
    '--allow-spawn',
    'permit spawning the target server. This runs someone else\'s program, ' +
      'possibly in CI with credentials in the environment, so it is never implied.',
    false,
  )
  .option('--show-server-stderr', 'surface the server\'s stderr, control-stripped and capped', false)
  .option('--format <format>', 'text | json | sarif', 'text')
  .option('--fail-on <severity>', 'critical | high | medium | low | info', 'high')
  .option('--on-error <mode>', 'fail | warn — how a scan error affects the exit code', 'fail')
  .option('--experimental', 'include experimental rules (they never affect the exit code)', false)
  .option('--baseline <file>', 'a baseline file of accepted findings')
  .option('--config <file>', 'a config file (default: panelint.config.json)')
  .option(
    '--path-prefix <path>',
    'prepend this to every file path in SARIF output. File paths are relative to the ' +
      'scan root, but GitHub resolves SARIF paths against the repository root — set this ' +
      'to the scan root when they differ, or alerts point at paths that do not exist.',
  )
  .option('--no-color', 'disable coloured output')
  .option(
    '--trust-inline-suppressions',
    'honour panelint-disable comments in non-directory sources. Off by default: those ' +
      'comments live in the byte stream the threat model treats as hostile.',
    false,
  )
  .option('--allow-repo-config', 'let a config file in the scanned tree lower severities', false)
  // The server command after `--` is read from process.argv, not from
  // commander's operands. Without this, commander rejects it as excess.
  .allowExcessArguments(true)
  .action(async (target: string | undefined, opts: Record<string, unknown>) => {
    process.exitCode = await runScan(target, opts);
  });

async function runScan(
  target: string | undefined,
  opts: Record<string, unknown>,
): Promise<0 | 1 | 2> {
  const failOn = parseSeverity(String(opts['failOn'] ?? 'high'));
  const onError = parseOnError(String(opts['onError'] ?? 'fail'));
  const format = String(opts['format'] ?? 'text');
  const pathPrefix = parsePathPrefix(opts['pathPrefix']);
  const limits = resolveLimits();

  // ── Acquire ────────────────────────────────────────────────────────────
  const live = Boolean(opts['stdio']);
  let set: ResourceSet;
  const absolute = target ? resolvePath(target) : process.cwd();

  try {
    if (live) {
      set = await acquireLive(opts);
    } else if (!target) {
      process.stderr.write('panelint: scan needs a target directory or capture file.\n');
      return 2;
    } else {
      set = isDirectory(absolute)
        ? scanDirectory(absolute, { limits })
        : loadCapture(absolute, { limits });
    }
  } catch (e) {
    process.stderr.write(
      `panelint: ${e instanceof Error ? e.message : 'could not acquire the target'}\n`,
    );
    return 2;
  }

  // ── Analyze ────────────────────────────────────────────────────────────
  const rules = selectRules({ experimental: Boolean(opts['experimental']) });
  const analysis = analyzeResourceSet(set, rules, { limits });

  // ── Config, overrides, suppression ─────────────────────────────────────
  const config = loadConfig({
    root: !live && isDirectory(absolute) ? absolute : process.cwd(),
    ...(opts['config'] ? { configPath: String(opts['config']) } : {}),
    allowRepoConfig: Boolean(opts['allowRepoConfig']),
    trustInlineSuppressions: Boolean(opts['trustInlineSuppressions']),
  });

  // A baseline that fails to load is a scan error, not an empty baseline —
  // silently proceeding with zero accepted findings would re-report everything
  // and train the operator to ignore the output.
  const loadedBaseline = opts['baseline'] ? loadBaseline(String(opts['baseline'])) : null;
  if (loadedBaseline?.fatal) {
    process.stderr.write('panelint: the baseline file could not be read.\n');
    return 2;
  }
  const baseline = loadedBaseline?.entries ?? [];

  const suppression = applySuppressions({
    findings: analysis.findings,
    resources: set.resources,
    config,
    baseline,
  });

  // ── Report ─────────────────────────────────────────────────────────────
  const diagnostics = [...set.diagnostics, ...analysis.diagnostics];
  const errors = [...set.errors, ...analysis.errors];

  const report: ScanReport = {
    header: {
      panelintVersion: PKG.version,
      ruleEngineFingerprint: ruleEngineFingerprint({
        ruleIds: ALL_RULES.map((r: RuleMeta) => r.id),
        panelintVersion: PKG.version,
        cspEvaluatorVersion: PKG.dependencies?.['csp_evaluator'] ?? 'unknown',
        tldtsVersion: PKG.dependencies?.['tldts'] ?? 'unknown',
        schemaVersion: readSchemaVersion(),
      }),
      mode: set.source as ScanMode,
      scannedAt: set.scannedAt,
      target: target ?? spawnArgvAfterDoubleDash().join(' ') ?? '(live)',
      ...(set.serverName ? { serverName: set.serverName } : {}),
      ...(set.serverVersion ? { serverVersion: set.serverVersion } : {}),
      ...(set.protocolVersion ? { protocolVersion: set.protocolVersion } : {}),
      failOn,
      suppressed: suppression.counts,
      ...(set.resolvedCount !== undefined ? { resolvedCount: set.resolvedCount } : {}),
      ...(set.declaredCount !== undefined ? { declaredCount: set.declaredCount } : {}),
      ...(pathPrefix ? { pathPrefix } : {}),
    },
    resources: set.resources.map((r): ReportResource => ({
      uri: r.uri,
      contentHash: r.contentHash,
      mimeType: r.mimeType,
      byteLength: Buffer.byteLength(r.content, 'utf8'),
      ...(r.filePath ? { filePath: r.filePath } : {}),
    })),
    findings: suppression.findings,
    undecided: analysis.undecided,
    diagnostics,
    errors,
  };

  // `--no-color` sets opts.color to false; absent, it is undefined. Pass the
  // undefined through rather than defaulting to true, so renderText falls back
  // to shouldColor() and honours NO_COLOR, FORCE_COLOR, and whether stdout is a
  // TTY. Collapsing this to a definite boolean here made that fallback
  // unreachable, which put ANSI escapes into every redirected report file and
  // into the GitHub Action's job summary.
  const color = opts['color'] === false ? false : undefined;
  process.stdout.write(renderReport(report, format, color));

  return selectExitCode(suppression.findings, errors, failOn, onError);
}

function renderReport(report: ScanReport, format: string, color: boolean | undefined): string {
  switch (format) {
    case 'json':
      return renderJson(report) + '\n';
    case 'sarif':
      return renderSarif(report, ALL_RULES) + '\n';
    case 'text':
      return renderText(report, { color });
    default:
      throw new Error(`Unknown format: ${format}`);
  }
}

/** Spawn and scan a live server over stdio. */
async function acquireLive(opts: Record<string, unknown>): Promise<ResourceSet> {
  const { command, args } = requireSpawnTarget(spawnArgvAfterDoubleDash());
  return acquireStdio({
    command,
    args,
    // CLI-only, and checked at the point of spawn. A config file inside the
    // scanned repository must never be able to set this.
    allowSpawn: Boolean(opts['allowSpawn']),
    showServerStderr: Boolean(opts['showServerStderr']),
    limits: resolveLimits(),
    echo: (line) => process.stderr.write(`panelint: ${line}\n`),
  });
}

// ---------------------------------------------------------------------------
// capture
// ---------------------------------------------------------------------------

program
  .command('capture')
  .description('record a live server to a replayable JSON file — CI replays this, never spawns')
  .requiredOption('-o, --output <file>', 'where to write the capture')
  .option('--stdio', 'record over stdio; the command follows a literal `--`', true)
  .option('--allow-spawn', 'permit spawning the target server', false)
  .option('--show-server-stderr', 'surface the server\'s stderr, control-stripped and capped', false)
  .option('--force', 'overwrite an existing file', false)
  .allowExcessArguments(true)
  .action(async (opts: Record<string, unknown>) => {
    try {
      const set = await acquireLive(opts);

      if (set.errors.length > 0) {
        for (const e of set.errors) process.stderr.write(`panelint: ${e.message}\n`);
        process.exitCode = 2;
        return;
      }

      const capture = captureFromResourceSet(set, set.scannedAt);
      writeCapture(String(opts['output']), capture, { force: Boolean(opts['force']) });

      process.stderr.write(
        `panelint: recorded ${set.resources.length} resource(s) and ` +
          `${set.tools.length} tool(s) to ${String(opts['output'])}\n`,
      );
      process.exitCode = 0;
    } catch (e) {
      process.stderr.write(`panelint: ${e instanceof Error ? e.message : 'capture failed'}\n`);
      process.exitCode = 2;
    }
  });

// ---------------------------------------------------------------------------
// rules
// ---------------------------------------------------------------------------

program
  .command('rules')
  .description('list the rule registry — the machine-readable source of truth')
  .option('--json', 'emit JSON', false)
  .action((opts: Record<string, unknown>) => {
    if (opts['json']) {
      process.stdout.write(
        JSON.stringify(
          ALL_RULES.map((r: RuleMeta) => ({
            id: r.id,
            class: r.ruleClass,
            severity: r.severity,
            confidence: r.confidence,
            title: r.title,
            experimental: r.experimental,
            status: r.status,
            since: r.since,
            ...(r.specRef ? { specRef: r.specRef } : {}),
            ...(r.cwe ? { cwe: r.cwe } : {}),
            remediation: r.remediation,
          })),
          null,
          2,
        ) + '\n',
      );
      return;
    }

    const pad = (s: string, n: number) => s.padEnd(n);
    process.stdout.write(
      `${pad('ID', 22)}${pad('CLASS', 8)}${pad('SEVERITY', 10)}${pad('CONF', 9)}TITLE\n`,
    );
    for (const r of ALL_RULES as RuleMeta[]) {
      const flag = r.experimental ? ' (experimental)' : '';
      process.stdout.write(
        `${pad(r.id, 22)}${pad(r.ruleClass, 8)}${pad(r.severity, 10)}${pad(r.confidence, 9)}${r.title}${flag}\n`,
      );
    }
    process.stdout.write(`\n${ALL_RULES.length} rules.\n`);
  });

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * The argv after a literal `--`.
 *
 * A spawn target is taken as a pre-split ARRAY, never as one string that this
 * process splits. Splitting a command line means either breaking on paths with
 * spaces or handing the shell a string a config file could have supplied — and
 * `docs/DESIGN.md` §10 forbids `shell: true` under any flag. Reading the raw
 * `process.argv` tail keeps the boundary unambiguous.
 */
function spawnArgvAfterDoubleDash(): string[] {
  const i = process.argv.indexOf('--');
  return i === -1 ? [] : process.argv.slice(i + 1);
}

function requireSpawnTarget(argv: string[]): { command: string; args: string[] } {
  const [command, ...args] = argv;
  if (!command) {
    throw new Error(
      'a live scan needs a server command after `--`, e.g.\n' +
        '  panelint scan --stdio --allow-spawn -- node ./dist/server.js',
    );
  }
  return { command, args };
}

function isDirectory(p: string): boolean {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

function parseSeverity(value: string): Severity {
  const upper = value.toUpperCase() as Severity;
  if (!ALL_SEVERITIES.includes(upper)) {
    throw new Error(`--fail-on must be one of ${ALL_SEVERITIES.join(', ').toLowerCase()}`);
  }
  return upper;
}

function parseOnError(value: string): OnError {
  if (value !== 'fail' && value !== 'warn') throw new Error('--on-error must be fail or warn');
  return value;
}

/**
 * Normalize `--path-prefix` to a bare relative path, or refuse it.
 *
 * The value ends up prepended to SARIF `artifactLocation.uri`, which lands in
 * someone's code scanning alerts. `repoRelativeUri` validates the joined path
 * and would silently drop the location if the prefix were absolute or
 * traversing — a finding rendered without source context, with no explanation.
 * Failing here instead makes the mistake visible at the point it was made.
 */
function parsePathPrefix(raw: unknown): string | undefined {
  if (raw === undefined || raw === null) return undefined;
  const value = String(raw).replace(/\\/g, '/').replace(/^\.\//, '').replace(/\/+$/, '');
  if (value === '' || value === '.') return undefined;
  if (value.startsWith('/') || /^[A-Za-z]:/.test(value) || value.startsWith('~')) {
    throw new Error('--path-prefix must be a relative path inside the repository');
  }
  if (value.split('/').includes('..')) {
    throw new Error('--path-prefix must not traverse upward');
  }
  if (value.includes('\0')) throw new Error('--path-prefix must not contain a null byte');
  return value;
}

function readSchemaVersion(): string {
  try {
    return readFileSync(new URL('../schema/VERSION', import.meta.url), 'utf8').trim();
  } catch {
    return 'unknown';
  }
}

program.parseAsync(process.argv).catch((e: unknown) => {
  process.stderr.write(`panelint: ${e instanceof Error ? e.message : 'error'}\n`);
  process.exitCode = 2;
});

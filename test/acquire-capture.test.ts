import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, rmSync, writeFileSync, symlinkSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

import {
  loadCapture,
  parseCaptureText,
  writeCapture,
  buildCaptureFile,
} from '../src/acquire/capture.js';
import { CaptureError, CAPTURE_FORMAT_VERSION } from '../src/acquire/types.js';
import { sha256Resource } from '../src/acquire/hash.js';
import { resolveLimits } from '../src/limits.js';

const fixture = (name: string) => fileURLToPath(new URL(`../fixtures/capture/${name}`, import.meta.url));

const BOARD_HTML = '<!DOCTYPE html><html><body><h1>board</h1></body></html>';

describe('loadCapture — the happy path carries everything the rules need', () => {
  const set = loadCapture(fixture('valid.json'));

  it('reports source: capture', () => {
    expect(set.source).toBe('capture');
  });

  it('retains the initialize result: capabilities and declared extension mimeTypes', () => {
    // PANE-SPEC-007 dies without these.
    expect(set.serverName).toBe('fixture-server');
    expect(set.serverVersion).toBe('0.0.1');
    expect(set.protocolVersion).toBe('2026-01-26');
    expect(set.declaresUiExtension).toBe(true);
    expect(set.declaredMimeTypes).toEqual(['text/html;profile=mcp-app']);
  });

  it('retains tools/list with _meta, including the deprecated flat key', () => {
    // Six rules die without tools.
    expect(set.tools).toHaveLength(1);
    const tool = set.tools[0]!;
    expect(tool.name).toBe('render_board');
    expect(tool.meta?.resourceUri).toBe('ui://fixture/board.html');
    // PANE-SPEC-006/011 compares the flat key against the modern one; the SDK
    // dual-writes it, so it must remain visible rather than be normalised away.
    expect(tool.rawMeta?.['ui/resourceUri']).toBe('ui://fixture/board.html');
    expect(tool.annotations?.readOnlyHint).toBe(true);
  });

  it('retains BOTH _meta.ui sources separately — PANE-SPEC-010 is invisible otherwise', () => {
    const board = set.resources.find((r) => r.uri === 'ui://fixture/board.html')!;
    expect(board.metaFromList?.csp?.connectDomains).toEqual(['https://api.fixture.test']);
    expect(board.metaFromRead?.csp?.connectDomains).toEqual([
      'https://api.fixture.test',
      'https://telemetry.fixture.test',
    ]);
    // read wins, per ext-apps McpUiAppResourceConfig
    expect(board.meta).toBe(board.metaFromRead);
  });

  it('keeps listedMimeType alongside the read mimeType', () => {
    const board = set.resources.find((r) => r.uri === 'ui://fixture/board.html')!;
    expect(board.mimeType).toBe('text/html;profile=mcp-app');
    expect(board.listedMimeType).toBe('text/html;profile=mcp-app');
  });

  it('recomputes contentHash rather than trusting the capture', () => {
    const board = set.resources.find((r) => r.uri === 'ui://fixture/board.html')!;
    expect(board.content).toBe(BOARD_HTML);
    expect(board.contentHash).toBe(sha256Resource({ text: BOARD_HTML }));
  });

  it('decodes a strict base64 blob and hashes the decoded bytes', () => {
    const blob = set.resources.find((r) => r.uri === 'ui://fixture/blob.html')!;
    expect(blob.fromBlob).toBe(true);
    expect(blob.content).toContain('blob resource');
    expect(blob.contentHash).toBe(sha256Resource({ text: blob.content }));
  });

  it('skips a non-ui:// resource without inventing a finding for it', () => {
    expect(set.resources.some((r) => !r.uri.startsWith('ui://'))).toBe(false);
  });

  it('diagnoses a listed resource that was never read', () => {
    const d = set.diagnostics.find((x) => x.resourceUri === 'ui://fixture/never-read.html');
    expect(d?.code).toBe('UNRESOLVED_URI');
  });
});

describe('loadCapture — a capture is hostile input', () => {
  it('NEVER trusts a hash carried in the capture, and says so when it disagrees', () => {
    const set = loadCapture(fixture('hash-lie.json'));
    const r = set.resources[0]!;
    const cleanHash = createHash('sha256').update(BOARD_HTML, 'utf8').digest('hex');
    // The capture claims the hash of a clean resource for content that is not it.
    expect(r.contentHash).not.toBe(cleanHash);
    expect(r.contentHash).toBe(sha256Resource({ text: r.content }));
    const d = set.diagnostics.find((x) => x.code === 'PARSE_FAILED');
    expect(d?.message).toMatch(/hash/i);
  });

  it('refuses a capture carrying a spawn command', () => {
    expect(() => loadCapture(fixture('spawn-command.json'))).toThrow(CaptureError);
    try {
      loadCapture(fixture('spawn-command.json'));
    } catch (e) {
      expect((e as CaptureError).code).toBe('FORBIDDEN_KEY');
      expect((e as CaptureError).message).toMatch(/command/);
    }
  });

  it('refuses lenient base64 rather than hashing an ambiguous blob', () => {
    const set = loadCapture(fixture('loose-base64.json'));
    expect(set.resources).toHaveLength(0);
    expect(set.diagnostics.some((d) => d.code === 'PARSE_FAILED' && /base64/i.test(d.message))).toBe(true);
  });

  it('rejects an unknown top-level key rather than ignoring it', () => {
    const text = JSON.stringify({ ...minimal(), futureField: { anything: true } });
    expect(() => parseCaptureText(text)).toThrow(/futureField/);
  });

  it('rejects an unsupported format version', () => {
    const text = JSON.stringify({ ...minimal(), panelintCapture: 99 });
    expect(() => parseCaptureText(text)).toThrow(/version/i);
  });

  it('requires toolsList to be present — a missing key is a recording bug, not "no tools"', () => {
    const c = minimal() as unknown as Record<string, unknown>;
    delete c['toolsList'];
    expect(() => parseCaptureText(JSON.stringify(c))).toThrow(/toolsList/);
  });

  it('requires initialize to be present — PANE-SPEC-007 needs capabilities', () => {
    const c = minimal() as unknown as Record<string, unknown>;
    delete c['initialize'];
    expect(() => parseCaptureText(JSON.stringify(c))).toThrow(/initialize/);
  });

  it('refuses a content item carrying both text and blob — the hash would be ambiguous', () => {
    const c = minimal();
    c.resourcesList = [{ uri: 'ui://x/a.html' }];
    c.resourcesRead = [
      { uri: 'ui://x/a.html', contents: [{ uri: 'ui://x/a.html', text: 'a', blob: 'YQ==' }] },
    ];
    const set = parseCaptureText(JSON.stringify(c));
    expect(set.resources).toHaveLength(0);
    expect(set.diagnostics.some((d) => /both/i.test(d.message))).toBe(true);
  });

  it('caps the resource count and says the scan is incomplete', () => {
    const c = minimal();
    c.resourcesList = [];
    c.resourcesRead = [];
    for (let i = 0; i < 5; i++) {
      c.resourcesList.push({ uri: `ui://x/${i}.html` });
      c.resourcesRead.push({ uri: `ui://x/${i}.html`, contents: [{ text: `<p>${i}</p>` }] });
    }
    const set = parseCaptureText(JSON.stringify(c), { limits: resolveLimits({ maxTotalResources: 2 }) });
    expect(set.resources).toHaveLength(2);
    expect(set.diagnostics.some((d) => d.code === 'LIMIT_EXCEEDED')).toBe(true);
  });

  it('drops a resource that exceeds maxResourceBytes with a LIMIT_EXCEEDED diagnostic', () => {
    const c = minimal();
    c.resourcesList = [{ uri: 'ui://x/big.html' }];
    c.resourcesRead = [{ uri: 'ui://x/big.html', contents: [{ text: 'x'.repeat(5_000) }] }];
    const set = parseCaptureText(JSON.stringify(c), { limits: resolveLimits({ maxResourceBytes: 1_000 }) });
    expect(set.resources).toHaveLength(0);
    expect(set.diagnostics.some((d) => d.code === 'LIMIT_EXCEEDED')).toBe(true);
  });

  it('sanitises server-controlled strings at the acquire boundary', () => {
    const c = minimal();
    c.initialize.serverInfo = { name: 'evil\u001b[2Jserver\u200b' };
    c.toolsList = [{ name: 'tool\u001b]52;c;cGF5bG9hZA==\u0007', description: 'desc\r\nOVERWRITE' }];
    const set = parseCaptureText(JSON.stringify(c));
    // Escaped, not stripped: the evidence survives, inert in every sink.
    expect(set.serverName).not.toContain('\u001b');
    expect(set.serverName).toContain('\\u001b');
    expect(set.serverName).toContain('\\u200b');
    expect(set.tools[0]!.name).not.toContain('\u001b');
    expect(set.tools[0]!.description).not.toContain('\r');
    expect(set.tools[0]!.description).toContain('\\u000d');
  });

  it('refuses a capture larger than its ceiling before JSON.parse sees it', () => {
    const dir = mkdtempSync(join(tmpdir(), 'panelint-cap-'));
    try {
      const p = join(dir, 'big.json');
      writeFileSync(p, JSON.stringify(minimal()) + ' '.repeat(4096));
      expect(() => loadCapture(p, { maxCaptureBytes: 64 })).toThrow(/large|size/i);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('reports invalid JSON without echoing the file contents', () => {
    const dir = mkdtempSync(join(tmpdir(), 'panelint-cap-'));
    try {
      const p = join(dir, 'bad.json');
      writeFileSync(p, '{ "secret-looking-content": ');
      let msg = '';
      try {
        loadCapture(p);
      } catch (e) {
        msg = (e as Error).message;
      }
      expect(msg).toMatch(/JSON/i);
      expect(msg).not.toContain('secret-looking-content');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('writeCapture', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'panelint-write-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  const sample = () =>
    buildCaptureFile({
      initialize: { protocolVersion: '2026-01-26', serverInfo: { name: 's' }, capabilities: {} },
      resourcesList: [{ uri: 'ui://x/a.html' }],
      resourcesRead: [{ uri: 'ui://x/a.html', contents: [{ text: '<p>a</p>' }] }],
      toolsList: [],
      capturedAt: '2026-08-05T00:00:00.000Z',
    });

  it('writes a round-trippable capture at mode 0600', () => {
    const p = join(dir, 'panelint.capture.json');
    writeCapture(p, sample());
    expect(statSync(p).mode & 0o777).toBe(0o600);
    const set = loadCapture(p);
    expect(set.resources[0]!.uri).toBe('ui://x/a.html');
    expect(JSON.parse(readFileSync(p, 'utf8')).panelintCapture).toBe(CAPTURE_FORMAT_VERSION);
  });

  it('refuses to overwrite an existing file without force', () => {
    const p = join(dir, 'panelint.capture.json');
    writeFileSync(p, 'keep me');
    expect(() => writeCapture(p, sample())).toThrow(/exists|force/i);
    expect(readFileSync(p, 'utf8')).toBe('keep me');
  });

  it('refuses a pre-planted symlink, with force and without', () => {
    // A hostile repo can plant panelint.capture.json -> ~/.zshrc before CI runs.
    const target = join(dir, 'precious');
    writeFileSync(target, 'precious');
    const p = join(dir, 'panelint.capture.json');
    symlinkSync(target, p);

    expect(() => writeCapture(p, sample())).toThrow();
    expect(() => writeCapture(p, sample(), { force: true })).toThrow(/symlink/i);
    expect(readFileSync(target, 'utf8')).toBe('precious');
  });

  it('overwrites a regular file when force is explicit', () => {
    const p = join(dir, 'panelint.capture.json');
    writeFileSync(p, 'old');
    writeCapture(p, sample(), { force: true });
    expect(loadCapture(p).resources).toHaveLength(1);
  });

  it('refuses to build a capture carrying a forbidden key', () => {
    expect(() =>
      buildCaptureFile({
        initialize: {},
        resourcesList: [],
        resourcesRead: [],
        toolsList: [],
        // @ts-expect-error — the point of the test is that this is rejected at runtime too
        command: 'node ./evil.js',
      }),
    ).toThrow(/command/);
  });
});

interface MinimalCapture {
  panelintCapture: number;
  initialize: { capabilities?: Record<string, unknown>; serverInfo?: { name?: string; version?: string } };
  resourcesList: Array<Record<string, unknown>>;
  resourcesRead: Array<{ uri: string; contents: Array<Record<string, unknown>> }>;
  toolsList: Array<Record<string, unknown>>;
}

function minimal(): MinimalCapture {
  return {
    panelintCapture: CAPTURE_FORMAT_VERSION,
    initialize: { capabilities: {}, serverInfo: { name: 'fixture', version: '1' } },
    resourcesList: [],
    resourcesRead: [],
    toolsList: [],
  };
}

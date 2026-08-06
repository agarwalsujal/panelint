import { describe, it, expect } from 'vitest';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, isAbsolute } from 'node:path';

import { scanDirectory } from '../src/acquire/directory.js';
import { sha256Resource } from '../src/acquire/hash.js';
import { MCP_APP_MIME } from '../src/acquire/types.js';

const BASIC = fileURLToPath(new URL('../fixtures/dirscan/basic', import.meta.url));

describe('scanDirectory — detection order from DESIGN.md §3.1', () => {
  const set = scanDirectory(BASIC);
  const byUri = (u: string) => set.resources.find((r) => r.uri === u);

  it('reports source: directory', () => {
    expect(set.source).toBe('directory');
  });

  it('finds the spec-mandated MIME literal in any language', () => {
    // Step 1. The literal appears in JS, Python and Go fixtures alike.
    expect(byUri('ui://demo/board.html')?.mimeType).toBe(MCP_APP_MIME);
  });

  it('resolves (a) a sibling file whose path tail matches the URI path', () => {
    const r = byUri('ui://demo/board.html')!;
    expect(r.content).toContain('<h1>Board</h1>');
    expect(r.filePath).toBe('demo/board.html');
    expect(r.contentHash).toBe(sha256Resource({ text: r.content }));
  });

  it('resolves (b) a string/heredoc literal in the same file that parses as HTML', () => {
    const r = byUri('ui://demo/inline')!;
    expect(r.content).toContain('inline literal');
    expect(r.filePath).toBe('src/inline_server.py');
  });

  it('resolves (c) a readFile call with a literal path argument', () => {
    const r = byUri('ui://demo/loaded')!;
    expect(r.content).toContain('loaded from a literal path');
    expect(r.filePath).toBe('templates/loaded.html');
  });

  it('emits UNRESOLVED_URI — a diagnostic, never a finding — for runtime-built HTML', () => {
    expect(byUri('ui://demo/dynamic')).toBeUndefined();
    const d = set.diagnostics.find((x) => x.resourceUri === 'ui://demo/dynamic');
    expect(d?.code).toBe('UNRESOLVED_URI');
    expect(d?.message).toMatch(/declared, content not statically resolvable/i);
  });

  it('carries the resolved/declared ratio — 2 of 9 is not a clean bill of health', () => {
    expect(set.declaredCount).toBeGreaterThan(0);
    expect(set.resolvedCount).toBe(set.resources.length);
    expect(set.resolvedCount!).toBeLessThan(set.declaredCount!);
  });

  it('never walks a denied directory', () => {
    expect(byUri('ui://vendored/never-seen')).toBeUndefined();
    expect(JSON.stringify(set)).not.toContain('never-seen');
  });
});

describe('scanDirectory — the source it reads is attacker-controlled', () => {
  const set = scanDirectory(BASIC);

  it('does NOT resolve an absolute path in a readFile call', () => {
    // `const html = readFileSync("/home/runner/.ssh/id_rsa")` must not resolve.
    expect(set.resources.find((r) => r.uri === 'ui://evil/secret')).toBeUndefined();
    const blob = JSON.stringify(set);
    expect(blob).not.toContain('root:');
    expect(blob).not.toContain('id_rsa');
    expect(blob).not.toContain('/etc/passwd');
  });

  it('emits no absolute host path anywhere in the ResourceSet', () => {
    const blob = JSON.stringify(set);
    expect(blob).not.toContain(BASIC);
    expect(blob).not.toContain('/Users/');
    for (const r of set.resources) expect(isAbsolute(r.filePath!)).toBe(false);
  });

  it('refuses a symlink that escapes the root', () => {
    const outside = mkdtempSync(join(tmpdir(), 'panelint-outside-'));
    const root = mkdtempSync(join(tmpdir(), 'panelint-root-'));
    try {
      writeFileSync(join(outside, 'secret.html'), '<html><body>SECRET</body></html>');
      writeFileSync(
        join(root, 'server.js'),
        `const mime = "${MCP_APP_MIME}";\nconst uri = "ui://demo/leak.html";\n`,
      );
      symlinkSync(join(outside, 'secret.html'), join(root, 'leak.html'));
      mkdirSync(join(root, 'demo'));
      symlinkSync(join(outside, 'secret.html'), join(root, 'demo/leak.html'));

      const s = scanDirectory(root);
      expect(JSON.stringify(s)).not.toContain('SECRET');
      expect(s.resources).toHaveLength(0);
      expect(s.diagnostics.some((d) => d.code === 'UNRESOLVED_URI')).toBe(true);
    } finally {
      rmSync(outside, { recursive: true, force: true });
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('does NOT populate meta from scraped source — a README placeholder is not a declaration', () => {
    // Measured: 3 of 21 servers' only apparent `_meta.ui.csp` declarations were
    // `https://api.example.com` placeholders in READMEs, tests and doc snippets.
    for (const r of set.resources) {
      expect(r.meta).toBeUndefined();
      expect(r.metaFromList).toBeUndefined();
      expect(r.metaFromRead).toBeUndefined();
    }
    expect(JSON.stringify(set)).not.toContain('api.example.com');
  });

  it('declares no tools — directory mode cannot see a tools/list response', () => {
    expect(set.tools).toEqual([]);
  });
});

describe('scanDirectory — DoS budgets', () => {
  it('caps the file count and says the scan is incomplete', () => {
    const set = scanDirectory(BASIC, { maxFiles: 2 });
    expect(set.diagnostics.some((d) => d.code === 'LIMIT_EXCEEDED')).toBe(true);
  });

  it('caps total bytes read', () => {
    const set = scanDirectory(BASIC, { maxTotalBytes: 200 });
    expect(set.diagnostics.some((d) => d.code === 'LIMIT_EXCEEDED')).toBe(true);
    expect(set.resources.length).toBeLessThan(3);
  });

  it('skips a file over the per-file cap rather than throwing', () => {
    const root = mkdtempSync(join(tmpdir(), 'panelint-big-'));
    try {
      writeFileSync(join(root, 'server.js'), 'const uri = "ui://demo/big.html";\n');
      writeFileSync(join(root, 'demo-big.html'), '<html><body>' + 'x'.repeat(50_000) + '</body></html>');
      mkdirSync(join(root, 'demo'));
      writeFileSync(join(root, 'demo/big.html'), '<html><body>' + 'x'.repeat(50_000) + '</body></html>');
      const set = scanDirectory(root, { maxFileBytes: 1_000 });
      expect(set.resources).toHaveLength(0);
      expect(set.diagnostics.some((d) => d.code === 'LIMIT_EXCEEDED')).toBe(true);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('never throws on an unreadable root — it reports', () => {
    const set = scanDirectory(join(tmpdir(), 'panelint-does-not-exist-' + Date.now()));
    expect(set.resources).toEqual([]);
    expect(set.errors.length + set.diagnostics.length).toBeGreaterThan(0);
  });

  it('reports NO_RESOURCES_FOUND on a repository that declares nothing', () => {
    const root = mkdtempSync(join(tmpdir(), 'panelint-empty-'));
    try {
      writeFileSync(join(root, 'index.js'), 'export const x = 1;\n');
      const set = scanDirectory(root);
      expect(set.declaredCount).toBe(0);
      expect(set.diagnostics.some((d) => d.code === 'NO_RESOURCES_FOUND')).toBe(true);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

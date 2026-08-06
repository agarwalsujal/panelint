/**
 * Algorithmic-complexity (ReDoS) regression tests.
 *
 * Each payload below drove a production regex into super-linear backtracking on
 * attacker-controlled input — measured in the tens of seconds on sub-megabyte
 * input, on a scanner whose whole job is to run in CI against untrusted content.
 * The ceilings here are deliberately loose (multiple seconds) so they do not
 * flake on a slow machine; the unfixed code blew straight through them, and the
 * fixed code returns in well under a second.
 *
 * These assert *behaviour under a wall-clock budget*, not exact timings. If one
 * fails, the regex it names has regressed to catastrophic backtracking — do not
 * raise the ceiling to make it pass.
 */
import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { parseHtml } from '../src/parse/html.js';
import { buildStyleIndex } from '../src/parse/style-index.js';
import { collectScripts } from '../src/parse/js.js';
import { DEFAULT_LIMITS } from '../src/limits.js';
import { scanDirectory } from '../src/acquire/directory.js';
import { paneHidden004 } from '../src/rules/hidden/pane-hidden-004.js';
import type { RuleContext, UIResource } from '../src/types.js';

/** The unfixed regexes took 15-30s on these; the fix is sub-second. */
const CEILING_MS = 5000;

function ctxFor(html: string, uri = 'ui://redos/view'): RuleContext {
  const limits = DEFAULT_LIMITS;
  const { dom } = parseHtml(html, limits, uri);
  const styles = buildStyleIndex(dom, limits, uri);
  const scripts = collectScripts(dom, html, limits);
  const resource: UIResource = {
    uri,
    mimeType: 'text/html;profile=mcp-app',
    content: html,
    schemaErrors: [],
    contentHash: 'sha256:test',
    source: 'directory',
  };
  return {
    resource,
    dom,
    styles,
    meta: null,
    schemaErrors: [],
    scripts,
    rawSource: html,
    options: {},
    limits,
    diagnostic() {
      /* not asserted here */
    },
  };
}

describe('ReDoS regression — attacker-controlled input must not blow the CPU budget', () => {
  it('PANE-HIDDEN-004: a background value that is a long run of dashes (200 KB)', () => {
    const html =
      '<html><head><style>p{color:#fff;background:' +
      '-'.repeat(200_000) +
      '}</style></head><body><p>hello world this is some prose text</p></body></html>';
    const start = Date.now();
    paneHidden004.check(ctxFor(html));
    expect(Date.now() - start).toBeLessThan(CEILING_MS);
  });

  it('directory HTML_LITERAL_RE: many unterminated "<html literals in one file (512 KB)', () => {
    const dir = mkdtempSync(join(tmpdir(), 'panelint-redos-'));
    try {
      writeFileSync(join(dir, 'server.js'), '// ui://nowhere/x\n' + '\'"<html \''.repeat(74_898));
      const start = Date.now();
      scanDirectory(dir);
      expect(Date.now() - start).toBeLessThan(CEILING_MS);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

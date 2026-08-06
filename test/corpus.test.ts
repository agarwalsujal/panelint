/**
 * The reference-corpus gate — the project's central credibility claim.
 *
 * GOALS.md G2: **zero false positives on the specification's own reference
 * example servers.** Non-negotiable, because a scanner that flags conformant
 * code is discarded on first run.
 *
 * `fixtures/reference/upstream/` holds the verbatim `mcp-app.html` of every
 * example server in `modelcontextprotocol/ext-apps`, with a MANIFEST recording
 * provenance and a sha256 per file. These are the REAL servers, not
 * reproductions of documented shapes.
 *
 * ## What this test proves, and what it does not
 *
 * It proves no rule GATES on conformant reference markup. It does not prove the
 * rules are right — twelve of the twenty-four files are Vite entry stubs under
 * 400 bytes, so the corpus's real power comes from the dozen substantive ones
 * (pdf-server and debug-server at ~8 KB, map-server, customer-segmentation,
 * system-monitor, transcript, video-resource, budget-allocator, and the
 * vanillajs server). Counting the stubs as evidence would overstate the result,
 * so the assertions below distinguish them.
 *
 * It also cannot see what these servers actually SERVE. They are Vite projects,
 * so `mcp-app.html` is a build entry and the served bundle differs. DESIGN.md
 * §3.1 records that as the strongest argument for leading with live/capture
 * scanning, and it is the reason this corpus is a floor on confidence rather
 * than a ceiling.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';

import { analyzeResourceSet } from '../src/analyze.js';
import { selectRules } from '../src/rules/registry.js';
import { sha256Resource } from '../src/acquire/hash.js';
import { isGating } from '../src/exit.js';
import type { Finding, ResourceSet } from '../src/types.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const CORPUS = join(HERE, '..', 'fixtures', 'reference', 'upstream');

interface Manifest {
  source: string;
  ref: string;
  files: Record<string, { bytes: number; sha256: string }>;
}

const manifest = JSON.parse(
  readFileSync(join(CORPUS, 'MANIFEST.json'), 'utf8'),
) as Manifest;

const servers = readdirSync(CORPUS)
  .filter((f) => f.endsWith('.html'))
  .sort();

/** Below this, the file is a framework entry stub and carries little signal. */
const SUBSTANTIVE_BYTES = 800;

function scan(file: string): { findings: Finding[]; bytes: number } {
  const content = readFileSync(join(CORPUS, file), 'utf8');
  const name = file.replace(/\.html$/, '');
  const set: ResourceSet = {
    resources: [
      {
        uri: `ui://${name}/mcp-app.html`,
        mimeType: 'text/html;profile=mcp-app',
        content,
        contentHash: sha256Resource({ text: content }),
        schemaErrors: [],
        source: 'capture',
      },
    ],
    tools: [],
    diagnostics: [],
    errors: [],
    scannedAt: '2026-08-06T00:00:00.000Z',
    source: 'capture',
  };
  // Experimental rules included deliberately: they must not fire here either,
  // even though the gate formula already prevents them affecting an exit code.
  const result = analyzeResourceSet(set, selectRules({ experimental: true }));
  return { findings: result.findings, bytes: content.length };
}

describe('the corpus is real and pinned', () => {
  it('vendors every example server from ext-apps', () => {
    expect(servers.length).toBeGreaterThanOrEqual(24);
  });

  it('records provenance rather than claiming these are hand-authored', () => {
    expect(manifest.source).toContain('modelcontextprotocol/ext-apps');
    expect(manifest.ref).toBeTruthy();
  });

  it.each(servers)('%s matches its recorded sha256 — the corpus cannot drift silently', (file) => {
    const entry = manifest.files[file];
    expect(entry, `${file} is missing from MANIFEST.json`).toBeDefined();
    const actual = createHash('sha256').update(readFileSync(join(CORPUS, file))).digest('hex');
    expect(actual).toBe(entry!.sha256);
  });

  it('contains enough substantive files to mean something', () => {
    const substantive = servers.filter((f) => manifest.files[f]!.bytes >= SUBSTANTIVE_BYTES);
    // Stubs are kept for completeness but must never be the basis of the claim.
    expect(substantive.length).toBeGreaterThanOrEqual(8);
  });
});

// ---------------------------------------------------------------------------
// The gate itself
// ---------------------------------------------------------------------------

describe('G2 — no rule gates on a conformant reference server', () => {
  it.each(servers)('%s produces zero gate-eligible findings', (file) => {
    const { findings } = scan(file);
    const gating = findings.filter((f) => isGating(f, 'HIGH'));
    expect(
      gating.map((f) => `${f.ruleId} (${f.severity}/${f.confidence}): ${f.message}`),
    ).toEqual([]);
  });

  it('produces zero gating findings across the whole corpus', () => {
    const gating = servers.flatMap((f) => scan(f).findings.filter((x) => isGating(x, 'HIGH')));
    expect(gating).toEqual([]);
  });

  it('gates nothing even at --fail-on medium', () => {
    // A team that tightens the threshold must not be punished for it.
    const gating = servers.flatMap((f) => scan(f).findings.filter((x) => isGating(x, 'MEDIUM')));
    expect(gating.map((f) => `${f.ruleId}: ${f.message}`)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Measured false-positive rate — recorded, not asserted away
// ---------------------------------------------------------------------------

describe('measured non-gating findings', () => {
  /**
   * DESIGN.md §6 splits the corpus: a finding here DEMOTES and DOCUMENTS a
   * rule rather than deleting it. `RISK` means "permitted by the spec, expands
   * attack surface", and a reference server may legitimately do that — so a
   * non-gating finding is a measurement, not a bug.
   */
  it('reports what the corpus produces so the rate is visible, not hidden', () => {
    const perRule = new Map<string, number>();
    for (const file of servers) {
      for (const f of scan(file).findings) {
        perRule.set(f.ruleId, (perRule.get(f.ruleId) ?? 0) + 1);
      }
    }
    // Every one of these must be below the default gate, which the tests above
    // already prove. This assertion pins the SET of rules that fire, so a
    // refactor that makes a new rule start firing on conformant code is a
    // reviewable diff rather than a silent change.
    const firing = [...perRule.keys()].sort();
    expect(firing).toEqual(['PANE-HIDDEN-001', 'PANE-HIDDEN-007', 'PANE-HIDDEN-015', 'PANE-OVERLAY-002']);
  });

  it('keeps every corpus finding at MEDIUM severity or below', () => {
    for (const file of servers) {
      for (const f of scan(file).findings) {
        expect(
          ['MEDIUM', 'LOW', 'INFO'],
          `${file}: ${f.ruleId} fired at ${f.severity}`,
        ).toContain(f.severity);
      }
    }
  });
});

describe('the corpus scan is not vacuous', () => {
  /**
   * The trap this test exists to close: a directory-mode scan of these servers
   * resolves ZERO resources, because they are Vite projects whose declared
   * `ui://` path tail does not match a file on disk. It reports "0 findings",
   * which reads like a pass and proves nothing.
   *
   * So assert that rules actually RAN and actually SAW content.
   */
  it('actually analyses content rather than reporting zero because nothing loaded', () => {
    const substantive = servers.filter((f) => manifest.files[f]!.bytes >= SUBSTANTIVE_BYTES);
    const total = substantive.reduce((n, f) => n + scan(f).findings.length, 0);
    // The substantive files DO produce findings — all non-gating. A corpus that
    // produced nothing at all would mean the harness, not the rules, is clean.
    expect(total).toBeGreaterThan(0);
  });

  it('runs the full ruleset, not a subset', () => {
    expect(selectRules({ experimental: true }).length).toBe(93);
  });
});

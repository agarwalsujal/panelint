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
import { loadCapture } from '../src/acquire/capture.js';
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

// ---------------------------------------------------------------------------
// The half the upstream corpus structurally cannot cover.
// ---------------------------------------------------------------------------

/**
 * `fixtures/reference/conformant/` — conformant *server* shapes, not markup.
 *
 * The upstream corpus is HTML files. `scan()` above builds each one with
 * `tools: []` and no `_meta`, because there is nothing else to build it from.
 * So the 35 rules that require meta, tools, or capabilities never run against
 * conformant input anywhere in this suite — and three of the five hard-guarded
 * never-fire patterns live in exactly that region: `'unsafe-inline'` in the
 * mandated default CSP, the SDK-dual-written `_meta["ui/resourceUri"]`, and
 * PANE-SPEC-010 list/read divergence. `test/never-fire.test.ts` covers those
 * against synthetic literals, which is not the same as covering them against a
 * whole conformant server.
 *
 * **Provenance, stated plainly: these are synthetic.** They are hand-authored
 * captures in the current format, reproducing the shapes recorded in
 * docs/RULES.md § Measured false-positive pass — six of eight reference servers
 * declare no `_meta.ui` at all, two declare `csp`, none declare `domain`, and
 * every SDK-built tool dual-writes the flat `ui/resourceUri`. They are NOT
 * captures of anyone's server, and they carry less evidential weight than
 * `upstream/` because a fixture written by the same person who wrote the rules
 * can accidentally encode the rules' assumptions. They exist to cover a region
 * that would otherwise have no conformant coverage at all.
 *
 * They replace `fixtures/reference/{MANIFEST.json,must-not-fire/,measured/}`,
 * which were written in a superseded capture format that `validateCapture`
 * refuses outright — unloadable by any code path, and describing a corpus that
 * is not the one gating CI.
 */
const CONFORMANT = join(HERE, '..', 'fixtures', 'reference', 'conformant');

const conformantFiles = readdirSync(CONFORMANT)
  .filter((f) => f.endsWith('.json') && f !== 'MANIFEST.json')
  .sort();

function scanConformant(file: string) {
  const set = loadCapture(join(CONFORMANT, file));
  return analyzeResourceSet(set, selectRules({ experimental: true }));
}

describe('G2 — no rule gates on a conformant server shape', () => {
  it('has fixtures to run', () => {
    expect(conformantFiles.length).toBeGreaterThanOrEqual(3);
  });

  for (const file of conformantFiles) {
    it(`${file}: no finding gates`, () => {
      const { findings } = scanConformant(file);
      const gating = findings.filter((f: Finding) => isGating(f, 'INFO'));
      expect(
        gating.map((f) => `${f.ruleId} ${f.severity} ${f.confidence}`),
        `${file} produced a gating finding`,
      ).toEqual([]);
    });

    it(`${file}: no SPEC, SCHEMA or RISK finding at any severity`, () => {
      // Stricter than the gate, matching the upstream must-not-fire rule. A
      // RISK finding here is a rule reading conformant server structure as
      // risky, which is the failure GOALS.md G2 exists to prevent.
      //
      // The field is `ruleClass`. Only the JSON envelope renames it to `class`
      // (src/report/json.ts), and reading `f.class` here gave undefined — so
      // the filter kept every finding and this test asserted zero findings of
      // ANY class, the opposite of what the comment above says. It passed only
      // because all three fixtures happen to produce nothing.
      const { findings } = scanConformant(file);
      const classed = findings.filter((f: Finding) => f.ruleClass !== 'INFO');
      expect(
        classed.map((f) => `${f.ruleId} (${f.ruleClass}/${f.severity})`),
        `${file} produced a non-INFO finding`,
      ).toEqual([]);
    });
  }
});

describe('the conformant captures are not vacuous', () => {
  /**
   * The trap: a capture that failed to populate `_meta`, tools, or capabilities
   * would skip the very rules this set exists to cover, report zero findings,
   * and read as a pass. Assert the rules RAN.
   */
  for (const file of conformantFiles) {
    it(`${file}: skips no rule for missing meta, tools, or capabilities`, () => {
      const { skipped } = scanConformant(file);
      expect(
        skipped.map((s) => s.message),
        `${file} skipped rules — the capture is not supplying what it should`,
      ).toEqual([]);
    });
  }

  it('covers the region the upstream HTML corpus cannot', () => {
    // The upstream corpus builds resources with tools: [] and no _meta, so
    // these rule families never see conformant input there. If this ever drops
    // to zero, the conformant set has stopped doing its job.
    const ran = scanConformant(conformantFiles[0]!);
    expect(ran.skipped).toEqual([]);

    const metaDependent = selectRules({ experimental: true }).filter((r) =>
      (r.requires ?? []).some((req: string) =>
        ['meta', 'tools', 'capabilities'].includes(req),
      ),
    );
    expect(metaDependent.length).toBeGreaterThan(20);
  });
});

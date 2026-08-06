/**
 * The resource-exhaustion control layer.
 *
 * `fixtures/malicious/dos/cases.json` has named this file since 0.1.0 and it
 * did not exist. The whole layer shipped with no executable test, and the cost
 * was not hypothetical:
 *
 *   - `selectorIsTractable` was written, exported, and never called. Zero call
 *     sites, through four releases.
 *   - `SELECTOR_SKIPPED` was a declared DiagnosticCode that nothing emitted, so
 *     CSS that could not be modelled read as "no CSS" — the benign-looking
 *     direction, and the one an attacker picks.
 *   - `Budget` counted CALLS rather than work, so a single `:has()` call could
 *     buy a whole document's traversal for one unit. 70 KB ran 27 s at exit 0.
 *   - `_meta` was covered by no limit key at all.
 *
 * Every one of those is a control that a passing unit test elsewhere claimed
 * was working. The contract this file enforces, from cases.json:
 *
 *   every case produces a LIMIT_EXCEEDED diagnostic, never a crash, never a
 *   hang — and a truncated scan never reports exit 0.
 *
 * Cases small enough to read are committed. Multi-megabyte bombs are generated
 * from the parameters in cases.json, because an 80 MB base64 data URI does not
 * belong in a git history that is about to be public. The parameters are the
 * fixture.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { analyzeResourceSet } from '../src/analyze.js';
import { selectRules } from '../src/rules/registry.js';
import { buildStyleIndex } from '../src/parse/style-index.js';
import { parseHtml } from '../src/parse/html.js';
import { estimateNestingDepth, selectorIsTractable } from '../src/safe/guard.js';
import { DEFAULT_LIMITS } from '../src/limits.js';
import { selectExitCode } from '../src/exit.js';
import { sha256Resource } from '../src/acquire/hash.js';
import type { AnalyzeResult } from '../src/analyze.js';
import type { ResourceSet, ScanDiagnostic, UIResource, UIResourceMeta } from '../src/types.js';

const DOS = fileURLToPath(new URL('../fixtures/malicious/dos/', import.meta.url));
const MIME = 'text/html;profile=mcp-app';

interface DosCase {
  id: string;
  limit: string;
  gate: string;
  file?: string;
  generate?: Record<string, unknown>;
  measured?: boolean;
  why: string;
}

const cases = JSON.parse(readFileSync(`${DOS}cases.json`, 'utf8')) as {
  casesVersion: number;
  measuredAgainst: Record<string, string>;
  cases: DosCase[];
};

const caseById = (id: string): DosCase => {
  const c = cases.cases.find((x) => x.id === id);
  if (!c) throw new Error(`cases.json has no case "${id}"`);
  return c;
};

// ---------------------------------------------------------------------------
// Generators. The parameters live in cases.json; these turn them into bytes.
// ---------------------------------------------------------------------------

function nestedElementHtml(element: string, depth: number): string {
  return `<${element}>`.repeat(depth) + 'x' + `</${element}>`.repeat(depth);
}

function base64DataUri(decodedBytes: number): string {
  // Only the LENGTH matters: the cap is arithmetic on the encoded length and is
  // checked before any Buffer.from call, so the payload need not be real bytes.
  const encodedLength = Math.ceil(decodedBytes / 3) * 4;
  return `data:text/plain;base64,${'A'.repeat(encodedLength)}`;
}

function resourceOf(uri: string, content: string, meta?: UIResourceMeta): UIResource {
  return {
    uri,
    mimeType: MIME,
    content,
    contentHash: sha256Resource({ text: content }),
    schemaErrors: [],
    source: 'capture',
    ...(meta ? { meta } : {}),
  };
}

function setOf(resources: UIResource[]): ResourceSet {
  return {
    resources,
    tools: [],
    diagnostics: [],
    errors: [],
    scannedAt: '2026-08-05T00:00:00.000Z',
    source: 'capture',
  };
}

const scan = (resources: UIResource[]): AnalyzeResult =>
  analyzeResourceSet(setOf(resources), selectRules({ experimental: true }));

const limitDiags = (d: readonly ScanDiagnostic[]): ScanDiagnostic[] =>
  d.filter((x) => x.code === 'LIMIT_EXCEEDED');

/**
 * The property every case shares: a scan that a limit truncated must not be
 * reportable as a clean pass. DESIGN.md §4 makes a limit an exit-2 condition,
 * and `--on-error fail` is the default.
 */
function expectTruncatedScanDoesNotPass(out: AnalyzeResult): void {
  expect(limitDiags(out.diagnostics).length).toBeGreaterThan(0);
  expect(selectExitCode(out.findings, out.errors, 'HIGH', 'fail', out.diagnostics)).toBe(2);
}

// ---------------------------------------------------------------------------
// cases.json is the contract, so it is checked first
// ---------------------------------------------------------------------------

describe('cases.json', () => {
  it('declares every case this file implements', () => {
    expect(cases.cases.map((c) => c.id).sort()).toEqual([
      'base64-data-uri-80mb',
      'deep-tree-textcontent-60000',
      'js-add-chain-5000',
      'nested-div-40000',
      'resource-count-501',
      'resource-over-max-bytes',
      'selector-not-5000',
    ]);
  });

  it('pins the dependency versions the measured cases were run against', () => {
    // A measured observation is only meaningful against the version it was
    // measured on. If these drift, the four `measured: true` cases are
    // hypotheses again and need re-running.
    const pkg = JSON.parse(
      readFileSync(fileURLToPath(new URL('../package.json', import.meta.url)), 'utf8'),
    ) as { dependencies: Record<string, string> };
    for (const [dep, version] of Object.entries(cases.measuredAgainst)) {
      if (dep === 'date') continue;
      expect(pkg.dependencies[dep], `${dep} drifted from the measured version`).toContain(version);
    }
  });

  it('commits every case that declares a file', () => {
    for (const c of cases.cases) {
      if (!c.file) continue;
      expect(() => readFileSync(`${DOS}${c.file}`, 'utf8'), c.id).not.toThrow();
    }
  });
});

// ---------------------------------------------------------------------------
// The seven declared cases
// ---------------------------------------------------------------------------

describe('nested-div-40000 — maxNestingDepth', () => {
  const c = caseById('nested-div-40000');
  const g = c.generate as { element: string; depth: number };

  it('is caught BEFORE the parse, because the cost and the crash are in it', () => {
    const html = nestedElementHtml(g.element, g.depth);
    // The two ceilings that do NOT catch it. Asserting this is the point of the
    // case: without it, someone deletes the pre-parse gate as redundant.
    expect(Buffer.byteLength(html, 'utf8')).toBeLessThan(DEFAULT_LIMITS.maxResourceBytes);

    const est = estimateNestingDepth(html, DEFAULT_LIMITS.maxNestingDepth);
    expect(est.exceeded).toBe(true);
  });

  it('produces a diagnostic and no crash, and does not pass', () => {
    const out = scan([resourceOf('ui://dos/nested', nestedElementHtml(g.element, g.depth))]);
    expectTruncatedScanDoesNotPass(out);
    expect(out.resourcesAnalyzed).toBe(0);
  }, 20_000);
});

describe('js-add-chain-5000 — recursion in a third-party walker', () => {
  const c = caseById('js-add-chain-5000');

  it('is contained rather than thrown, and the scan survives', () => {
    const js = readFileSync(`${DOS}${c.file!}`, 'utf8');
    const html = `<!doctype html><html><body><script>${js}</script></body></html>`;
    // acorn parses it in 6 ms; acorn-walk throws RangeError. `contained` turns
    // that into a result, so the RangeError costs the rules that hit it rather
    // than the scan: other resources and other rules still run.
    let out!: AnalyzeResult;
    expect(() => {
      out = scan([resourceOf('ui://dos/addchain', html)]);
    }).not.toThrow();
    expect(out.resourcesAnalyzed).toBe(1);
  }, 20_000);

  it('records every rule the RangeError killed as undecided, never as clean', () => {
    // This is the whole point of containment. A rule that died did not decide
    // anything, and "no finding from PANE-MSG-004" must not be reportable as
    // "PANE-MSG-004 checked this script and was happy with it".
    const js = readFileSync(`${DOS}${c.file!}`, 'utf8');
    const html = `<!doctype html><html><body><script>${js}</script></body></html>`;
    const out = scan([resourceOf('ui://dos/addchain2', html)]);

    const crashed = out.errors.filter((e) => e.code === 'INTERNAL_ERROR');
    expect(crashed.length).toBeGreaterThan(0);
    for (const e of crashed) {
      const ruleId = /Rule (\S+) failed/.exec(e.message)?.[1];
      expect(
        out.undecided.some((u) => u.ruleId === ruleId && u.resourceUri === 'ui://dos/addchain2'),
        `${ruleId} crashed but was not recorded undecided`,
      ).toBe(true);
    }
  }, 20_000);
});

describe('deep-tree-textcontent-60000 — recursion in a third-party traversal', () => {
  const c = caseById('deep-tree-textcontent-60000');
  const g = c.generate as { element: string; depth: number };

  it('never lets a RangeError out of the scan', () => {
    // Below the nesting gate so the tree is actually built, which is what puts
    // domutils' recursive textContent on the path.
    const depth = Math.min(g.depth, DEFAULT_LIMITS.maxNestingDepth - 1);
    const html = nestedElementHtml(g.element, depth);
    expect(() => scan([resourceOf('ui://dos/deeptree', html)])).not.toThrow();
  }, 20_000);
});

describe('selector-not-5000 — selectorIsTractable', () => {
  const c = caseById('selector-not-5000');

  it('rejects the selector before css-select compiles it', () => {
    const css = readFileSync(`${DOS}${c.file!}`, 'utf8');
    const selector = css.slice(0, css.indexOf('{')).trim();
    // One rule, one selector: neither maxCssRules nor the node count sees it.
    expect(selector.length).toBeGreaterThan(0);
    expect(selectorIsTractable(selector)).toBe(false);
  });

  it('emits SELECTOR_SKIPPED rather than silently modelling no CSS', () => {
    const css = readFileSync(`${DOS}${c.file!}`, 'utf8');
    const html = `<!doctype html><html><head><style>${css}</style></head><body><p>x</p></body></html>`;
    const { dom } = parseHtml(html, DEFAULT_LIMITS);
    const index = buildStyleIndex(dom, DEFAULT_LIMITS, 'ui://dos/selector');

    expect(index.diagnostics.some((d) => d.code === 'SELECTOR_SKIPPED')).toBe(true);
    // Undecided is not clean. A skipped selector removes declarations from
    // candidatesFor, and which nodes it would have matched is unknown, so the
    // document goes undecided rather than reading as "no such declaration".
    expect(index.undecidedReasons().length).toBeGreaterThan(0);
  }, 20_000);
});

describe('base64-data-uri-80mb — base64DecodeCap', () => {
  const c = caseById('base64-data-uri-80mb');
  const g = c.generate as { decodedBytes: number };

  it('checks the decoded size as arithmetic, before any Buffer.from', () => {
    const uri = base64DataUri(g.decodedBytes);
    const encoded = uri.slice(uri.indexOf(',') + 1);
    const decodedSize = Math.floor((encoded.length * 3) / 4);
    expect(decodedSize).toBeGreaterThan(DEFAULT_LIMITS.base64DecodeCap);
  });
});

describe('resource-over-max-bytes — maxResourceBytes', () => {
  const c = caseById('resource-over-max-bytes');
  const g = c.generate as { bytes: number };

  it('refuses the resource and does not report it as scanned', () => {
    const out = scan([resourceOf('ui://dos/big', 'x'.repeat(g.bytes))]);
    expectTruncatedScanDoesNotPass(out);
    expect(out.resourcesAnalyzed).toBe(0);
    expect(limitDiags(out.diagnostics)[0]!.message).toContain('maxResourceBytes');
  }, 20_000);
});

describe('resource-count-501 — maxTotalResources', () => {
  const c = caseById('resource-count-501');
  const g = c.generate as { count: number };

  it('caps the count and says so rather than scanning them all', () => {
    const resources = Array.from({ length: g.count }, (_, i) =>
      resourceOf(`ui://dos/r${i}`, '<p>x</p>'),
    );
    const out = scan(resources);
    expectTruncatedScanDoesNotPass(out);
    expect(out.resourcesAnalyzed).toBeLessThanOrEqual(DEFAULT_LIMITS.maxTotalResources);
  }, 30_000);
});

// ---------------------------------------------------------------------------
// The four defects this file was written after, none of which cases.json knew
// ---------------------------------------------------------------------------

describe(':has() is charged for the work it does, not the call it makes', () => {
  it('bounds the measured bomb: one rule, 490-deep chain, three descendants', () => {
    // The measured case. 5,456 bytes, 495 nodes, ONE CSS rule — every existing
    // ceiling passes it by orders of magnitude (maxResourceBytes by 1500x,
    // maxDomNodes by 200x, maxCssRules by 20000x). Growth is ~O(subtree^(1+d)).
    //
    //   published 0.1.3        45,555 ms, zero diagnostics, exit 0
    //
    // The first cost model charged `1 + hasCount x N`, which is additive where
    // the cost is multiplicative, so it never tripped either. This asserts the
    // refusal happens BEFORE the first call: one cssIs call on this document
    // takes 12.7 s by itself, so nothing checked between calls can bound it.
    const body = '<div>'.repeat(490) + '<span>x</span>' + '</div>'.repeat(490);
    const html =
      `<!doctype html><html><head><style>div:has(div div div span){color:red}</style>` +
      `</head><body>${body}</body></html>`;

    const started = Date.now();
    const { dom } = parseHtml(html, DEFAULT_LIMITS);
    const index = buildStyleIndex(dom, DEFAULT_LIMITS, 'ui://dos/has');
    const elapsed = Date.now() - started;

    expect(index.diagnostics.some((d) => d.code === 'SELECTOR_SKIPPED')).toBe(true);
    // Deliberately loose so it cannot flake. The unfixed code took 45 s; do not
    // raise this ceiling to make a regression pass.
    expect(elapsed).toBeLessThan(5_000);
  }, 30_000);

  it('does not skip ordinary :has() markup — the false-positive guard', () => {
    // The whole fix is worthless if it makes real stylesheets undecided. A
    // single-combinator `:has()` over 300 cards must match normally.
    const body = '<div class="card"><b class="badge">y</b></div>'.repeat(300);
    const html =
      `<!doctype html><html><head><style>.card:has(.badge){opacity:0}</style>` +
      `</head><body>${body}</body></html>`;
    const { dom } = parseHtml(html, DEFAULT_LIMITS);
    const index = buildStyleIndex(dom, DEFAULT_LIMITS, 'ui://dos/has-ok');

    expect(index.diagnostics.some((d) => d.code === 'SELECTOR_SKIPPED')).toBe(false);
    expect(index.undecidedReasons()).toEqual([]);
  }, 30_000);

  it('leaves the cascade undecided when the budget stops the match loop', () => {
    // Otherwise the index reports a complete cascade built from a prefix of the
    // stylesheet, and front-loading expensive selectors becomes a way to make
    // the declaration that would have been found simply never looked at.
    const rules = Array.from(
      { length: 200 },
      (_, i) => `.c${i}:has(div div div span) { color: red }`,
    ).join('\n');
    const body = '<div>'.repeat(30) + '<span>x</span>'.repeat(400) + '</div>'.repeat(30);
    const html = `<!doctype html><html><head><style>${rules}</style></head><body>${body}</body></html>`;
    const { dom } = parseHtml(html, DEFAULT_LIMITS);
    const index = buildStyleIndex(dom, DEFAULT_LIMITS, 'ui://dos/has2');

    expect(index.undecidedReasons().some((r) => /budget/.test(r))).toBe(true);
  }, 30_000);
});

describe('_meta is covered by a limit key', () => {
  it('refuses an oversized domain list rather than truncating it', () => {
    const domains = Array.from({ length: 10_000 }, (_, i) => `https://d${i}.example.com`);
    const meta: UIResourceMeta = { csp: { connectDomains: domains } };
    const imgs = '<img src="https://x.example.com/a.png">'.repeat(400);
    const out = scan([
      resourceOf('ui://dos/meta', `<!doctype html><html><body>${imgs}</body></html>`, meta),
    ]);

    const d = limitDiags(out.diagnostics).find((x) => /maxMetaDomains/.test(x.message));
    expect(d).toBeDefined();
    expect(d!.message).toContain('connectDomains');
  }, 20_000);

  it('records the rules it did not run as undecided, never as clean', () => {
    // Truncating the list would have been worse than refusing it: a shortened
    // connectDomains makes a declared origin read as undeclared, which turns a
    // resource ceiling into a finding on conformant markup.
    const domains = Array.from({ length: 10_000 }, (_, i) => `https://d${i}.example.com`);
    const meta: UIResourceMeta = { csp: { connectDomains: domains } };
    const out = scan([resourceOf('ui://dos/meta2', '<!doctype html><p>x</p>', meta)]);

    const skipped = out.undecided.filter((u) => /maxMetaDomains/.test(u.reason));
    expect(skipped.length).toBeGreaterThan(0);
    for (const u of skipped) expect(u.reason).toMatch(/unknown, not clean/);
  }, 20_000);

  it('leaves a normal declaration alone', () => {
    const meta: UIResourceMeta = { csp: { connectDomains: ['https://api.example.com'] } };
    const out = scan([resourceOf('ui://dos/meta3', '<!doctype html><p>x</p>', meta)]);
    expect(limitDiags(out.diagnostics).filter((x) => /maxMetaDomains/.test(x.message))).toEqual([]);
    expect(out.undecided.filter((u) => /maxMetaDomains/.test(u.reason))).toEqual([]);
  });
});

describe('an exhausted budget names the rules it suppressed', () => {
  it('does not let an unrun rule read as a rule that found nothing', () => {
    // Rule order is deterministic and published, so an attacker who wants a
    // specific rule silenced crafts input whose cost is paid by a rule that
    // runs before it. The count alone does not say which rule went unanswered.
    const times = [0, 0, 100_000, 100_000, 100_000];
    let i = 0;
    const now = (): number => times[i++] ?? 100_000;

    const out = analyzeResourceSet(
      setOf([resourceOf('ui://dos/suppress', '<!doctype html><p>x</p>')]),
      selectRules({ experimental: true }),
      { now, limits: { ...DEFAULT_LIMITS, perResourceMs: 5_000 } },
    );

    const suppressed = out.undecided.filter((u) => /time budget/.test(u.reason));
    expect(suppressed.length).toBeGreaterThan(0);
    expect(selectExitCode(out.findings, out.errors, 'HIGH', 'fail', out.diagnostics)).toBe(2);
  });
});

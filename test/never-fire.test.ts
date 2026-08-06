/**
 * The patterns that must never produce a finding.
 *
 * Each one is mandated or emitted by the specification or the official SDK, and
 * each looks like a classic vulnerability. A rule that fires on any of them
 * fires on conformant servers across the whole ecosystem — GOALS.md G2 calls
 * that non-negotiable, and DESIGN.md §6 calls it the highest-severity bug this
 * project has.
 *
 * These run through the REAL pipeline — acquire shape, analyze runner, dedup —
 * not through individual rule functions, because a guard that only holds when a
 * rule is called directly is not a guard.
 */

import { describe, it, expect } from 'vitest';
import { analyzeResourceSet } from '../src/analyze.js';
import { selectRules } from '../src/rules/registry.js';
import { sha256Resource } from '../src/acquire/hash.js';
import { resolveMeta } from '../src/parse/meta.js';
import type { ResourceSet, UIResourceMeta, Finding, ToolWithUIMeta } from '../src/types.js';

const MIME = 'text/html;profile=mcp-app';

interface Build {
  html?: string;
  metaFromList?: UIResourceMeta;
  metaFromRead?: UIResourceMeta;
  tools?: ToolWithUIMeta[];
  source?: ResourceSet['source'];
}

function setOf(b: Build): ResourceSet {
  const content = b.html ?? '<!doctype html><html><body><p>hello</p></body></html>';
  const resolved = resolveMeta(b.metaFromList, b.metaFromRead);
  return {
    serverName: 'guard-server',
    protocolVersion: '2025-11-25',
    declaresUiExtension: true,
    declaredMimeTypes: [MIME],
    resources: [
      {
        uri: 'ui://guard/view',
        mimeType: MIME,
        listedMimeType: MIME,
        content,
        contentHash: sha256Resource({ text: content }),
        schemaErrors: [],
        source: b.source ?? 'capture',
        ...(b.metaFromList ? { metaFromList: b.metaFromList } : {}),
        ...(b.metaFromRead ? { metaFromRead: b.metaFromRead } : {}),
        ...(resolved ? { meta: resolved } : {}),
      },
    ],
    tools: b.tools ?? [],
    diagnostics: [],
    errors: [],
    scannedAt: '2026-08-05T00:00:00.000Z',
    source: b.source ?? 'capture',
  };
}

/** Findings that would actually be reported — INFO class included. */
function findingsFor(b: Build): Finding[] {
  const rules = selectRules({ experimental: true });
  return analyzeResourceSet(setOf(b), rules).findings;
}

function idsFor(b: Build): string[] {
  return findingsFor(b).map((f) => f.ruleId).sort();
}

// ---------------------------------------------------------------------------
// Guard 1 — 'unsafe-inline' is MANDATED, not a flaw
// ---------------------------------------------------------------------------

describe("guard 1: 'unsafe-inline' and inline <script> are in-policy", () => {
  /**
   * The spec's enforced default CSP includes 'unsafe-inline' in script-src and
   * style-src UNCONDITIONALLY, because raw HTML resources have no build step to
   * externalize inline scripts. A scanner flagging it flags every conformant
   * server in the ecosystem. This is the single most likely way to ship a
   * scanner that is instantly discredited.
   */
  const INLINE_EVERYTHING = `<!doctype html><html><head>
      <style>.a{color:red}</style>
    </head><body>
      <button onclick="doThing()">go</button>
      <script>function doThing(){ console.log('hi'); }</script>
    </body></html>`;

  it('produces no finding mentioning unsafe-inline', () => {
    const found = findingsFor({ html: INLINE_EVERYTHING });
    const offenders = found.filter((f) => /unsafe-inline/i.test(f.message));
    expect(offenders.map((f) => f.ruleId)).toEqual([]);
  });

  it('does not flag an inline <script> element as a CSP problem', () => {
    const found = findingsFor({ html: INLINE_EVERYTHING });
    const cspFindings = found.filter((f) => f.ruleId.startsWith('PANE-CSP-'));
    expect(cspFindings.map((f) => f.ruleId)).toEqual([]);
  });

  it('does not flag an inline event handler attribute', () => {
    // 'unsafe-inline' also permits inline event handlers, javascript: URLs and
    // <svg>-embedded script. All are in-policy.
    const found = findingsFor({ html: '<div onclick="go()">x</div>' });
    expect(found.filter((f) => /event handler|inline/i.test(f.message))).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Guard 2 — allow-scripts + allow-same-origin is REQUIRED for the proxy
// ---------------------------------------------------------------------------

describe('guard 2: allow-scripts + allow-same-origin without a declared origin', () => {
  /**
   * In general web security this combination defeats sandbox isolation. In MCP
   * Apps it is MANDATED for the sandbox proxy, and is safe only because the
   * proxy sits on a different origin from the host.
   *
   * Measured: none of the eight reference servers declares `_meta.ui.domain`.
   * With no declared origin, "same-origin with the host" is UNKNOWABLE, so the
   * rule must decline to answer rather than guess.
   */
  const SRCDOC_FRAME =
    '<iframe sandbox="allow-scripts allow-same-origin" srcdoc="<p>nested</p>"></iframe>';

  it('produces no PANE-SANDBOX-001 finding', () => {
    expect(idsFor({ html: SRCDOC_FRAME })).not.toContain('PANE-SANDBOX-001');
  });

  it('produces no CRITICAL finding at all on the documented double-iframe pattern', () => {
    const critical = findingsFor({ html: SRCDOC_FRAME }).filter((f) => f.severity === 'CRITICAL');
    expect(critical.map((f) => f.ruleId)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Guard 3 — the SDK DUAL-WRITES the deprecated flat key
// ---------------------------------------------------------------------------

describe('guard 3: SDK-dual-written _meta["ui/resourceUri"]', () => {
  /**
   * `registerAppTool` writes the deprecated flat key for you whenever the
   * modern `_meta.ui.resourceUri` is supplied. Verified against
   * @modelcontextprotocol/ext-apps@1.7.5. A rule flagging the flat key's
   * presence fires on every conformant TypeScript server, including the
   * reference fixtures.
   */
  const dualWritten: ToolWithUIMeta[] = [
    {
      name: 'get_board',
      meta: { resourceUri: 'ui://guard/view', visibility: ['model', 'app'] },
      rawMeta: {
        ui: { resourceUri: 'ui://guard/view', visibility: ['model', 'app'] },
        'ui/resourceUri': 'ui://guard/view',
      },
      schemaErrors: [],
    },
  ];

  it('produces no PANE-SPEC-006 finding when both forms agree', () => {
    expect(idsFor({ tools: dualWritten })).not.toContain('PANE-SPEC-006');
  });

  it('produces no PANE-SPEC-011 finding when both forms carry the same value', () => {
    expect(idsFor({ tools: dualWritten })).not.toContain('PANE-SPEC-011');
  });

  it('produces no SCHEMA finding — MCP _meta is explicitly extensible', () => {
    // Pointing ajv at `_meta` rather than at the `_meta.ui` subtree would
    // reject the flat key as an unknown property on every conformant server.
    const schemaFindings = findingsFor({ tools: dualWritten }).filter((f) =>
      f.ruleId.startsWith('PANE-SCHEMA-'),
    );
    expect(schemaFindings.map((f) => f.ruleId)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Guard 4 — the curated csp_evaluator check list
// ---------------------------------------------------------------------------

describe('guard 4: csp_evaluator on the policies the spec defines', () => {
  /**
   * Measured against csp_evaluator@1.1.8. `evaluate()` with no arguments runs
   * DEFAULT_CHECKS, which flags 'unsafe-inline' (severity 10) AND any 'self' in
   * script-src (severity 50) — both present in the mandated default policy.
   *
   * Note the API shape, because getting it wrong is silent: the check list is
   * the SECOND argument. `evaluate(CURATED)` leaves DEFAULT_CHECKS running and
   * reproduces the exact fatal false positive.
   */
  const MANDATED =
    "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data:; media-src 'self' data:; connect-src 'none';";

  const CONSTRUCTED =
    "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; " +
    "connect-src 'self'; img-src 'self' data:; font-src 'self'; media-src 'self' data:; " +
    "frame-src 'none'; object-src 'none'; base-uri 'self';";

  it('the curated list produces zero findings on the mandated default policy', async () => {
    const { CspParser } = await import('csp_evaluator/dist/parser.js');
    const { CspEvaluator } = await import('csp_evaluator/dist/evaluator.js');
    const c = await import('csp_evaluator/dist/checks/security_checks.js');
    const CURATED = [c.checkSrcHttp, c.checkIpSource, c.checkPlainUrlSchemes];

    const parsed = new CspParser(MANDATED).csp;
    expect(new CspEvaluator(parsed).evaluate(undefined, CURATED)).toHaveLength(0);
  });

  it('the curated list produces zero findings on the constructed policy', async () => {
    const { CspParser } = await import('csp_evaluator/dist/parser.js');
    const { CspEvaluator } = await import('csp_evaluator/dist/evaluator.js');
    const c = await import('csp_evaluator/dist/checks/security_checks.js');
    const CURATED = [c.checkSrcHttp, c.checkIpSource, c.checkPlainUrlSchemes];

    const parsed = new CspParser(CONSTRUCTED).csp;
    expect(new CspEvaluator(parsed).evaluate(undefined, CURATED)).toHaveLength(0);
  });

  it('DEFAULT_CHECKS still fires on the mandated policy — the trap is real, not theoretical', async () => {
    const { CspParser } = await import('csp_evaluator/dist/parser.js');
    const { CspEvaluator } = await import('csp_evaluator/dist/evaluator.js');
    const parsed = new CspParser(MANDATED).csp;
    // If this ever returns 0, the dependency changed and the guard above has
    // stopped proving anything. That is worth failing on.
    expect(new CspEvaluator(parsed).evaluate().length).toBeGreaterThan(0);
  });

  it('the deep-imported bypass allowlists are the expected size', async () => {
    // Tamper detection, and an early warning that a patch bump changed findings.
    const jsonp = await import('csp_evaluator/dist/allowlist_bypasses/jsonp.js');
    const angular = await import('csp_evaluator/dist/allowlist_bypasses/angular.js');
    expect(jsonp.URLS.length).toBe(123);
    expect(angular.URLS.length).toBe(41);
  });
});

// ---------------------------------------------------------------------------
// Guard 5 — list-level-only _meta.ui is NOT divergence
// ---------------------------------------------------------------------------

describe('guard 5: idiomatic registerAppResource puts _meta.ui on the LIST entry only', () => {
  /**
   * The fourth poisoned rule, found the same way the third was.
   *
   * `registerAppResource`'s own documentation says `_meta.ui` "appears on the
   * resource entry in resources/list and acts as a listing-level fallback", so
   * idiomatic SDK usage yields metaFromList populated and metaFromRead ABSENT.
   * A naive `!deepEqual(list, read)` fires on every conformant TypeScript
   * server that declares a CSP, at RISK/HIGH/CERTAIN — gate-eligible.
   *
   * An absent read-level meta means the list value IS the effective one. That
   * is not divergence.
   */
  const listOnly: UIResourceMeta = {
    csp: { connectDomains: ['https://api.example.test'] },
  };

  it('produces no PANE-SPEC-010 finding', () => {
    expect(idsFor({ metaFromList: listOnly })).not.toContain('PANE-SPEC-010');
  });

  it('produces no PANE-SPEC-010 finding when the two forms are identical', () => {
    expect(
      idsFor({ metaFromList: listOnly, metaFromRead: { ...listOnly } }),
    ).not.toContain('PANE-SPEC-010');
  });

  it('still fires when the read-level policy is genuinely broader', () => {
    // The guard must not be so wide that it disables the rule. This is the case
    // PANE-SPEC-010 exists for: a host reviewing at connection time sees the
    // narrow policy, and the broad one is what gets enforced.
    const ids = idsFor({
      metaFromList: { csp: { connectDomains: ['https://api.example.test'] } },
      metaFromRead: { csp: { connectDomains: ['https://api.example.test', 'https://elsewhere.test'] } },
    });
    expect(ids).toContain('PANE-SPEC-010');
  });
});

// ---------------------------------------------------------------------------
// The whole conformant baseline
// ---------------------------------------------------------------------------

describe('a plainly conformant server produces nothing that gates', () => {
  it('emits no SPEC, SCHEMA or RISK finding', () => {
    // The app CONTACTS the origin it declares. A conformant server declares what
    // it uses and uses what it declares — a declared-but-uncontacted origin is
    // over-declaration, and PANE-CSP-009 is right to say so.
    const found = findingsFor({
      html:
        '<!doctype html><html><body><h1>Dashboard</h1><p>All good.</p>' +
        '<script>fetch("https://api.example.test/v1/status");</script></body></html>',
      metaFromList: { csp: { connectDomains: ['https://api.example.test'] }, prefersBorder: true },
    });
    const serious = found.filter((f) => f.ruleClass !== 'INFO');
    expect(serious.map((f) => `${f.ruleId}: ${f.message}`)).toEqual([]);
  });
});

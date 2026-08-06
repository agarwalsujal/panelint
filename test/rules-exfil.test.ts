import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parseHtml } from '../src/parse/html.js';
import { collectScripts } from '../src/parse/js.js';
import { buildStyleIndex } from '../src/parse/style-index.js';
import { DEFAULT_LIMITS } from '../src/limits.js';
import { isGating } from '../src/exit.js';
import type { Finding, RuleContext, UIResource, UIResourceMeta } from '../src/types.js';

import { exfil001 } from '../src/rules/exfil/exfil-001.js';
import { exfil002 } from '../src/rules/exfil/exfil-002.js';
import { exfil003 } from '../src/rules/exfil/exfil-003.js';
import { exfil004 } from '../src/rules/exfil/exfil-004.js';
import { exfil006 } from '../src/rules/exfil/exfil-006.js';
import { exfil007 } from '../src/rules/exfil/exfil-007.js';
import { isOffDocument, offDocumentOrigin } from '../src/rules/exfil/url-shape.js';

/**
 * The PANE-EXFIL family — the channels no `_meta.ui.csp` field governs.
 *
 * The organising fact, from docs/RULES.md § The finding that reorganized this
 * catalog: the app document's URL is `about:srcdoc`, a `blob:` URL, or an
 * opaque origin. There is no origin to be "same" as, so EVERY absolute URL is
 * off-document and every relative URL is same-document. Half the tests below
 * exist because that inverts heuristics ported from the classic web.
 */

const fixture = (rel: string): string =>
  readFileSync(fileURLToPath(new URL(`../fixtures/${rel}`, import.meta.url)), 'utf8');

function ctxFor(html: string, meta: UIResourceMeta | null = null): RuleContext {
  const { dom } = parseHtml(html, DEFAULT_LIMITS);
  const resource: UIResource = {
    uri: 'ui://test-server/view',
    mimeType: 'text/html;profile=mcp-app',
    content: html,
    schemaErrors: [],
    contentHash: 'sha256:test',
    source: 'directory',
  };
  return {
    resource,
    dom,
    styles: buildStyleIndex(dom, DEFAULT_LIMITS),
    meta,
    schemaErrors: [],
    scripts: collectScripts(dom, html, DEFAULT_LIMITS),
    rawSource: html,
    tools: [],
    options: {},
    limits: DEFAULT_LIMITS,
    diagnostic: () => {},
  };
}

const ids = (f: Finding[]): string[] => f.map((x) => x.ruleId);

describe('PANE-EXFIL-001 — <form action> / formaction to an off-document origin', () => {
  it('declares the contract from the RULES.md table', () => {
    expect(exfil001.id).toBe('PANE-EXFIL-001');
    expect(exfil001.ruleClass).toBe('RISK');
    expect(exfil001.severity).toBe('CRITICAL');
    expect(exfil001.confidence).toBe('CERTAIN');
    expect(exfil001.experimental).toBe(false);
    expect(exfil001.requires).toEqual(['content']);
  });

  it('carries the fixed remediation text verbatim, unsoftened', () => {
    // docs/RULES.md: "Remediation text for -001 is fixed and must not be softened".
    expect(exfil001.remediation).toContain(
      '`form-action` is not covered by any `_meta.ui.csp` field, and it does not inherit from `default-src`.',
    );
    expect(exfil001.remediation).toContain('**The host cannot block this submission.**');
    expect(exfil001.remediation).toContain(
      "Send the data with `fetch()` to an origin declared in `connectDomains` instead, where the host's CSP applies.",
    );
  });

  it('fires on an absolute http(s) action and on button/input formaction', () => {
    const findings = exfil001.check(ctxFor(fixture('malicious/exfil/form-off-origin.html'))).findings;
    expect(findings).toHaveLength(3);
    expect(new Set(ids(findings))).toEqual(new Set(['PANE-EXFIL-001']));
    expect(findings.every((f) => isGating(f, 'HIGH'))).toBe(true);
  });

  it('finds a form inside <template> — css-select alone does not descend', () => {
    // parse/html.ts `selectAll` queries template fragments separately. A rule
    // using css-select directly is one line of markup away from blind.
    const findings = exfil001.check(ctxFor(fixture('malicious/exfil/form-in-template.html'))).findings;
    expect(findings).toHaveLength(1);
    expect(findings[0]!.evidence).toContain('collector.invalid');
  });

  it('is silent on every same-document action — the empty action is BENIGN here', () => {
    // Empty, absent, relative, "#", "?", javascript:, mailto:, method=dialog.
    const findings = exfil001.check(ctxFor(fixture('nondetect/exfil/form-benign.html'))).findings;
    expect(findings).toEqual([]);
  });

  it('is silent on a formaction that cannot submit', () => {
    // `formaction` is inert on anything but a submit control, and an <input>
    // defaults to type="text". A CRITICAL/CERTAIN rule must not fire on markup
    // that cannot submit at all.
    const html = `
      <form action="/local">
        <input formaction="https://collector.invalid/x">
        <input type="text" formaction="https://collector.invalid/x">
        <button type="button" formaction="https://collector.invalid/x">no</button>
      </form>`;
    expect(exfil001.check(ctxFor(html)).findings).toEqual([]);
  });

  it('is silent on a protocol-relative action only when it has no authority', () => {
    expect(exfil001.check(ctxFor('<form action="//">x</form>')).findings).toEqual([]);
    // `//host/p` resolves against the parent document's scheme. It is off-document.
    expect(exfil001.check(ctxFor('<form action="//collector.invalid/p"></form>')).findings).toHaveLength(1);
  });
});

describe('PANE-EXFIL-002 — form action assigned at runtime', () => {
  it('declares the contract from the RULES.md table', () => {
    expect(exfil002.id).toBe('PANE-EXFIL-002');
    expect(exfil002.ruleClass).toBe('RISK');
    expect(exfil002.severity).toBe('HIGH');
    expect(exfil002.confidence).toBe('HIGH');
  });

  it('fires on a non-literal action assignment and setAttribute', () => {
    const findings = exfil002.check(ctxFor(fixture('malicious/exfil/form-action-runtime.html'))).findings;
    expect(findings).toHaveLength(2);
    expect(findings.every((f) => f.confidence === 'HIGH')).toBe(true);
  });

  it('is silent on a literal same-document assignment — the PANE-DOM-001 carve-out', () => {
    // RULES.md's row has no literal carve-out and needs one. At HIGH/HIGH the
    // rule is gate-eligible, so `form.setAttribute('action','/search')` would
    // break a conformant build.
    const findings = exfil002.check(
      ctxFor(fixture('nondetect/exfil/form-action-literal-assignment.html')),
    ).findings;
    expect(findings).toEqual([]);
  });

  it('reports an unidentifiable receiver below the gate rather than breaking a build', () => {
    // `state.action = payload` is ordinary reducer code, not a form.
    const findings = exfil002.check(
      ctxFor('<script>function r(s, p){ s.action = p.type + p.id; return s; }</script>'),
    ).findings;
    expect(findings).toHaveLength(1);
    expect(findings[0]!.confidence).toBe('MEDIUM');
    expect(isGating(findings[0]!, 'HIGH')).toBe(false);
  });
});

describe('PANE-EXFIL-003 — <meta http-equiv="refresh">', () => {
  it('declares the contract from the RULES.md table', () => {
    expect(exfil003.id).toBe('PANE-EXFIL-003');
    expect(exfil003.severity).toBe('HIGH');
    expect(exfil003.confidence).toBe('CERTAIN');
  });

  it('fires on a refresh carrying an off-document url= component', () => {
    const findings = exfil003.check(ctxFor(fixture('malicious/exfil/meta-refresh.html'))).findings;
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('HIGH');
    expect(isGating(findings[0]!, 'HIGH')).toBe(true);
  });

  it('parses the quoted and case-varied url= spellings', () => {
    expect(
      exfil003.check(ctxFor(`<meta http-equiv="REFRESH" content="0; URL='https://collector.invalid/c'">`))
        .findings,
    ).toHaveLength(1);
  });

  it('is silent on a refresh with no url= component — it reloads this document', () => {
    // `content="30"` exfiltrates nothing.
    const findings = exfil003.check(ctxFor(fixture('nondetect/exfil/meta-refresh-self.html'))).findings;
    expect(findings).toEqual([]);
  });

  it('does not claim a refresh inside <noscript> — it is inert under allow-scripts', () => {
    // The spec mandates `script-src 'self' 'unsafe-inline'`, so scripting is on
    // and noscript content never applies. PANE-HIDDEN-012 covers the carrier.
    // parse/html.ts uses scriptingEnabled:false, so the element IS in the tree.
    const html = `<noscript><meta http-equiv="refresh" content="0;url=https://collector.invalid/c"></noscript>`;
    expect(exfil003.check(ctxFor(html)).findings).toEqual([]);
  });

  it('demotes a same-document refresh target below the gate', () => {
    const findings = exfil003.check(ctxFor('<meta http-equiv="refresh" content="5;url=/next">')).findings;
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('MEDIUM');
    expect(isGating(findings[0]!, 'HIGH')).toBe(false);
  });
});

describe('PANE-EXFIL-004 — navigation sinks', () => {
  it('declares the contract from the RULES.md table', () => {
    expect(exfil004.id).toBe('PANE-EXFIL-004');
    expect(exfil004.severity).toBe('HIGH');
    expect(exfil004.confidence).toBe('HIGH');
  });

  it('fires on every self-navigation sink with a non-literal argument', () => {
    const findings = exfil004.check(ctxFor(fixture('malicious/exfil/navigation.html'))).findings;
    // location.href, location.assign, location.replace, bare location,
    // window.location, window.open.
    expect(findings).toHaveLength(6);
  });

  it('reports window.open BELOW location assignment, and says why', () => {
    const findings = exfil004.check(ctxFor(fixture('malicious/exfil/navigation.html'))).findings;
    const open = findings.find((f) => f.message.includes('window.open'))!;
    const self = findings.find((f) => f.message.includes('location.href'))!;

    expect(self.severity).toBe('HIGH');
    expect(open.severity).toBe('MEDIUM');
    // The reference sandbox is `allow-scripts allow-same-origin allow-forms`.
    expect(open.message).toContain('allow-popups');
    expect(isGating(open, 'HIGH')).toBe(false);
  });

  it('does not fire on `.location` of an arbitrary object — map-server has markers', () => {
    // `.location` is not an HTML-only property name and this rule is HIGH/HIGH,
    // so a marker assignment would be a gate-eligible finding on a reference
    // server. Only a browsing context navigates.
    const html = `<script>
      marker.location = data.position;
      store.location = props.city + ', ' + props.country;
    </script>`;
    expect(exfil004.check(ctxFor(html)).findings).toEqual([]);
  });

  it('does not fire on a locally shadowed `location` binding', () => {
    const html = `<script>function f(rows){ let location = rows[0].place; return location; }</script>`;
    expect(exfil004.check(ctxFor(html)).findings).toEqual([]);
  });

  it('is silent on literal destinations', () => {
    const findings = exfil004.check(ctxFor(fixture('nondetect/exfil/navigation-literal.html'))).findings;
    expect(findings).toEqual([]);
  });
});

describe('PANE-EXFIL-006 — <base>', () => {
  it('declares the contract from the RULES.md table', () => {
    expect(exfil006.id).toBe('PANE-EXFIL-006');
    expect(exfil006.severity).toBe('HIGH');
    expect(exfil006.confidence).toBe('CERTAIN');
    expect(exfil006.requires).toContain('meta');
  });

  it('fires on an absolute off-origin href', () => {
    const findings = exfil006.check(ctxFor(fixture('malicious/exfil/base-off-origin.html'))).findings;
    expect(findings).toHaveLength(1);
    expect(isGating(findings[0]!, 'HIGH')).toBe(true);
  });

  it('is silent on <base> with no href and on a relative href', () => {
    // RULES.md says "any <base> when baseUriDomains is unset" — measured, that
    // condition is universally true (0 of 8 reference servers declare it), so
    // the rule as written fires on every app that has a <base> at all.
    const findings = exfil006.check(ctxFor(fixture('nondetect/exfil/base-benign.html'))).findings;
    expect(findings).toEqual([]);
  });

  it('says when a declared baseUriDomains already permits the origin', () => {
    const meta: UIResourceMeta = { csp: { baseUriDomains: ['https://cdn.example.com'] } };
    const findings = exfil006.check(
      ctxFor('<base href="https://cdn.example.com/app/">', meta),
    ).findings;
    expect(findings).toHaveLength(1);
    expect(findings[0]!.message).toContain('baseUriDomains');
    expect(findings[0]!.assumption).toBeTruthy();
  });

  it('does NOT gate when baseUriDomains declares the origin', () => {
    // Declaring an origin and then pointing <base> at it is the spec's own
    // mechanism used as designed. At the default --fail-on high this rule used
    // to gate on it, failing the build of a conformant server. G2 calls a
    // gate-eligible finding on conformant markup non-negotiable.
    const meta: UIResourceMeta = { csp: { baseUriDomains: ['https://cdn.example.com'] } };
    const findings = exfil006.check(
      ctxFor('<base href="https://cdn.example.com/app/">', meta),
    ).findings;
    expect(findings[0]!.severity).toBe('LOW');
    expect(isGating(findings[0]!, 'HIGH')).toBe(false);
  });

  it('still gates when no baseUriDomains covers the origin', () => {
    const meta: UIResourceMeta = { csp: { baseUriDomains: ['https://cdn.example.com'] } };
    const findings = exfil006.check(
      ctxFor('<base href="https://attacker.tld/app/">', meta),
    ).findings;
    expect(findings[0]!.severity).toBe('HIGH');
    expect(isGating(findings[0]!, 'HIGH')).toBe(true);
  });
});

describe('PANE-EXFIL-007 — resource hints', () => {
  it('declares the contract from the RULES.md table', () => {
    expect(exfil007.id).toBe('PANE-EXFIL-007');
    expect(exfil007.severity).toBe('MEDIUM');
    expect(exfil007.confidence).toBe('HIGH');
    expect(exfil007.requires).toContain('meta');
  });

  it('fires on hints to undeclared origins and escalates the runtime-built href', () => {
    const findings = exfil007.check(ctxFor(fixture('malicious/exfil/resource-hints.html'))).findings;
    expect(findings).toHaveLength(3);

    const runtime = findings.filter((f) => f.severity === 'HIGH');
    expect(runtime).toHaveLength(1);
    expect(runtime[0]!.message).toContain('runtime');

    const statics = findings.filter((f) => f.severity === 'MEDIUM');
    expect(statics).toHaveLength(2);
  });

  it('is silent on hints to origins the server already declared', () => {
    const meta: UIResourceMeta = {
      csp: {
        connectDomains: ['https://api.example.com'],
        resourceDomains: ['https://cdn.example.com', 'https://*.fonts.example.com'],
      },
    };
    const findings = exfil007.check(
      ctxFor(fixture('nondetect/exfil/resource-hints-declared.html'), meta),
    ).findings;
    expect(findings).toEqual([]);
  });
});

describe('family invariants', () => {
  const rules = [exfil001, exfil002, exfil003, exfil004, exfil006, exfil007];

  it('never reuses or renumbers an ID — SARIF rules[].id is a public contract', () => {
    expect(rules.map((r) => r.id)).toEqual([
      'PANE-EXFIL-001',
      'PANE-EXFIL-002',
      'PANE-EXFIL-003',
      'PANE-EXFIL-004',
      'PANE-EXFIL-006',
      'PANE-EXFIL-007',
    ]);
  });

  it('is class RISK throughout — these are permitted by the spec, not violations of it', () => {
    expect(rules.every((r) => r.ruleClass === 'RISK')).toBe(true);
    expect(rules.every((r) => r.status === 'active')).toBe(true);
    expect(rules.every((r) => r.experimental === false)).toBe(true);
  });

  it('remediates by removal, never by tighter declaration', () => {
    // A server cannot narrow form-action; the field does not exist.
    for (const r of rules) {
      expect(r.remediation.length).toBeGreaterThan(0);
      expect(r.remediation).not.toMatch(/declare it more tightly/i);
    }
  });

  it('scans the whole malicious fixture set without a rule throwing', () => {
    const files = [
      'malicious/exfil/form-off-origin.html',
      'malicious/exfil/form-in-template.html',
      'malicious/exfil/form-action-runtime.html',
      'malicious/exfil/meta-refresh.html',
      'malicious/exfil/navigation.html',
      'malicious/exfil/base-off-origin.html',
      'malicious/exfil/resource-hints.html',
    ];
    for (const f of files) {
      const ctx = ctxFor(fixture(f));
      const found = rules.flatMap((r) => r.check(ctx).findings);
      expect(found.length).toBeGreaterThan(0);
    }
  });

  it('produces zero findings across every nondetect fixture', () => {
    const files = [
      'nondetect/exfil/form-benign.html',
      'nondetect/exfil/form-action-literal-assignment.html',
      'nondetect/exfil/meta-refresh-self.html',
      'nondetect/exfil/navigation-literal.html',
      'nondetect/exfil/base-benign.html',
    ];
    for (const f of files) {
      const ctx = ctxFor(fixture(f));
      expect(ids(rules.flatMap((r) => r.check(ctx).findings))).toEqual([]);
    }
  });
});

// ---------------------------------------------------------------------------
// URL spellings a browser resolves off-document but a string match does not.
// ---------------------------------------------------------------------------

/**
 * The WHATWG URL parser treats `\` as `/` and strips tab, LF and CR before
 * resolving. Classification used to pattern-match the raw attribute: anything
 * starting with `/` was called same-document, and the scheme-relative regex
 * excluded backslashes and whitespace.
 *
 * So every spelling below reached a foreign origin while PANE-EXFIL-001 — the
 * CRITICAL/CERTAIN rule the catalog calls the unblockable-egress check —
 * reported nothing. Measured before the fix: `action="/\collector.example/c"`
 * produced 0 findings where the plain `https://` spelling produced a gating
 * CRITICAL.
 *
 * These assert the classifier, not one rule, because six rules share it.
 */
describe('off-document classification resolves the way a browser does', () => {
  const OFF_DOCUMENT = [
    ['plain absolute', 'https://collector.example/c'],
    ['scheme-relative', '//collector.example/c'],
    ['backslash after leading slash', '/\\collector.example/c'],
    ['double backslash', '\\\\collector.example/c'],
    ['backslash in path', '//collector.example\\c'],
    ['newline inside the host', '//collector.exa\nmple/c'],
    ['tab inside the host', '//collector.exa\tmple/c'],
    ['carriage return inside the host', '//collector.exa\rmple/c'],
  ] as const;

  for (const [name, url] of OFF_DOCUMENT) {
    it(`treats ${name} as off-document`, () => {
      expect(isOffDocument(url), `${JSON.stringify(url)} reaches a foreign origin`).toBe(true);
      expect(offDocumentOrigin(url)).toBe('https://collector.example');
    });
  }

  const SAME_DOCUMENT = [
    ['empty', ''],
    ['fragment', '#section'],
    ['query', '?q=1'],
    ['absolute path', '/submit'],
    ['relative path', './submit'],
    ['bare relative', 'submit'],
  ] as const;

  for (const [name, url] of SAME_DOCUMENT) {
    it(`leaves ${name} classified as same-document`, () => {
      expect(isOffDocument(url)).toBe(false);
      expect(offDocumentOrigin(url)).toBeNull();
    });
  }

  const NON_NETWORK = ['javascript:alert(1)', 'mailto:a@b.example', 'data:text/html,x', 'about:blank'];
  for (const url of NON_NETWORK) {
    it(`does not treat ${url.split(':')[0]}: as an off-document network target`, () => {
      // These are handled by other rules; they are not egress over http(s).
      expect(isOffDocument(url)).toBe(false);
    });
  }
});

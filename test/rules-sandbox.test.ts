/**
 * PANE-SANDBOX — frame isolation.
 *
 * Two facts govern every test here.
 *
 * 1. `allow-scripts allow-same-origin` is MANDATED for the sandbox proxy
 *    (SPEC-REFERENCE.md §3.3). Flagging it on the documented double-iframe
 *    pattern is a false positive of exactly the kind GOALS.md G2 calls fatal.
 * 2. A nested browsing context can never exceed its ancestor's sandbox flags
 *    and can never acquire a Permissions Policy feature its parent lacks — and
 *    the spec does not enumerate the View iframe's sandbox value. Every finding
 *    in this family therefore carries that conditionality in its TEXT.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { parseHtml } from '../src/parse/html.js';
import { buildStyleIndex } from '../src/parse/style-index.js';
import { collectScripts } from '../src/parse/js.js';
import { DEFAULT_LIMITS } from '../src/limits.js';
import { HOST_SANDBOX_ASSUMPTION } from '../src/rules/shared/helpers.js';
import type { RuleContext, RuleResult, UIResourceMeta } from '../src/types.js';

import { sandbox001 } from '../src/rules/sandbox/sandbox-001.js';
import { sandbox002 } from '../src/rules/sandbox/sandbox-002.js';
import { sandbox003 } from '../src/rules/sandbox/sandbox-003.js';
import { sandbox004 } from '../src/rules/sandbox/sandbox-004.js';
import { sandbox005 } from '../src/rules/sandbox/sandbox-005.js';
import { sandbox006 } from '../src/rules/sandbox/sandbox-006.js';
import { sandbox007 } from '../src/rules/sandbox/sandbox-007.js';

const FIXTURES = fileURLToPath(new URL('../fixtures/', import.meta.url));

function ctxFor(html: string, meta: UIResourceMeta | null = null): RuleContext {
  const limits = DEFAULT_LIMITS;
  const { dom } = parseHtml(html, limits);
  return {
    resource: {
      uri: 'ui://example/app.html',
      mimeType: 'text/html;profile=mcp-app',
      content: html,
      schemaErrors: [],
      contentHash: 'sha256:test',
      source: 'directory',
    },
    dom,
    styles: buildStyleIndex(dom, limits),
    meta,
    schemaErrors: [],
    scripts: collectScripts(dom, html, limits),
    rawSource: html,
    options: {},
    limits,
    diagnostic: () => {},
  };
}

const fixture = (name: string) => readFileSync(`${FIXTURES}${name}`, 'utf8');
const ids = (r: RuleResult) => r.findings.map((f) => f.ruleId);

const ALL = [sandbox001, sandbox002, sandbox003, sandbox004, sandbox005, sandbox006, sandbox007];

// ---------------------------------------------------------------------------
// PANE-SANDBOX-001 — the rule that must not guess
// ---------------------------------------------------------------------------

describe('PANE-SANDBOX-001 — same-origin cannot be established, so it is not asserted', () => {
  it('is RISK / CRITICAL / HIGH', () => {
    expect([sandbox001.ruleClass, sandbox001.severity, sandbox001.confidence]).toEqual([
      'RISK',
      'CRITICAL',
      'HIGH',
    ]);
  });

  it('emits ZERO findings and exactly one undecided note on a nested srcdoc frame', () => {
    // The required negative. None of the eight reference servers declares
    // _meta.ui.domain, so there is no declared origin to compare against, and
    // srcdoc is the legitimate pattern.
    const r = sandbox001.check(ctxFor(fixture('nondetect/nested-srcdoc-frame.html')));
    expect(r.findings).toEqual([]);
    expect(r.undecided ?? []).toHaveLength(1);
    expect(r.undecided![0]!.reason).toMatch(/domain|origin/i);
  });

  it('declines rather than guesses on an absolute src with no declared domain', () => {
    const html = '<iframe sandbox="allow-scripts allow-same-origin" src="https://cdn.example/x.html"></iframe>';
    const r = sandbox001.check(ctxFor(html));
    expect(r.findings).toEqual([]);
    expect(r.undecided ?? []).toHaveLength(1);
  });

  it('emits nothing at all when the two tokens are not both present', () => {
    const html = '<iframe sandbox="allow-scripts" srcdoc="<p>x</p>"></iframe>';
    const r = sandbox001.check(ctxFor(html));
    expect(r.findings).toEqual([]);
    expect(r.undecided ?? []).toEqual([]);
  });

  it('fires only when the frame src matches the origin the server itself declared', () => {
    const meta: UIResourceMeta = { domain: 'abc123.claudemcpcontent.com' };
    const html =
      '<iframe sandbox="allow-scripts allow-same-origin" src="https://abc123.claudemcpcontent.com/inner.html"></iframe>';
    const r = sandbox001.check(ctxFor(html, meta));
    expect(ids(r)).toEqual(['PANE-SANDBOX-001']);
    expect(r.findings[0]!.assumption).toBe(HOST_SANDBOX_ASSUMPTION);
  });

  it('does not fire on a genuinely cross-origin child, which keeps its own origin', () => {
    const meta: UIResourceMeta = { domain: 'abc123.claudemcpcontent.com' };
    const html =
      '<iframe sandbox="allow-scripts allow-same-origin" src="https://widgets.other.example/x"></iframe>';
    expect(sandbox001.check(ctxFor(html, meta)).findings).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// The three demoted rules
// ---------------------------------------------------------------------------

describe('PANE-SANDBOX-002 / -003 / -004 describe no privilege gain and stay demoted', () => {
  it('-002 is INFO / LOW / CERTAIN and says the child inherits the ancestor flags', () => {
    expect([sandbox002.ruleClass, sandbox002.severity, sandbox002.confidence]).toEqual([
      'INFO',
      'LOW',
      'CERTAIN',
    ]);
    const r = sandbox002.check(ctxFor('<iframe src="/inner.html"></iframe>'));
    expect(ids(r)).toEqual(['PANE-SANDBOX-002']);
    expect(r.findings[0]!.message).toMatch(/inherit/i);
  });

  it('-002 does not fire when the child declares its own sandbox', () => {
    expect(sandbox002.check(ctxFor('<iframe sandbox="" src="/x"></iframe>')).findings).toEqual([]);
  });

  it('-003 is INFO / LOW / CERTAIN and needs an actual wildcard allowlist', () => {
    expect([sandbox003.ruleClass, sandbox003.severity, sandbox003.confidence]).toEqual([
      'INFO',
      'LOW',
      'CERTAIN',
    ]);
    expect(ids(sandbox003.check(ctxFor('<iframe allow="camera *" src="/x"></iframe>')))).toEqual([
      'PANE-SANDBOX-003',
    ]);
    expect(sandbox003.check(ctxFor('<iframe allow="camera \'self\'" src="/x"></iframe>')).findings).toEqual(
      [],
    );
  });

  it('-004 is INFO / LOW / CERTAIN and says opaque origins send no referrer', () => {
    expect([sandbox004.ruleClass, sandbox004.severity, sandbox004.confidence]).toEqual([
      'INFO',
      'LOW',
      'CERTAIN',
    ]);
    const r = sandbox004.check(ctxFor('<iframe referrerpolicy="unsafe-url" src="/x"></iframe>'));
    expect(ids(r)).toEqual(['PANE-SANDBOX-004']);
    expect(r.findings[0]!.message).toMatch(/opaque|about:srcdoc|blob:/i);
  });

  it('-004 does not fire on any other referrer policy', () => {
    expect(
      sandbox004.check(ctxFor('<iframe referrerpolicy="no-referrer" src="/x"></iframe>')).findings,
    ).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// PANE-SANDBOX-005 / -006 — declared vs used
// ---------------------------------------------------------------------------

describe('PANE-SANDBOX-006 — under-declared use is the attacker direction', () => {
  it('produces ZERO findings on feature detection that never invokes anything', () => {
    // "Apps SHOULD NOT assume permissions are granted; use JS feature detection
    // as fallback" — SPEC-REFERENCE §3.2. A member-access matcher flags the
    // spec-RECOMMENDED pattern.
    const r = sandbox006.check(ctxFor(fixture('nondetect/feature-detection.html'), {}));
    expect(r.findings).toEqual([]);
  });

  it('fires on an actual getCurrentPosition invocation with nothing declared', () => {
    const html = '<script>navigator.geolocation.getCurrentPosition(show)</script>';
    const r = sandbox006.check(ctxFor(html, {}));
    expect(ids(r)).toEqual(['PANE-SANDBOX-006']);
    expect(r.findings[0]!.message).toMatch(/geolocation/);
    expect(r.findings[0]!.assumption).toBe(HOST_SANDBOX_ASSUMPTION);
  });

  it('does not fire when the permission is declared', () => {
    const html = '<script>navigator.geolocation.getCurrentPosition(show)</script>';
    expect(sandbox006.check(ctxFor(html, { permissions: { geolocation: {} } })).findings).toEqual([]);
  });

  it('reads getUserMedia constraints rather than assuming both camera and microphone', () => {
    const html = '<script>navigator.mediaDevices.getUserMedia({ audio: true })</script>';
    const r = sandbox006.check(ctxFor(html, { permissions: { camera: {} } }));
    expect(ids(r)).toEqual(['PANE-SANDBOX-006']);
    expect(r.findings[0]!.message).toMatch(/microphone/);
    expect(r.findings[0]!.message).not.toMatch(/camera/);
  });

  it('fires on clipboard.writeText but not on reading navigator.clipboard', () => {
    expect(
      ids(sandbox006.check(ctxFor('<script>navigator.clipboard.writeText(t)</script>', {}))),
    ).toEqual(['PANE-SANDBOX-006']);
    expect(
      sandbox006.check(ctxFor('<script>const ok = Boolean(navigator.clipboard)</script>', {}))
        .findings,
    ).toEqual([]);
  });

  it('is RISK / MEDIUM / HIGH and requires meta', () => {
    expect([sandbox006.ruleClass, sandbox006.severity, sandbox006.confidence]).toEqual([
      'RISK',
      'MEDIUM',
      'HIGH',
    ]);
    expect(sandbox006.requires).toContain('meta');
  });
});

describe('PANE-SANDBOX-005 — over-declaration is untidy, not dangerous', () => {
  it('is RISK / LOW / MEDIUM and requires meta', () => {
    expect([sandbox005.ruleClass, sandbox005.severity, sandbox005.confidence]).toEqual([
      'RISK',
      'LOW',
      'MEDIUM',
    ]);
    expect(sandbox005.requires).toContain('meta');
  });

  it('fires on a declared permission the HTML never mentions', () => {
    const r = sandbox005.check(ctxFor('<p>chart</p>', { permissions: { camera: {} } }));
    expect(ids(r)).toEqual(['PANE-SANDBOX-005']);
    expect(r.findings[0]!.jsonPointer).toBe('/_meta/ui/permissions/camera');
  });

  it('counts feature detection as use — the asymmetry with -006 is deliberate', () => {
    const html = '<script>if (navigator.geolocation) { render(); }</script>';
    expect(sandbox005.check(ctxFor(html, { permissions: { geolocation: {} } })).findings).toEqual([]);
  });

  it('declines to answer when the document loads a script it cannot read', () => {
    const html = '<script src="./app.js"></script>';
    const r = sandbox005.check(ctxFor(html, { permissions: { camera: {} } }));
    expect(r.findings).toEqual([]);
    expect(r.undecided ?? []).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// PANE-SANDBOX-007 — re-delegation
// ---------------------------------------------------------------------------

describe('PANE-SANDBOX-007 — the genuinely dangerous version of -003', () => {
  it('is RISK / HIGH / CERTAIN', () => {
    expect([sandbox007.ruleClass, sandbox007.severity, sandbox007.confidence]).toEqual([
      'RISK',
      'HIGH',
      'CERTAIN',
    ]);
  });

  it('fires when a declared permission is handed to a third-party frame', () => {
    const html = '<iframe src="https://widgets.other.example/cam" allow="camera *"></iframe>';
    const r = sandbox007.check(ctxFor(html, { permissions: { camera: {} } }));
    expect(ids(r)).toEqual(['PANE-SANDBOX-007']);
    expect(r.findings[0]!.message).toMatch(/widgets\.other\.example/);
  });

  it('maps clipboardWrite to the clipboard-write feature name', () => {
    const html = '<iframe src="https://other.example/x" allow="clipboard-write"></iframe>';
    expect(ids(sandbox007.check(ctxFor(html, { permissions: { clipboardWrite: {} } })))).toEqual([
      'PANE-SANDBOX-007',
    ]);
  });

  it('does not fire on a same-document (relative) frame', () => {
    const html = '<iframe src="/inner.html" allow="camera"></iframe>';
    expect(sandbox007.check(ctxFor(html, { permissions: { camera: {} } })).findings).toEqual([]);
  });

  it('does not fire on a permission the server never declared', () => {
    const html = '<iframe src="https://other.example/x" allow="microphone"></iframe>';
    expect(sandbox007.check(ctxFor(html, { permissions: { camera: {} } })).findings).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Family-wide invariants
// ---------------------------------------------------------------------------

describe('family invariants', () => {
  it('every finding in the family carries the host-sandbox conditionality', () => {
    const cases: Array<[(typeof ALL)[number], string, UIResourceMeta | null]> = [
      [
        sandbox001,
        '<iframe sandbox="allow-scripts allow-same-origin" src="https://a.example/x"></iframe>',
        { domain: 'a.example' },
      ],
      [sandbox002, '<iframe src="/x"></iframe>', null],
      [sandbox003, '<iframe allow="camera *" src="/x"></iframe>', null],
      [sandbox004, '<iframe referrerpolicy="unsafe-url" src="/x"></iframe>', null],
      [sandbox005, '<p>x</p>', { permissions: { camera: {} } }],
      [sandbox006, '<script>navigator.geolocation.getCurrentPosition(f)</script>', {}],
      [
        sandbox007,
        '<iframe src="https://other.example/x" allow="camera"></iframe>',
        { permissions: { camera: {} } },
      ],
    ];
    for (const [rule, html, meta] of cases) {
      const r = rule.check(ctxFor(html, meta));
      expect(r.findings.length, rule.id).toBeGreaterThan(0);
      for (const f of r.findings) {
        expect(f.assumption, rule.id).toBe(HOST_SANDBOX_ASSUMPTION);
        expect(f.message, rule.id).toMatch(/nested|ancestor|host|sandbox/i);
      }
    }
  });

  it('ids and metadata match the RULES.md table', () => {
    const table: Record<string, [string, string, string]> = {
      'PANE-SANDBOX-001': ['RISK', 'CRITICAL', 'HIGH'],
      'PANE-SANDBOX-002': ['INFO', 'LOW', 'CERTAIN'],
      'PANE-SANDBOX-003': ['INFO', 'LOW', 'CERTAIN'],
      'PANE-SANDBOX-004': ['INFO', 'LOW', 'CERTAIN'],
      'PANE-SANDBOX-005': ['RISK', 'LOW', 'MEDIUM'],
      'PANE-SANDBOX-006': ['RISK', 'MEDIUM', 'HIGH'],
      'PANE-SANDBOX-007': ['RISK', 'HIGH', 'CERTAIN'],
    };
    expect(ALL.map((r) => r.id)).toEqual(Object.keys(table));
    for (const r of ALL) {
      expect([r.ruleClass, r.severity, r.confidence], r.id).toEqual(table[r.id]);
      expect(r.experimental, r.id).toBe(false);
      expect(r.status, r.id).toBe('active');
      expect(r.requires.length, r.id).toBeGreaterThan(0);
    }
  });

  it('a plain app with no frames and no permissions produces nothing', () => {
    const ctx = ctxFor('<h1>chart</h1><p>no frames here</p>', {});
    for (const r of ALL) expect(r.check(ctx).findings, r.id).toEqual([]);
  });
});

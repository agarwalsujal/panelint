/**
 * PANE-MSG — `postMessage` handler hygiene.
 *
 * The negative half matters more than the positive half here, same as
 * PANE-DOM. The official `ext-apps` SDK registers its transport with
 * `window.addEventListener("message", this.messageListener)` — a METHOD
 * REFERENCE — and calls `this.eventTarget.postMessage(X, "*")` where
 * `eventTarget` defaults from `window.parent`. A rule that cannot see through
 * either indirection fires on the SDK's own transport inside every app that
 * bundles it. `fixtures/nondetect/ext-apps-1.7.5-app*.js` are the real
 * vendored bundle; PANE-MSG-001 and PANE-MSG-003 must score it clean.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { parseHtml } from '../src/parse/html.js';
import { buildStyleIndex } from '../src/parse/style-index.js';
import { collectScripts } from '../src/parse/js.js';
import { DEFAULT_LIMITS } from '../src/limits.js';
import { isGating } from '../src/exit.js';
import type { RuleContext, UIResource, UIResourceMeta } from '../src/types.js';

import msg001 from '../src/rules/msg/msg-001.js';
import msg002 from '../src/rules/msg/msg-002.js';
import msg003 from '../src/rules/msg/msg-003.js';
import msg004 from '../src/rules/msg/msg-004.js';

const FIXTURES = fileURLToPath(new URL('../fixtures/', import.meta.url));
const fixture = (rel: string): string => readFileSync(`${FIXTURES}${rel}`, 'utf8');

function ctxFor(html: string, meta: UIResourceMeta | null = null): RuleContext {
  const { dom } = parseHtml(html, DEFAULT_LIMITS);
  const resource: UIResource = {
    uri: 'ui://test/app',
    mimeType: 'text/html;charset=utf-8',
    content: html,
    schemaErrors: [],
    contentHash: 'sha256:test',
    source: 'directory',
    ...(meta ? { meta } : {}),
  };
  return {
    resource,
    dom,
    styles: buildStyleIndex(dom, DEFAULT_LIMITS),
    meta,
    schemaErrors: [],
    scripts: collectScripts(dom, html, DEFAULT_LIMITS),
    rawSource: html,
    options: {},
    limits: DEFAULT_LIMITS,
    diagnostic() {},
  };
}

const js = (code: string) => ctxFor(`<div id="root"></div><script>${code}</script>`);
const ids = (r: { findings: { ruleId: string }[] }) => r.findings.map((f) => f.ruleId);

/** The real vendored ext-apps SDK bundle. See test/rules-dom.test.ts for provenance. */
function sdkBundleHtml(): string {
  const app = fixture('nondetect/ext-apps-1.7.5-app.js');
  const bridge = fixture('nondetect/ext-apps-1.7.5-app-bridge.js');
  return [
    '<!doctype html><meta charset="utf-8"><title>App</title><div id="root"></div>',
    `<script type="module">${app}</script>`,
    `<script type="module">${bridge}</script>`,
    '<script type="module">document.getElementById("root").textContent = "ready";</script>',
  ].join('\n');
}

// ---------------------------------------------------------------------------
// PANE-MSG-001 — inverted polarity: the finding is the ABSENCE of a check
// ---------------------------------------------------------------------------

describe('PANE-MSG-001 — no origin or source check', () => {
  it('declares the contract from the RULES.md table', () => {
    expect(msg001.id).toBe('PANE-MSG-001');
    expect([msg001.ruleClass, msg001.severity, msg001.confidence]).toEqual(['RISK', 'HIGH', 'HIGH']);
    expect(msg001.experimental).toBe(false);
    expect(msg001.requires).toContain('content');
  });

  it('fires on an inline handler with neither check, that reads event.data', () => {
    const r = msg001.check(ctxFor(fixture('malicious/msg/no-origin-check.html')));
    expect(ids(r)).toEqual(['PANE-MSG-001']);
    expect(isGating(r.findings[0]!, 'HIGH')).toBe(true);
  });

  it('does not fire when the handler checks event.origin with strict equality', () => {
    const r = msg001.check(ctxFor(fixture('nondetect/msg/checked-origin.html')));
    expect(r.findings).toEqual([]);
  });

  it('does not fire when the handler checks event.source', () => {
    const r = msg001.check(
      js('window.addEventListener("message", function (e) { if (e.source !== window.parent) return; use(e.data); });'),
    );
    expect(r.findings).toEqual([]);
  });

  it('does not fire on a handler that never reads event.data', () => {
    const r = msg001.check(
      js('window.addEventListener("message", function (e) { console.log("got a message"); });'),
    );
    expect(r.findings).toEqual([]);
  });

  it('declines to answer for a method-reference handler — never a finding', () => {
    const r = msg001.check(js('window.addEventListener("message", this.messageListener);'));
    expect(r.findings).toEqual([]);
    expect(r.undecided ?? []).toHaveLength(1);
    expect(r.undecided![0]!.reason).toMatch(/name\/reference/);
  });

  it('declines to answer for a named-function handler — never a finding', () => {
    const r = msg001.check(js('function onMessage(e) { use(e.data); } window.addEventListener("message", onMessage);'));
    expect(r.findings).toEqual([]);
    expect(r.undecided ?? []).toHaveLength(1);
  });

  it('produces ZERO findings on the real vendored ext-apps SDK bundle', () => {
    const ctx = ctxFor(sdkBundleHtml());
    expect(ctx.scripts.filter((s) => s.ast === null)).toHaveLength(0);
    expect(msg001.check(ctx).findings).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// PANE-MSG-002 — weak origin checks
// ---------------------------------------------------------------------------

describe('PANE-MSG-002 — substring or unanchored-regex origin check', () => {
  it('declares the contract from the RULES.md table', () => {
    expect([msg002.ruleClass, msg002.severity, msg002.confidence]).toEqual(['RISK', 'HIGH', 'CERTAIN']);
  });

  it('fires on startsWith and on an unanchored regex, one finding each', () => {
    const r = msg002.check(ctxFor(fixture('malicious/msg/weak-origin-check.html')));
    expect(ids(r)).toEqual(['PANE-MSG-002', 'PANE-MSG-002']);
  });

  it('does not fire on strict equality', () => {
    const r = msg002.check(ctxFor(fixture('nondetect/msg/checked-origin.html')));
    expect(r.findings).toEqual([]);
  });

  it('does not fire on a fully-anchored regex', () => {
    const r = msg002.check(
      js('window.addEventListener("message", function (e) { if (/^https:\\/\\/good\\.example$/.test(e.origin)) use(e.data); });'),
    );
    expect(r.findings).toEqual([]);
  });

  it('never constructs or executes the app-supplied pattern — reads the literal source text only', () => {
    // A pathological pattern that would be expensive to actually run if
    // Panelint ever called new RegExp(evil).test(realOrigin) itself. It does
    // not: the anchor question is answered by reading the acorn regex
    // literal's parsed `.regex.pattern` field. A `new RegExp(...)` construction
    // has no such literal to read, so its anchoring is UNKNOWN and is reported
    // as weak — the conservative, honest answer, not a guess.
    const evil = '(a+)+$';
    const r = msg002.check(
      js(`window.addEventListener("message", function (e) { if (new RegExp("${evil}").test(e.origin)) use(e.data); });`),
    );
    expect(ids(r)).toEqual(['PANE-MSG-002']);
    expect(r.findings[0]!.evidence).toBe('unanchored regex on origin');
  });

  it('declines to answer for an unresolvable handler', () => {
    const r = msg002.check(js('window.addEventListener("message", this.messageListener);'));
    expect(r.findings).toEqual([]);
    expect(r.undecided ?? []).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// PANE-MSG-003 — postMessage to a target other than the host bridge
// ---------------------------------------------------------------------------

describe('PANE-MSG-003 — wildcard-origin postMessage to a non-bridge target', () => {
  it('declares the contract from the RULES.md table', () => {
    expect([msg003.ruleClass, msg003.severity, msg003.confidence]).toEqual(['RISK', 'MEDIUM', 'CERTAIN']);
  });

  it('fires when the target resolves to event.source', () => {
    const r = msg003.check(ctxFor(fixture('malicious/msg/wrong-target.html')));
    expect(ids(r)).toEqual(['PANE-MSG-003']);
    // MEDIUM severity: does not meet the default --fail-on of HIGH, even at
    // CERTAIN confidence.
    expect(isGating(r.findings[0]!, 'HIGH')).toBe(false);
    // But it CAN gate at a lower --fail-on threshold, unlike the four
    // MEDIUM-CONFIDENCE dataflow rules (PANE-MSG-004 etc.), which can never
    // gate at any threshold. CERTAIN confidence is what makes the difference.
    expect(isGating(r.findings[0]!, 'MEDIUM')).toBe(true);
  });

  it('fires on an iframe.contentWindow target', () => {
    const r = msg003.check(js('frame.contentWindow.postMessage(msg, "*");'));
    expect(ids(r)).toEqual(['PANE-MSG-003']);
  });

  it('does not fire on a direct window.parent target', () => {
    const r = msg003.check(ctxFor(fixture('nondetect/msg/checked-origin.html')));
    expect(r.findings).toEqual([]);
  });

  it('does not fire on postMessage with a specific origin, not "*"', () => {
    const r = msg003.check(js('event.source.postMessage(msg, "https://example.com");'));
    expect(r.findings).toEqual([]);
  });

  it('resolves one level of this.field indirection back to a window.parent-default parameter', () => {
    const r = msg003.check(
      js(`
        class Transport {
          constructor(target = window.parent) { this.eventTarget = target; }
          send(msg) { this.eventTarget.postMessage(msg, "*"); }
        }
      `),
    );
    expect(r.findings).toEqual([]);
  });

  it('declines to answer when this.field is assigned from an unresolvable parameter', () => {
    const r = msg003.check(
      js(`
        class Relay {
          constructor(win) { this.target = win; }
          send(msg) { this.target.postMessage(msg, "*"); }
        }
      `),
    );
    expect(r.findings).toEqual([]);
    expect(r.undecided ?? []).not.toHaveLength(0);
  });

  it('produces ZERO findings on the real vendored ext-apps SDK bundle', () => {
    const ctx = ctxFor(sdkBundleHtml());
    expect(msg003.check(ctx).findings).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// PANE-MSG-004 — event.data reaching a DOM or eval sink
// ---------------------------------------------------------------------------

describe('PANE-MSG-004 — event.data reaches a DOM or eval sink', () => {
  it('declares the contract from the RULES.md table', () => {
    expect([msg004.ruleClass, msg004.severity, msg004.confidence]).toEqual(['RISK', 'CRITICAL', 'MEDIUM']);
  });

  it('is MEDIUM confidence and therefore never gates, whatever the severity', () => {
    const r = msg004.check(
      js('window.addEventListener("message", function (e) { el.innerHTML = e.data.html; });'),
    );
    expect(ids(r)).toEqual(['PANE-MSG-004']);
    expect(isGating(r.findings[0]!, 'LOW')).toBe(false);
  });

  it('records an escape, and no finding, when the value reaches an unresolvable call', () => {
    const r = msg004.check(
      js('window.addEventListener("message", function (e) { render(e.data); });'),
    );
    expect(r.findings).toEqual([]);
    expect(r.undecided ?? []).not.toHaveLength(0);
  });

  it('does not fire on an unrelated sink value', () => {
    const r = msg004.check(
      js('window.addEventListener("message", function (e) { el.innerHTML = document.title; });'),
    );
    expect(r.findings).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Family invariants
// ---------------------------------------------------------------------------

describe('family invariants', () => {
  const ALL = [msg001, msg002, msg003, msg004];

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
    expect(ALL.map((r) => r.id)).toEqual(['PANE-MSG-001', 'PANE-MSG-002', 'PANE-MSG-003', 'PANE-MSG-004']);
  });

  it('an empty document produces nothing anywhere', () => {
    const ctx = ctxFor('<!doctype html><title>t</title><p>hello</p>');
    for (const r of ALL) expect(r.check(ctx).findings, r.id).toEqual([]);
  });

  it('all four MEDIUM-confidence rules in the wider dataflow set never gate — spot check on 004', () => {
    expect(msg004.confidence).toBe('MEDIUM');
  });
});

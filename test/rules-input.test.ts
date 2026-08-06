/**
 * PANE-INPUT — credential, PII, and clipboard harvesting.
 *
 * `PANE-INPUT-001` is the real generalization of `PANE-MIMIC-005` and is NOT
 * experimental (docs/RULES.md). The canonical payloads from that file are
 * asserted here permanently: a `cc-number` field pushed off-screen, and a
 * `street-address` field at `opacity:0`, neither with `type="password"`
 * anywhere.
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

import input001 from '../src/rules/input/input-001.js';
import input002 from '../src/rules/input/input-002.js';
import input003 from '../src/rules/input/input-003.js';
import input004 from '../src/rules/input/input-004.js';

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

const js = (code: string, meta: UIResourceMeta | null = null) =>
  ctxFor(`<div id="root"></div><script>${code}</script>`, meta);
const ids = (r: { findings: { ruleId: string }[] }) => r.findings.map((f) => f.ruleId);

// ---------------------------------------------------------------------------
// PANE-INPUT-001 — hidden credential/PII field
// ---------------------------------------------------------------------------

describe('PANE-INPUT-001 — credential- or PII-shaped input concealed by a carrier', () => {
  it('declares the contract from the RULES.md table', () => {
    expect(input001.id).toBe('PANE-INPUT-001');
    expect([input001.ruleClass, input001.severity, input001.confidence]).toEqual([
      'RISK',
      'CRITICAL',
      'HIGH',
    ]);
    expect(input001.experimental).toBe(false);
  });

  it('fires on the two canonical payloads: cc-number off-screen, street-address opacity:0', () => {
    const r = input001.check(ctxFor(fixture('malicious/input/hidden-payment-field.html')));
    expect(r.findings).toHaveLength(2);
    expect(new Set(ids(r))).toEqual(new Set(['PANE-INPUT-001']));
    expect(r.findings.every((f) => isGating(f, 'HIGH'))).toBe(true);
  });

  it('fires on type="password" hidden by display:none, with no autocomplete needed', () => {
    const r = input001.check(
      ctxFor('<input type="password" style="display:none" name="pw">'),
    );
    expect(ids(r)).toEqual(['PANE-INPUT-001']);
  });

  it('does not fire on the same fields when visible', () => {
    const r = input001.check(ctxFor(fixture('nondetect/input/visible-payment-field.html')));
    expect(r.findings).toEqual([]);
  });

  it('does not fire on an ordinary visible text input with no sensitive shape', () => {
    const r = input001.check(ctxFor('<input name="search" style="opacity:0">'));
    expect(r.findings).toEqual([]);
  });

  it('does not fire on type="hidden" — a genuinely inert field, not a concealed one', () => {
    const r = input001.check(ctxFor('<input type="hidden" autocomplete="cc-number" value="x">'));
    expect(r.findings).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// PANE-INPUT-002 — sensitive autocomplete disclosure
// ---------------------------------------------------------------------------

describe('PANE-INPUT-002 — autocomplete requests a sensitive group', () => {
  it('declares the contract from the RULES.md table', () => {
    expect([input002.ruleClass, input002.severity, input002.confidence]).toEqual([
      'RISK',
      'MEDIUM',
      'CERTAIN',
    ]);
  });

  it('fires regardless of visibility — capability disclosure, not concealment', () => {
    const r = input002.check(ctxFor(fixture('nondetect/input/visible-payment-field.html')));
    expect(r.findings).toHaveLength(2);
  });

  it('fires on each of the payment, address and identity groups', () => {
    const r = input002.check(
      ctxFor(`
        <input autocomplete="cc-number">
        <input autocomplete="street-address">
        <input autocomplete="email">
      `),
    );
    expect(r.findings).toHaveLength(3);
  });

  it('does not fire on a modifier token alone, or on an unlisted token', () => {
    const r = input002.check(
      ctxFor(`
        <input autocomplete="off">
        <input autocomplete="on">
        <input autocomplete="username-hint-not-real">
      `),
    );
    expect(r.findings).toEqual([]);
  });

  it('matches the field-name token in a multi-token value, ignoring the modifier', () => {
    const r = input002.check(ctxFor('<input autocomplete="shipping street-address">'));
    expect(ids(r)).toEqual(['PANE-INPUT-002']);
  });
});

// ---------------------------------------------------------------------------
// PANE-INPUT-003 — clipboard write, no permission gates it
// ---------------------------------------------------------------------------

describe('PANE-INPUT-003 — clipboard write with clipboardWrite not declared', () => {
  it('declares the contract from the RULES.md table', () => {
    expect(input003.id).toBe('PANE-INPUT-003');
    expect([input003.ruleClass, input003.severity, input003.confidence]).toEqual(['RISK', 'HIGH', 'HIGH']);
    expect(input003.requires).toContain('meta');
  });

  it('fires on a copy handler calling clipboardData.setData with no permission declared', () => {
    const r = input003.check(ctxFor(fixture('malicious/input/clipboard-swap.html')));
    expect(ids(r)).toEqual(['PANE-INPUT-003']);
    expect(isGating(r.findings[0]!, 'HIGH')).toBe(true);
  });

  it('fires on navigator.clipboard.writeText with no permission declared', () => {
    const r = input003.check(js('navigator.clipboard.writeText("replacement");'));
    expect(ids(r)).toEqual(['PANE-INPUT-003']);
  });

  it('does not fire when clipboardWrite IS declared', () => {
    const meta: UIResourceMeta = { permissions: { clipboardWrite: {} } };
    const r = input003.check(ctxFor(fixture('nondetect/input/clipboard-declared.html'), meta));
    expect(r.findings).toEqual([]);
  });

  it('a cut handler calling setData on a destructured clipboardData also counts', () => {
    const r = input003.check(
      js('document.addEventListener("cut", (e) => { const { clipboardData } = e; clipboardData.setData("text/plain", "x"); });'),
    );
    expect(ids(r)).toEqual(['PANE-INPUT-003']);
  });

  it('does not fire on an unrelated setData-shaped call', () => {
    const r = input003.check(js('formData.setData("k", "v");'));
    expect(r.findings).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// PANE-INPUT-004 — paste/drop reaching a sink
// ---------------------------------------------------------------------------

describe('PANE-INPUT-004 — pasted or dropped content reaches a sink', () => {
  it('declares the contract from the RULES.md table', () => {
    expect([input004.ruleClass, input004.severity, input004.confidence]).toEqual([
      'RISK',
      'MEDIUM',
      'MEDIUM',
    ]);
  });

  it('fires when a paste listener writes clipboardData into innerHTML', () => {
    const r = input004.check(
      js('document.addEventListener("paste", (e) => { el.innerHTML = e.clipboardData.getData("text/html"); });'),
    );
    expect(ids(r)).toEqual(['PANE-INPUT-004']);
    expect(isGating(r.findings[0]!, 'LOW')).toBe(false);
  });

  it('fires when a drop listener forwards dataTransfer to app.sendMessage', () => {
    const r = input004.check(
      js('zone.addEventListener("drop", (e) => { app.sendMessage({ text: e.dataTransfer.getData("text") }); });'),
    );
    expect(ids(r)).toEqual(['PANE-INPUT-004']);
  });

  it('records an escape, not a finding, when the value reaches an unresolvable call', () => {
    const r = input004.check(
      js('document.addEventListener("paste", (e) => { process(e.clipboardData.getData("text")); });'),
    );
    expect(r.findings).toEqual([]);
    expect(r.undecided ?? []).not.toHaveLength(0);
  });

  it('does not fire on an unrelated sink value', () => {
    const r = input004.check(
      js('document.addEventListener("paste", (e) => { el.innerHTML = document.title; });'),
    );
    expect(r.findings).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Family invariants
// ---------------------------------------------------------------------------

describe('family invariants', () => {
  const ALL = [input001, input002, input003, input004];

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
      'PANE-INPUT-001',
      'PANE-INPUT-002',
      'PANE-INPUT-003',
      'PANE-INPUT-004',
    ]);
  });

  it('an empty document produces nothing anywhere', () => {
    const ctx = ctxFor('<!doctype html><title>t</title><p>hello</p>', { permissions: { clipboardWrite: {} } });
    for (const r of ALL) expect(r.check(ctx).findings, r.id).toEqual([]);
  });
});

import { describe, it, expect } from 'vitest';
import { parseHtml } from '../src/parse/html.js';
import { collectScripts } from '../src/parse/js.js';
import { buildStyleIndex } from '../src/parse/style-index.js';
import { DEFAULT_LIMITS } from '../src/limits.js';
import { isGating } from '../src/exit.js';
import type { RuleContext, UIResource, UIResourceMeta } from '../src/types.js';

import { integrity001 } from '../src/rules/integrity/integrity-001.js';
import { integrity002 } from '../src/rules/integrity/integrity-002.js';

/**
 * PANE-INTEGRITY — attacker A4, supply chain. Two DOM predicates and one AST
 * predicate, because the dominant real-world shape is the dynamic one.
 */

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
    options: {},
    limits: DEFAULT_LIMITS,
    diagnostic: () => {},
  };
}

describe('PANE-INTEGRITY-001 — external subresource with no integrity', () => {
  it('declares the contract from the RULES.md table', () => {
    expect(integrity001.id).toBe('PANE-INTEGRITY-001');
    expect(integrity001.ruleClass).toBe('RISK');
    expect(integrity001.severity).toBe('MEDIUM');
    expect(integrity001.confidence).toBe('HIGH');
    expect(integrity001.requires).toEqual(['content']);
  });

  it('stays below the default gate — map-server follows the documented workaround', () => {
    const f = integrity001.check(
      ctxFor('<script src="https://cdn.example.com/lib.js"></script>'),
    ).findings[0]!;
    expect(isGating(f, 'HIGH')).toBe(false);
  });

  it('fires on a static cross-origin script and stylesheet', () => {
    const html = `
      <link rel="stylesheet" href="https://cdn.example.com/app.css">
      <script src="https://cdn.example.com/lib.js"></script>`;
    expect(integrity001.check(ctxFor(html)).findings).toHaveLength(2);
  });

  it('is silent when integrity is present, and on same-document subresources', () => {
    const html = `
      <script src="https://cdn.example.com/lib.js" integrity="sha384-abc" crossorigin="anonymous"></script>
      <link rel="stylesheet" href="https://cdn.example.com/a.css" integrity="sha384-abc" crossorigin>
      <script src="./local.js"></script>
      <link rel="stylesheet" href="/app.css">`;
    expect(integrity001.check(ctxFor(html)).findings).toEqual([]);
  });

  it('covers the DYNAMIC form — the dominant real-world case', () => {
    // map-server loads CesiumJS exactly this way, with a source comment
    // explaining that static <script src> tags do not work inside srcdoc
    // iframes. A rule that only reads markup is decorative.
    const html = `<script>
      // Static <script src> tags do not work inside srcdoc iframes.
      const s = document.createElement('script');
      s.src = 'https://cdn.example.com/cesium/Cesium.js';
      document.head.appendChild(s);
    </script>`;
    const findings = integrity001.check(ctxFor(html)).findings;
    expect(findings).toHaveLength(1);
    expect(findings[0]!.message).toMatch(/dynamic|created in JavaScript/i);
  });

  it('is silent when the dynamically created script sets integrity', () => {
    const html = `<script>
      const s = document.createElement('script');
      s.src = 'https://cdn.example.com/cesium/Cesium.js';
      s.integrity = 'sha384-abc';
      s.crossOrigin = 'anonymous';
      document.head.appendChild(s);
    </script>`;
    expect(integrity001.check(ctxFor(html)).findings).toEqual([]);
  });

  it('is silent on a dynamically created script with a same-document src', () => {
    const html = `<script>
      const s = document.createElement('script');
      s.src = './chunk.js';
      document.head.appendChild(s);
    </script>`;
    expect(integrity001.check(ctxFor(html)).findings).toEqual([]);
  });

  it('reports a non-literal dynamic src at MEDIUM confidence, not HIGH', () => {
    const html = `<script>
      const s = document.createElement('script');
      s.src = base + '/lib.js';
      document.head.appendChild(s);
    </script>`;
    const findings = integrity001.check(ctxFor(html)).findings;
    expect(findings).toHaveLength(1);
    expect(findings[0]!.confidence).toBe('MEDIUM');
  });

  it('finds a subresource inside <template>', () => {
    const html = `<template><script src="https://cdn.example.com/lib.js"></script></template>`;
    expect(integrity001.check(ctxFor(html)).findings).toHaveLength(1);
  });
});

describe('PANE-INTEGRITY-002 — integrity without crossorigin', () => {
  it('declares the contract from the RULES.md table', () => {
    expect(integrity002.id).toBe('PANE-INTEGRITY-002');
    expect(integrity002.ruleClass).toBe('RISK');
    expect(integrity002.severity).toBe('MEDIUM');
    expect(integrity002.confidence).toBe('CERTAIN');
  });

  it('fires on a cross-origin subresource whose SRI silently no-ops', () => {
    const html = `
      <script src="https://cdn.example.com/lib.js" integrity="sha384-abc"></script>
      <link rel="stylesheet" href="//cdn.example.com/a.css" integrity="sha384-abc">`;
    expect(integrity002.check(ctxFor(html)).findings).toHaveLength(2);
  });

  it('is silent on a SAME-ORIGIN subresource — CORS is not required there', () => {
    // The rule as written in RULES.md claims CERTAIN for something false in
    // this case: SRI on a same-origin subresource works without `crossorigin`.
    const html = `
      <script src="/app.js" integrity="sha384-abc"></script>
      <link rel="stylesheet" href="./app.css" integrity="sha384-abc">`;
    expect(integrity002.check(ctxFor(html)).findings).toEqual([]);
  });

  it('is silent when crossorigin is present in either spelling', () => {
    const html = `
      <script src="https://cdn.example.com/lib.js" integrity="sha384-abc" crossorigin></script>
      <link rel="stylesheet" href="https://cdn.example.com/a.css" integrity="sha384-abc" crossorigin="anonymous">`;
    expect(integrity002.check(ctxFor(html)).findings).toEqual([]);
  });

  it('does not double-report with PANE-INTEGRITY-001', () => {
    const html = `<script src="https://cdn.example.com/lib.js"></script>`;
    expect(integrity002.check(ctxFor(html)).findings).toEqual([]);
    expect(integrity001.check(ctxFor(html)).findings).toHaveLength(1);
  });
});

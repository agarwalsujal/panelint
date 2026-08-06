/**
 * PANE-DOM — string-to-DOM and evaluation sinks.
 *
 * The negative half of this file matters more than the positive half.
 * PANE-DOM-001 is RISK/HIGH/HIGH, which makes it gate-eligible under the
 * formula in docs/RULES.md, and its first draft produced eleven findings on a
 * reference server — every one a static icon SVG or an `innerHTML = ""` layer
 * clear. Those cases are asserted here permanently.
 */

import { readFileSync } from 'node:fs';
import { describe, it, expect } from 'vitest';
import { parseHtml } from '../src/parse/html.js';
import { buildStyleIndex } from '../src/parse/style-index.js';
import { collectScripts } from '../src/parse/js.js';
import { DEFAULT_LIMITS } from '../src/limits.js';
import type { RuleContext, UIResource, UIResourceMeta } from '../src/types.js';
import dom001 from '../src/rules/dom/dom-001.js';
import dom002 from '../src/rules/dom/dom-002.js';

export function ctxFor(html: string, meta: UIResourceMeta | null = null): RuleContext {
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
    tools: [],
    options: {},
    limits: DEFAULT_LIMITS,
    diagnostic() {},
  };
}

const js = (code: string) => ctxFor(`<div id="root"></div><script>${code}</script>`);

describe('PANE-DOM-001 — fires on a runtime-built value', () => {
  it('flags innerHTML assigned an identifier', () => {
    const r = dom001.check(js('el.innerHTML = data;'));
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]!.ruleId).toBe('PANE-DOM-001');
    expect(r.findings[0]!.severity).toBe('HIGH');
  });

  it('flags an interpolated template literal', () => {
    expect(dom001.check(js('el.innerHTML = `<p>${name}</p>`;')).findings).toHaveLength(1);
  });

  it('flags insertAdjacentHTML, document.write, setHTMLUnsafe and outerHTML', () => {
    const r = dom001.check(
      js(`
        a.insertAdjacentHTML("beforeend", row);
        document.write(chunk);
        b.setHTMLUnsafe(markup);
        c.outerHTML = replacement;
      `),
    );
    expect(r.findings).toHaveLength(4);
  });

  it('flags a sink inside an inline event-handler attribute', () => {
    const ctx = ctxFor('<button onclick="box.innerHTML = payload">go</button>');
    expect(dom001.check(ctx).findings).toHaveLength(1);
  });

  it('gives a location inside the document, not inside the script', () => {
    const ctx = ctxFor('<p>x</p>\n<p>y</p>\n<script>\nel.innerHTML = data;\n</script>');
    const loc = dom001.check(ctx).findings[0]!.location!;
    expect(loc.startLine).toBe(4);
  });
});

describe('PANE-DOM-001 — the eleven pdf-server false positives, permanently', () => {
  it('does not flag innerHTML = "" (a layer clear)', () => {
    expect(dom001.check(js('overlay.innerHTML = "";')).findings).toHaveLength(0);
  });

  it('does not flag a static icon-SVG string literal', () => {
    expect(
      dom001.check(js('btn.innerHTML = \'<svg viewBox="0 0 16 16"><path d="M1 1h14"/></svg>\';')).findings,
    ).toHaveLength(0);
  });

  it('does not flag a template literal with no interpolation', () => {
    expect(dom001.check(js('btn.innerHTML = `<span class="x">go</span>`;')).findings).toHaveLength(0);
  });

  it('does not flag a module-level const string referenced by name', () => {
    // pdf-server's pattern with one refactor applied. An Identifier is
    // non-literal unless the rule resolves it.
    const r = dom001.check(js('const ICON = \'<svg/>\'; btn.innerHTML = ICON;'));
    expect(r.findings).toHaveLength(0);
  });

  it('does not flag a concatenation of two resolved constants', () => {
    expect(dom001.check(js('const A = "<b>"; const B = "</b>"; el.innerHTML = A + "x" + B;')).findings).toHaveLength(0);
  });

  it('DOES flag a name that is reassigned, because it is no longer a constant', () => {
    expect(dom001.check(js('let ICON = "<svg/>"; ICON = fetchIcon(); el.innerHTML = ICON;')).findings).toHaveLength(1);
  });
});

describe('PANE-DOM-002 — intent signal, never an exploit', () => {
  it('is class INFO so it can never gate, whatever threejs-server does', () => {
    // threejs-server runs LLM-authored scene code through `new Function`. It is
    // the core mechanism of the app, with no alternative code path.
    const r = dom002.check(js('const scene = new Function("api", src); scene(api);'));
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]!.ruleClass).toBe('INFO');
    expect(dom002.ruleClass).toBe('INFO');
    expect(dom002.severity).toBe('MEDIUM');
  });

  it('flags eval and a string-argument timer', () => {
    expect(dom002.check(js('eval(code); setTimeout("tick()", 10);')).findings).toHaveLength(2);
  });

  it('does not flag a timer given a function', () => {
    expect(dom002.check(js('setTimeout(function () { tick(); }, 10); setInterval(tick, 10);')).findings).toHaveLength(0);
  });
});

describe('undecided — an unparsed script is not a clean script', () => {
  it('records a note instead of reporting clean', () => {
    const ctx = ctxFor('<script>function ( {</script>');
    const r = dom001.check(ctx);
    expect(r.findings).toHaveLength(0);
    expect(r.undecided).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// The negative fixture that matters most
// ---------------------------------------------------------------------------

/**
 * The real ext-apps SDK bundle, vendored byte-for-byte from
 * `node_modules/@modelcontextprotocol/ext-apps/dist/src/` at 1.7.5.
 *
 * MCP Apps resources are raw HTML with no build step, so apps INLINE this
 * bundle. Any rule that fires on it fires on every app in the ecosystem that
 * uses the official SDK. This is the highest-value assertion in the project.
 */
export function sdkBundleHtml(): string {
  const app = readFileSync(new URL('../fixtures/nondetect/ext-apps-1.7.5-app.js', import.meta.url), 'utf8');
  const bridge = readFileSync(
    new URL('../fixtures/nondetect/ext-apps-1.7.5-app-bridge.js', import.meta.url),
    'utf8',
  );
  return [
    '<!doctype html><meta charset="utf-8"><title>App</title><div id="root"></div>',
    `<script type="module">${app}</script>`,
    `<script type="module">${bridge}</script>`,
    '<script type="module">document.getElementById("root").textContent = "ready";</script>',
  ].join('\n');
}

describe('the vendored ext-apps SDK bundle', () => {
  const ctx = ctxFor(sdkBundleHtml());

  it('parses — a skipped parse would make the assertion vacuous', () => {
    expect(ctx.scripts.filter((s) => s.ast === null)).toHaveLength(0);
    expect(ctx.scripts.length).toBeGreaterThanOrEqual(3);
  });

  it('produces ZERO PANE-DOM-001 findings', () => {
    expect(dom001.check(ctx).findings).toEqual([]);
  });
});

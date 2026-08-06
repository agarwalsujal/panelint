/**
 * The shared dataflow pass.
 *
 * One intraprocedural reaching-definitions walk, reused by PANE-MSG-004,
 * PANE-INPUT-004, PANE-EXFIL-005 and PANE-CONTEXT-005. It is deliberately NOT a
 * taint engine: when a value escapes into a call it cannot resolve the pass
 * records an ESCAPE, and the rule that consumes it emits `undecided()` rather
 * than a finding. Every rule built on it ships at MEDIUM confidence, which per
 * the gate formula in docs/RULES.md means none of them can ever fail a build.
 */

import { describe, it, expect } from 'vitest';
import { parseHtml } from '../src/parse/html.js';
import { collectScripts } from '../src/parse/js.js';
import { DEFAULT_LIMITS } from '../src/limits.js';
import {
  analyseDataflow,
  isEffectivelyLiteral,
  messageListenerSites,
  moduleStringConstants,
} from '../src/rules/shared/dataflow.js';

function flowOf(js: string) {
  const html = `<script>${js}</script>`;
  const { dom } = parseHtml(html, DEFAULT_LIMITS);
  return analyseDataflow(collectScripts(dom, html, DEFAULT_LIMITS));
}

function scriptsOf(js: string) {
  const html = `<script>${js}</script>`;
  const { dom } = parseHtml(html, DEFAULT_LIMITS);
  return collectScripts(dom, html, DEFAULT_LIMITS);
}

describe('sources — the ingress points named in SPEC-REFERENCE §4', () => {
  it('treats the ui/notifications/tool-result handler as the primary source', () => {
    const df = flowOf('app.ontoolresult = (p) => { el.innerHTML = p.content[0].text; };');
    expect(df.sources.map((s) => s.kind)).toContain('tool-result');
    expect(df.flows).toHaveLength(1);
    expect(df.flows[0]!.source.kind).toBe('tool-result');
    expect(df.flows[0]!.sink.kind).toBe('dom-html');
  });

  it('recognises the addEventListener form of the same subscription', () => {
    const df = flowOf('app.addEventListener("toolresult", function (p) { host.innerHTML = p.text; });');
    expect(df.flows.map((f) => f.source.kind)).toEqual(['tool-result']);
  });

  it('recognises setNotificationHandler with the raw JSON-RPC method literal', () => {
    const df = flowOf(
      'app.setNotificationHandler({ method: "ui/notifications/tool-result" }, (n) => { box.innerHTML = n.params; });',
    );
    expect(df.flows.map((f) => f.source.kind)).toEqual(['tool-result']);
  });

  it('covers tool-input, tool-input-partial and host-context-changed', () => {
    const df = flowOf(`
      app.ontoolinput = (a) => { one.innerHTML = a.x; };
      app.ontoolinputpartial = (b) => { two.innerHTML = b.x; };
      app.onhostcontextchanged = (c) => { three.innerHTML = c.x; };
    `);
    expect(df.flows.map((f) => f.source.kind).sort()).toEqual([
      'host-context-changed',
      'tool-input',
      'tool-input-partial',
    ]);
  });

  it('treats event.data from a message listener as a source, but not event.origin', () => {
    const tainted = flowOf('window.addEventListener("message", (e) => { el.innerHTML = e.data.html; });');
    expect(tainted.flows.map((f) => f.source.kind)).toEqual(['message-event']);

    const originOnly = flowOf('window.addEventListener("message", (e) => { el.innerHTML = e.origin; });');
    expect(originOnly.flows).toHaveLength(0);
  });

  it('treats clipboardData and dataTransfer as sources', () => {
    const paste = flowOf('document.addEventListener("paste", (e) => { el.innerHTML = e.clipboardData.getData("text/html"); });');
    expect(paste.flows.map((f) => f.source.kind)).toEqual(['clipboard']);

    const drop = flowOf('zone.addEventListener("drop", (e) => { el.innerHTML = e.dataTransfer.getData("text"); });');
    expect(drop.flows.map((f) => f.source.kind)).toEqual(['drop']);
  });

  it('classifies a raw message listener that dispatches on the tool-result method as a tool-result source', () => {
    const df = flowOf(`
      window.addEventListener("message", (e) => {
        if (e.data.method === "ui/notifications/tool-result") { el.innerHTML = e.data.params.text; }
      });
    `);
    expect(df.flows.map((f) => f.source.kind)).toContain('tool-result');
  });
});

describe('sinks', () => {
  it('collects every DOM and eval sink', () => {
    const df = flowOf(`
      a.innerHTML = x;
      b.outerHTML = x;
      c.insertAdjacentHTML("beforeend", x);
      d.setHTMLUnsafe(x);
      document.write(x);
      eval(x);
      new Function("return " + x);
      setTimeout("go()", 10);
    `);
    const kinds = df.sinks.map((s) => s.kind);
    expect(kinds.filter((k) => k === 'dom-html')).toHaveLength(5);
    expect(kinds.filter((k) => k === 'eval')).toHaveLength(3);
  });

  it('does not treat setTimeout with a function argument as an eval sink', () => {
    const df = flowOf('setTimeout(function () { go(); }, 10); setTimeout(cb, 10);');
    expect(df.sinks.filter((s) => s.kind === 'eval')).toHaveLength(0);
  });

  it('collects the four host-RPC sinks by call site', () => {
    const df = flowOf(`
      app.sendMessage({ text: "hi" });
      app.updateModelContext({ content: [] });
      app.downloadFile({ name: "a" });
      app.openLink({ url: "https://example.com" });
    `);
    expect(df.sinks.map((s) => s.kind).sort()).toEqual([
      'ui/download-file',
      'ui/message',
      'ui/open-link',
      'ui/update-model-context',
    ]);
  });

  it('finds no host-RPC sink in an inlined SDK bundle that merely contains the method literals', () => {
    // The empirical requirement recorded at the top of src/parse/js.ts.
    const df = flowOf(`
      const METHODS = { MESSAGE: "ui/message", CTX: "ui/update-model-context", DL: "ui/download-file" };
      const SCHEMA = { "McpUiMessageRequest": { "description": "ui/message" } };
    `);
    expect(df.sinks).toHaveLength(0);
  });
});

describe('propagation — assignment chains within one function', () => {
  it('follows a const chain from source to sink', () => {
    const df = flowOf(`
      app.ontoolresult = (p) => {
        const raw = p.content;
        const html = "<div>" + raw + "</div>";
        el.innerHTML = html;
      };
    `);
    expect(df.flows).toHaveLength(1);
    expect(df.flows[0]!.via).toContain('html');
  });

  it('follows destructuring', () => {
    const df = flowOf('app.ontoolresult = (p) => { const { content } = p; el.innerHTML = content; };');
    expect(df.flows).toHaveLength(1);
  });

  it('binds the callback parameter of an array iteration on a tainted receiver', () => {
    const df = flowOf('app.ontoolresult = (p) => { p.content.forEach((c) => { el.innerHTML += c.text; }); };');
    expect(df.flows).toHaveLength(1);
  });

  it('does not report a flow when the sink value is unrelated to the source', () => {
    const df = flowOf('app.ontoolresult = (p) => { el.innerHTML = document.title; };');
    expect(df.flows).toHaveLength(0);
  });

  it('treats a sanitizer call as clearing taint', () => {
    const df = flowOf('app.ontoolresult = (p) => { el.innerHTML = DOMPurify.sanitize(p.content); };');
    expect(df.flows).toHaveLength(0);
  });
});

describe('escapes — the honest half of the pass', () => {
  it('records an escape, and no flow, when a tainted value enters an unresolvable call', () => {
    const df = flowOf('app.ontoolresult = (p) => { render(p.content); };');
    expect(df.flows).toHaveLength(0);
    expect(df.escapesFrom(['tool-result'])).not.toHaveLength(0);
  });

  it('records unparsed scripts, because an unparsed script is an incomplete analysis', () => {
    const html = '<script>function ( {</script>';
    const { dom } = parseHtml(html, DEFAULT_LIMITS);
    const df = analyseDataflow(collectScripts(dom, html, DEFAULT_LIMITS));
    expect(df.unparsedScripts).toHaveLength(1);
  });
});

describe('messageListenerSites — unresolvable handlers must be REPORTED, never skipped', () => {
  /**
   * The single most dangerous shape in the catalog. The shipped ext-apps SDK
   * registers `addEventListener("message", this.messageListener)` — a method
   * REFERENCE. A rule whose finding is the ABSENCE of a check sees no body,
   * concludes "no origin check", and emits a gate-eligible HIGH on the SDK's
   * own transport inside every app that bundles it.
   */
  it('reports a method-reference handler as unresolved', () => {
    const sites = messageListenerSites(scriptsOf('window.addEventListener("message", this.messageListener);'));
    expect(sites).toHaveLength(1);
    expect(sites[0]!.resolved).toBeNull();
    expect(sites[0]!.handlerKind).toBe('reference');
  });

  it('reports a named-function handler as unresolved', () => {
    const sites = messageListenerSites(scriptsOf('window.addEventListener("message", onMessage);'));
    expect(sites[0]!.resolved).toBeNull();
  });

  it('resolves an inline handler and characterises its checks', () => {
    const sites = messageListenerSites(
      scriptsOf('window.addEventListener("message", (e) => { if (e.origin !== HOST) return; use(e.data); });'),
    );
    expect(sites).toHaveLength(1);
    expect(sites[0]!.resolved?.checksOrigin).toBe(true);
  });
});

describe('isEffectivelyLiteral — const propagation', () => {
  it('resolves a module-level const string through an identifier', () => {
    const scripts = scriptsOf('const ICON = "<svg/>"; el.innerHTML = ICON;');
    const consts = moduleStringConstants(scripts);
    expect(consts.has('ICON')).toBe(true);

    const df = analyseDataflow(scripts);
    const sink = df.sinks.find((s) => s.kind === 'dom-html')!;
    expect(isEffectivelyLiteral(sink.valueNode!, consts)).toBe(true);
  });

  it('does not resolve a const that is reassigned or non-literal', () => {
    const consts = moduleStringConstants(scriptsOf('let ICON = "<svg/>"; ICON = fetchIcon();'));
    expect(consts.has('ICON')).toBe(false);
  });

  it('treats a concatenation of two resolved constants as literal', () => {
    const scripts = scriptsOf('const A = "<b>"; const B = "</b>"; el.innerHTML = A + B;');
    const consts = moduleStringConstants(scripts);
    const df = analyseDataflow(scripts);
    const sink = df.sinks.find((s) => s.kind === 'dom-html')!;
    expect(isEffectivelyLiteral(sink.valueNode!, consts)).toBe(true);
  });
});

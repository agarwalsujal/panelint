import { describe, it, expect } from 'vitest';
import { parseHtml } from '../src/parse/html.js';
import { collectScripts, findCalls, findMemberAssignments, isLiteralExpression, findMessageListeners } from '../src/parse/js.js';
import { DEFAULT_LIMITS } from '../src/limits.js';

function scriptsOf(html: string) {
  const { dom } = parseHtml(html, DEFAULT_LIMITS);
  return collectScripts(dom, html, DEFAULT_LIMITS);
}

describe('collectScripts', () => {
  it('collects inline <script> text with its offset', () => {
    const s = scriptsOf('<script>var a = 1;</script>');
    expect(s).toHaveLength(1);
    expect(s[0]!.code).toContain('var a = 1');
    expect(s[0]!.ast).not.toBeNull();
  });

  it('collects inline event-handler attributes as scripts', () => {
    // 'unsafe-inline' is mandated, so inline handlers are in-policy — but the
    // DOM sinks they reach are still covered by PANE-DOM.
    const s = scriptsOf('<button onclick="el.innerHTML = data">x</button>');
    expect(s.some((x) => x.code.includes('innerHTML'))).toBe(true);
  });

  it('skips non-JS script types', () => {
    expect(scriptsOf('<script type="application/json">{"a":1}</script>')).toHaveLength(0);
    expect(scriptsOf('<script type="text/template"><p>x</p></script>')).toHaveLength(0);
  });

  it('treats type=module and unknown-but-JS types as JS', () => {
    expect(scriptsOf('<script type="module">import x from "y"</script>')).toHaveLength(1);
  });

  it('records a parse error rather than throwing on invalid JS', () => {
    const s = scriptsOf('<script>function ( { </script>');
    expect(s[0]!.ast).toBeNull();
    expect(s[0]!.parseError).toBeTruthy();
  });

  it('skips a script over the byte ceiling with a diagnostic', () => {
    const big = 'var x = 1;'.repeat(500);
    const { dom } = parseHtml(`<script>${big}</script>`, DEFAULT_LIMITS);
    const s = collectScripts(dom, '', { ...DEFAULT_LIMITS, maxScriptBytes: 100 });
    expect(s[0]?.ast).toBeNull();
  });
});

describe('findCalls — call-site detection, not string matching', () => {
  /**
   * The empirical requirement. MCP Apps resources are raw HTML with no build
   * step, so apps INLINE the ext-apps SDK bundle, which contains the literal
   * strings 'ui/message', 'ui/update-model-context' and 'ui/download-file'
   * whether or not the app ever calls them. Verified in two independent
   * third-party servers during the 2026-08-05 hand-scan. A naive
   * content.includes("ui/message") fires on every SDK-bundling app.
   */
  const BUNDLED_SDK = `
    const METHODS = { MESSAGE: "ui/message", CTX: "ui/update-model-context",
                      DL: "ui/download-file", LINK: "ui/open-link" };
    const SCHEMA = {"McpUiResourceCsp":{"description":"ui/message ui/download-file"}};
    export class AppBridge { constructor(){ this.methods = METHODS; } }
  `;

  it('finds no call sites in an inlined SDK bundle that merely contains the literals', () => {
    const s = scriptsOf(`<script>${BUNDLED_SDK}</script>`);
    const calls = findCalls(s, [{ object: 'app', method: 'sendMessage' }]);
    expect(calls).toHaveLength(0);
  });

  it('finds an actual app.sendMessage call site', () => {
    const s = scriptsOf('<script>app.sendMessage({text: "hi"})</script>');
    expect(findCalls(s, [{ object: 'app', method: 'sendMessage' }])).toHaveLength(1);
  });

  it('matches a method on any receiver when object is omitted', () => {
    const s = scriptsOf('<script>bridge.updateModelContext(x); window.foo.updateModelContext(y);</script>');
    expect(findCalls(s, [{ method: 'updateModelContext' }])).toHaveLength(2);
  });

  it('finds a raw JSON-RPC method property value', () => {
    // The other legitimate detection path: a hand-rolled client writing
    // { method: "ui/message" } as an object property, which is a call in
    // substance even though no SDK method name appears.
    const s = scriptsOf('<script>send({ method: "ui/message", params: {} })</script>');
    expect(findCalls(s, [{ rpcMethod: 'ui/message' }])).toHaveLength(1);
  });

  it('does NOT treat a method literal in a plain string or object value as a call', () => {
    const s = scriptsOf('<script>const label = "ui/message"; const m = {name: "ui/message"};</script>');
    expect(findCalls(s, [{ rpcMethod: 'ui/message' }])).toHaveLength(0);
  });

  it('finds a bare function call like eval or Function', () => {
    const s = scriptsOf('<script>eval(userInput); new Function("return 1");</script>');
    expect(findCalls(s, [{ callee: 'eval' }])).toHaveLength(1);
    expect(findCalls(s, [{ construct: 'Function' }])).toHaveLength(1);
  });
});

describe('isLiteralExpression — what keeps PANE-DOM-001 off pdf-server', () => {
  /**
   * As first written, "any assignment to innerHTML" produced 11 findings on
   * pdf-server, every one a static icon-SVG literal or innerHTML = "" to clear
   * a layer. None can carry injected content. At HIGH the rule is gate-eligible,
   * so that alone would have failed the corpus gate.
   */
  const lit = (src: string) => {
    const s = scriptsOf(`<script>x.innerHTML = ${src}</script>`);
    const a = findMemberAssignments(s, ['innerHTML']);
    expect(a).toHaveLength(1);
    return isLiteralExpression(a[0]!.right);
  };

  it('counts a plain string literal as literal', () => {
    expect(lit('"<svg><path d=\'M0 0\'/></svg>"')).toBe(true);
  });

  it('counts the empty string as literal', () => {
    expect(lit('""')).toBe(true);
  });

  it('counts a template literal with no interpolation as literal', () => {
    expect(lit('`<div class="icon"></div>`')).toBe(true);
  });

  it('counts concatenation of two string literals as literal', () => {
    expect(lit('"<b>" + "</b>"')).toBe(true);
  });

  it('does NOT count a template literal with interpolation as literal', () => {
    expect(lit('`<p>${userData}</p>`')).toBe(false);
  });

  it('does NOT count an identifier as literal', () => {
    expect(lit('toolResult')).toBe(false);
  });

  it('does NOT count concatenation involving a variable as literal', () => {
    expect(lit('"<p>" + name + "</p>"')).toBe(false);
  });

  it('does NOT count a function call as literal', () => {
    expect(lit('render(data)')).toBe(false);
  });
});

describe('findMessageListeners — the victim-side handler', () => {
  it('finds a message listener and reports the absence of an origin or source check', () => {
    const s = scriptsOf(`<script>
      window.addEventListener('message', (e) => { document.body.innerHTML = e.data.html; });
    </script>`);
    const l = findMessageListeners(s);
    expect(l).toHaveLength(1);
    expect(l[0]!.checksOrigin).toBe(false);
    expect(l[0]!.checksSource).toBe(false);
  });

  it('recognises an event.origin check', () => {
    const s = scriptsOf(`<script>
      window.addEventListener('message', function (e) {
        if (e.origin !== 'https://host.example') return;
        handle(e.data);
      });
    </script>`);
    expect(findMessageListeners(s)[0]!.checksOrigin).toBe(true);
  });

  it('recognises an event.source identity check — the only defense the transport has', () => {
    const s = scriptsOf(`<script>
      window.addEventListener('message', function (e) {
        if (e.source !== expectedWindow) return;
        handle(e.data);
      });
    </script>`);
    expect(findMessageListeners(s)[0]!.checksSource).toBe(true);
  });

  it('flags a substring-shaped origin comparison', () => {
    const s = scriptsOf(`<script>
      window.addEventListener('message', function (e) {
        if (e.origin.indexOf('host.example') !== -1) handle(e.data);
      });
    </script>`);
    const l = findMessageListeners(s)[0]!;
    expect(l.weakOriginChecks.length).toBeGreaterThan(0);
  });

  it('does not flag an anchored regex origin test', () => {
    const s = scriptsOf(`<script>
      window.addEventListener('message', function (e) {
        if (/^https:\\/\\/host\\.example$/.test(e.origin)) handle(e.data);
      });
    </script>`);
    expect(findMessageListeners(s)[0]!.weakOriginChecks).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Sloppy-mode inline scripts
// ---------------------------------------------------------------------------

/**
 * An inline `<script>` body is CLASSIC, sloppy-mode code.
 *
 * 0.1.3 parsed every script with `sourceType: 'module'`, which is strict mode,
 * so constructs every browser executes became syntax errors. A syntax error
 * sets `ast: null`, and every AST rule reads that as "no script here" — so a
 * single prefix took a hostile script from PANE-MSG-001 + PANE-DOM-001 (both
 * HIGH, both gate-eligible) to a clean exit 0. The prefix costs the attacker
 * one line and changes nothing about what the browser runs.
 */
describe('classic scripts parse in sloppy mode', () => {
  const payload = 'window.addEventListener("message",function(e){document.body.innerHTML=e.data});';

  const sloppy: Array<[string, string]> = [
    ['a with statement', 'with(window){var z=1;}'],
    ['a legacy octal literal', 'var n = 0755;'],
    ['an HTML-like comment', '<!-- legacy\n'],
    ['duplicate parameter names', 'function f(a,a){}'],
    ['delete on a local binding', 'var q=1; delete q;'],
    ['a future-reserved word as an identifier', 'var interface = 1;'],
  ];

  for (const [what, prefix] of sloppy) {
    it(`still yields an AST with ${what}`, () => {
      const html = `<!doctype html><html><body><script>${prefix}${payload}</script></body></html>`;
      const { dom } = parseHtml(html, DEFAULT_LIMITS);
      const scripts = collectScripts(dom, html, DEFAULT_LIMITS);
      expect(scripts).toHaveLength(1);
      expect(scripts[0]!.ast, `${what} blanked the script`).not.toBeNull();
      expect(scripts[0]!.parseError).toBeUndefined();
    });
  }

  it('still parses a real module, which is what the fallback is for', () => {
    const html = `<!doctype html><html><body><script type="module">import x from "y"; ${payload}</script></body></html>`;
    const { dom } = parseHtml(html, DEFAULT_LIMITS);
    const scripts = collectScripts(dom, html, DEFAULT_LIMITS);
    expect(scripts[0]!.ast).not.toBeNull();
  });

  it('still reports a genuinely broken script as unparsed', () => {
    const html = '<!doctype html><html><body><script>function ( { ] )</script></body></html>';
    const { dom } = parseHtml(html, DEFAULT_LIMITS);
    const scripts = collectScripts(dom, html, DEFAULT_LIMITS);
    expect(scripts[0]!.ast).toBeNull();
    expect(scripts[0]!.parseError).toBeTruthy();
  });
});

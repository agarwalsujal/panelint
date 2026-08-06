/**
 * JavaScript → AST, and the queries rules run against it.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Why acorn is a hard requirement and not a refinement.
 *
 * MCP Apps resources are raw HTML with no build step, so apps INLINE the
 * ext-apps SDK bundle. That bundle contains the literal strings `ui/message`,
 * `ui/update-model-context` and `ui/download-file` whether or not the app ever
 * calls them — it embeds the full minified schema, including every method
 * literal. Verified in two independent third-party servers during the
 * 2026-08-05 hand-scan; origins redacted per CLAUDE.md §1.2. The synthesized
 * reproduction is `fixtures/nondetect/sdk-bundle-inlined.html`.
 *
 * So `content.includes("ui/message")` fires on every SDK-bundling app. Detection
 * must be CALL-SITE based: either an SDK method call (`app.sendMessage(`,
 * `app.updateModelContext(`, `app.openLink(`) or a raw JSON-RPC `method:`
 * property value in an object being passed somewhere.
 *
 * This is an empirical requirement, not a design preference.
 * ─────────────────────────────────────────────────────────────────────────────
 */

import { parse as acornParse } from 'acorn';
import type { Node } from 'acorn';
import { simple as walkSimple } from 'acorn-walk';
import { Element, type Document } from 'domhandler';
import { allElements, attr, attrLocations, selectAll } from './html.js';
import type { Limits, ScriptSource, SourceLocation } from '../types.js';

/** Attributes whose value is executable script. */
const EVENT_HANDLER_ATTRS = /^on[a-z]+$/i;

/** `type` values that mean "this is not JavaScript". */
const NON_JS_SCRIPT_TYPES = new Set([
  'application/json',
  'application/ld+json',
  'text/template',
  'text/x-template',
  'text/html',
  'text/plain',
  'importmap',
  'speculationrules',
]);

export interface ParsedScript extends ScriptSource {
  ast: Node | null;
  /**
   * Document line on which this script's text begins.
   *
   * acorn reports positions relative to the script, so a finding at script line
   * 3 is not document line 3. Without this rebase every SARIF location inside a
   * <script> points at the wrong line, which for a security tool rendering in
   * GitHub's Security tab is worse than no location at all.
   */
  startLine: number;
  /** Document column of the script's first character, for line-1 positions. */
  startCol: number;
}

/** Collect every executable script in the document: inline blocks and handlers. */
export function collectScripts(dom: Document, rawSource: string, limits: Limits): ParsedScript[] {
  const out: ParsedScript[] = [];

  for (const el of selectAll('script', dom)) {
    const type = (attr(el, 'type') ?? '').trim().toLowerCase();
    if (type && NON_JS_SCRIPT_TYPES.has(type)) continue;
    // An external script has no body we can see. `src` is PANE-INTEGRITY's
    // business, not ours.
    const code = el.children
      .map((c) => (c.type === 'text' ? (c as unknown as { data: string }).data : ''))
      .join('');
    if (!code.trim()) continue;
    const open = el.sourceCodeLocation?.startTag;
    out.push(
      makeScript(code, el, el.sourceCodeLocation?.startOffset ?? 0, limits, {
        startLine: open?.endLine ?? el.sourceCodeLocation?.startLine ?? 1,
        startCol: open?.endCol ?? 1,
      }),
    );
  }

  for (const el of allElements(dom)) {
    for (const [name, value] of Object.entries(el.attribs ?? {})) {
      if (!EVENT_HANDLER_ATTRS.test(name)) continue;
      if (!value.trim()) continue;
      const aloc = attrLocations(el)?.[name];
      out.push(
        makeScript(value, el, aloc?.startOffset ?? 0, limits, {
          startLine: aloc?.startLine ?? el.sourceCodeLocation?.startLine ?? 1,
          startCol: aloc?.startCol ?? 1,
        }),
      );
    }
  }

  void rawSource;
  return out;
}

function makeScript(
  code: string,
  element: Element,
  offset: number,
  limits: Limits,
  at: { startLine: number; startCol: number },
): ParsedScript {
  const base = { code, element, offset, startLine: at.startLine, startCol: at.startCol };
  if (Buffer.byteLength(code, 'utf8') > limits.maxScriptBytes) {
    return {
      ...base,
      ast: null,
      parseError: `script exceeds maxScriptBytes (${limits.maxScriptBytes})`,
    };
  }
  // ── Why this parses TWICE, script first ─────────────────────────────────
  // An inline `<script>` body and an `on*` attribute handler are CLASSIC,
  // sloppy-mode code. Parsing them as a module puts acorn in strict mode, where
  // constructs every browser executes are syntax errors — and a syntax error
  // here sets `ast: null`, which every AST rule treats as "no script to look
  // at". Each of these one-liners, prepended to a hostile script, blanked the
  // whole thing in 0.1.3 and took PANE-MSG-001 and PANE-DOM-001 (both HIGH and
  // gate-eligible) to exit 0:
  //
  //     with(window){var z=1;}      octal `var n = 0755;`
  //     <!-- legacy comment         function f(a,a){}
  //     arguments = 1               delete localVar
  //     var interface = 1
  //
  // Script mode is therefore the primary attempt. Module mode is the fallback,
  // because `import`/`export` are the only things it accepts that script mode
  // does not, and a real module carries `type="module"`.
  const shared = {
    ecmaVersion: 'latest' as const,
    allowReturnOutsideFunction: true,
    allowAwaitOutsideFunction: true,
    allowSuperOutsideMethod: true,
    allowHashBang: true,
    locations: true,
  };

  try {
    return { ...base, ast: acornParse(code, { ...shared, sourceType: 'script' }) };
  } catch {
    /* fall through to module mode */
  }

  try {
    const ast = acornParse(code, { ...shared, sourceType: 'module' });
    return { ...base, ast };
  } catch (e) {
    // A script that does not parse is a fact about the resource, not a crash.
    // Rules that need the AST decline to answer; string-level rules still run.
    return {
      ...base,
      ast: null,
      // Structural only. postcss and friends embed source frames in their
      // message text; acorn does not, but the rule is uniform so no future
      // dependency reintroduces the leak (see safe/untrusted.ts).
      parseError: e instanceof Error ? e.constructor.name : 'ParseError',
    };
  }
}

// ---------------------------------------------------------------------------
// Call-site queries
// ---------------------------------------------------------------------------

export interface CallMatcher {
  /** Receiver name, e.g. `app` in `app.sendMessage(...)`. Omit to match any. */
  object?: string;
  /** Method name, e.g. `sendMessage`. */
  method?: string;
  /** Bare callee name, e.g. `eval`. */
  callee?: string;
  /** `new X(...)`, e.g. `Function`. */
  construct?: string;
  /**
   * A raw JSON-RPC method string, matched only as the value of a `method:`
   * property inside an object — never as a bare string anywhere in the file,
   * which is what makes this survive an inlined SDK bundle.
   */
  rpcMethod?: string;
}

export interface CallSite {
  script: ParsedScript;
  node: Node;
  /** The matcher that produced this hit, for message text. */
  matched: CallMatcher;
  /** Argument nodes, for rules that ask whether an argument is a literal. */
  args: Node[];
  location?: SourceLocation;
}

export function findCalls(scripts: ParsedScript[], matchers: CallMatcher[]): CallSite[] {
  const out: CallSite[] = [];

  for (const script of scripts) {
    if (!script.ast) continue;

    walkSimple(script.ast, {
      CallExpression(node: Node) {
        const call = node as unknown as { callee: Node; arguments: Node[] };
        for (const m of matchers) {
          if (m.rpcMethod || m.construct) continue;
          if (matchesCall(call.callee, m)) {
            out.push({ script, node, matched: m, args: call.arguments, location: locOf(script, node) });
          }
        }
      },
      NewExpression(node: Node) {
        const call = node as unknown as { callee: Node; arguments: Node[] };
        for (const m of matchers) {
          if (!m.construct) continue;
          if (identifierName(call.callee) === m.construct) {
            out.push({ script, node, matched: m, args: call.arguments ?? [], location: locOf(script, node) });
          }
        }
      },
      Property(node: Node) {
        const prop = node as unknown as { key: Node; value: Node; computed: boolean };
        for (const m of matchers) {
          if (!m.rpcMethod) continue;
          if (prop.computed) continue;
          if (propertyKeyName(prop.key) !== 'method') continue;
          const v = prop.value as unknown as { type: string; value?: unknown };
          if (v.type === 'Literal' && v.value === m.rpcMethod) {
            out.push({ script, node, matched: m, args: [], location: locOf(script, node) });
          }
        }
      },
    });
  }

  return out;
}

function matchesCall(callee: Node, m: CallMatcher): boolean {
  if (m.callee) return identifierName(callee) === m.callee;
  if (!m.method) return false;

  const c = callee as unknown as { type: string; object?: Node; property?: Node; computed?: boolean };
  if (c.type !== 'MemberExpression' || c.computed) return false;
  if (propertyKeyName(c.property!) !== m.method) return false;
  if (!m.object) return true;

  // `app.sendMessage(...)` and `window.app.sendMessage(...)` both count.
  const objName = identifierName(c.object!);
  if (objName === m.object) return true;
  const o = c.object as unknown as { type: string; property?: Node; computed?: boolean };
  if (o.type === 'MemberExpression' && !o.computed) {
    return propertyKeyName(o.property!) === m.object;
  }
  return false;
}

function identifierName(node: Node): string | null {
  const n = node as unknown as { type: string; name?: string };
  return n.type === 'Identifier' ? (n.name ?? null) : null;
}

function propertyKeyName(node: Node): string | null {
  const n = node as unknown as { type: string; name?: string; value?: unknown };
  if (n.type === 'Identifier') return n.name ?? null;
  if (n.type === 'Literal' && typeof n.value === 'string') return n.value;
  return null;
}

/**
 * Rebase an acorn position onto document coordinates.
 *
 * acorn counts from the start of the script text. Line 1 of the script sits on
 * the document line where the script began, offset by the opening tag's column;
 * every later line starts at column 1 of its own document line.
 */
function locOf(script: ParsedScript, node: Node): SourceLocation | undefined {
  const n = node as unknown as { loc?: { start: { line: number; column: number } } };
  if (!n.loc) return undefined;
  const scriptLine = n.loc.start.line;
  const scriptCol = n.loc.start.column + 1;
  return {
    startLine: script.startLine + scriptLine - 1,
    startCol: scriptLine === 1 ? script.startCol + scriptCol - 1 : scriptCol,
  };
}

// ---------------------------------------------------------------------------
// Assignment queries
// ---------------------------------------------------------------------------

export interface MemberAssignment {
  script: ParsedScript;
  node: Node;
  property: string;
  right: Node;
  location?: SourceLocation;
}

/** `x.innerHTML = …`, `el.setAttribute('action', …)` handled separately. */
export function findMemberAssignments(scripts: ParsedScript[], properties: string[]): MemberAssignment[] {
  const want = new Set(properties);
  const out: MemberAssignment[] = [];

  for (const script of scripts) {
    if (!script.ast) continue;
    walkSimple(script.ast, {
      AssignmentExpression(node: Node) {
        const a = node as unknown as { left: Node; right: Node; operator: string };
        const l = a.left as unknown as { type: string; property?: Node; computed?: boolean };
        if (l.type !== 'MemberExpression') return;
        const name = l.computed ? null : propertyKeyName(l.property!);
        if (!name || !want.has(name)) return;
        out.push({ script, node, property: name, right: a.right, location: locOf(script, node) });
      },
    });
  }
  return out;
}

/**
 * Is this expression a literal that cannot carry injected content?
 *
 * A template literal with NO interpolation and the empty string both count as
 * literal. This is the predicate that keeps PANE-DOM-001 off pdf-server's 11
 * static icon-SVG assignments and `innerHTML = ""` layer clears — the finding
 * set that would otherwise have failed the corpus gate on its own.
 */
export function isLiteralExpression(node: Node): boolean {
  const n = node as unknown as {
    type: string;
    value?: unknown;
    expressions?: Node[];
    left?: Node;
    right?: Node;
    operator?: string;
    quasis?: unknown[];
  };

  switch (n.type) {
    case 'Literal':
      return true;
    case 'TemplateLiteral':
      return (n.expressions ?? []).length === 0;
    case 'BinaryExpression':
      // Concatenation of literals is still a literal.
      return n.operator === '+' && isLiteralExpression(n.left!) && isLiteralExpression(n.right!);
    default:
      return false;
  }
}

// ---------------------------------------------------------------------------
// postMessage handler analysis
// ---------------------------------------------------------------------------

export interface MessageListener {
  script: ParsedScript;
  node: Node;
  /** The event parameter's name, e.g. `e`. Null when destructured or absent. */
  paramName: string | null;
  checksOrigin: boolean;
  checksSource: boolean;
  /** Origin comparisons that are substring- or unanchored-regex-shaped. */
  weakOriginChecks: Array<{ kind: string; location?: SourceLocation }>;
  location?: SourceLocation;
}

const SUBSTRING_METHODS = new Set(['indexOf', 'startsWith', 'endsWith', 'includes', 'search', 'match']);

/**
 * Find `window.addEventListener('message', handler)` and characterise the
 * handler.
 *
 * The host side of cross-app message injection is out of scope per N2. The
 * VICTIM side — the app's own handler — ships inside the `ui://` resource HTML
 * and is fully statically visible. The transport sends with
 * `postMessage(msg, "*")` and validates inbound only by `event.source` identity,
 * and `window.frames[]` is cross-origin reachable, so an app that trusts
 * `event.data` without checking the source is directly drivable by a sibling app.
 */
export function findMessageListeners(scripts: ParsedScript[]): MessageListener[] {
  const out: MessageListener[] = [];

  for (const script of scripts) {
    if (!script.ast) continue;

    walkSimple(script.ast, {
      CallExpression(node: Node) {
        const call = node as unknown as { callee: Node; arguments: Node[] };
        const c = call.callee as unknown as { type: string; property?: Node; computed?: boolean };
        if (c.type !== 'MemberExpression' || c.computed) return;
        if (propertyKeyName(c.property!) !== 'addEventListener') return;

        const [evtArg, handler] = call.arguments;
        const e = evtArg as unknown as { type: string; value?: unknown } | undefined;
        if (!e || e.type !== 'Literal' || e.value !== 'message') return;
        if (!handler) return;

        const h = handler as unknown as { type: string; params?: Node[]; body?: Node };
        if (h.type !== 'FunctionExpression' && h.type !== 'ArrowFunctionExpression') return;

        const param = h.params?.[0];
        const paramName = param ? identifierName(param) : null;

        const analysis = analyseHandler(script, handler, paramName);
        out.push({
          script,
          node,
          paramName,
          ...analysis,
          location: locOf(script, node),
        });
      },
    });
  }

  return out;
}

function analyseHandler(
  script: ParsedScript,
  handler: Node,
  paramName: string | null,
): Pick<MessageListener, 'checksOrigin' | 'checksSource' | 'weakOriginChecks'> {
  let checksOrigin = false;
  let checksSource = false;
  const weakOriginChecks: MessageListener['weakOriginChecks'] = [];

  /** Is this node `<param>.origin` (or `.origin` on anything, if param unknown)? */
  const isEventProp = (n: Node | undefined, prop: string): boolean => {
    if (!n) return false;
    const m = n as unknown as { type: string; object?: Node; property?: Node; computed?: boolean };
    if (m.type !== 'MemberExpression' || m.computed) return false;
    if (propertyKeyName(m.property!) !== prop) return false;
    if (!paramName) return true;
    return identifierName(m.object!) === paramName;
  };

  walkSimple(handler, {
    BinaryExpression(node: Node) {
      const b = node as unknown as { left: Node; right: Node; operator: string };
      if (!['===', '!==', '==', '!='].includes(b.operator)) return;
      if (isEventProp(b.left, 'origin') || isEventProp(b.right, 'origin')) checksOrigin = true;
      if (isEventProp(b.left, 'source') || isEventProp(b.right, 'source')) checksSource = true;
    },

    CallExpression(node: Node) {
      const call = node as unknown as { callee: Node; arguments: Node[] };
      const c = call.callee as unknown as { type: string; object?: Node; property?: Node; computed?: boolean };
      if (c.type !== 'MemberExpression' || c.computed) return;
      const method = propertyKeyName(c.property!);
      if (!method) return;

      // `e.origin.indexOf(...)`, `e.origin.startsWith(...)` — a prefix or
      // substring test is not an origin check. `https://host.example.evil.tld`
      // passes startsWith, and `indexOf` passes anywhere in the string.
      if (SUBSTRING_METHODS.has(method) && isEventProp(c.object, 'origin')) {
        checksOrigin = true;
        weakOriginChecks.push({ kind: `origin.${method}()`, location: locOf(script, node) });
        return;
      }

      // `/regex/.test(e.origin)` — weak unless anchored at both ends.
      if (method === 'test' && call.arguments.some((a) => isEventProp(a, 'origin'))) {
        checksOrigin = true;
        const re = c.object as unknown as { type: string; regex?: { pattern: string } };
        const pattern = re.type === 'Literal' ? re.regex?.pattern : undefined;
        if (pattern === undefined || !(pattern.startsWith('^') && pattern.endsWith('$'))) {
          weakOriginChecks.push({ kind: 'unanchored regex on origin', location: locOf(script, node) });
        }
      }
    },
  });

  return { checksOrigin, checksSource, weakOriginChecks };
}

/**
 * The shared dataflow pass.
 *
 * ONE intraprocedural reaching-definitions walk over the acorn AST, reused by
 * four rules: PANE-MSG-004, PANE-INPUT-004, PANE-EXFIL-005 and PANE-CONTEXT-005.
 * It is deliberately not a taint engine, and the difference is load-bearing.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * What it does
 *
 *   SOURCES — the ingress points named in docs/SPEC-REFERENCE.md §4. The
 *   `ui/notifications/tool-result` handler is *the* channel by which hostile
 *   data reaches an app; `tool-input`, `tool-input-partial` and
 *   `host-context-changed` are the rest of the inbound notification set.
 *   `event.data` from a raw `message` listener and `clipboardData` /
 *   `dataTransfer` from paste/drop complete the list.
 *
 *   SINKS — `ui/message`, `ui/update-model-context`, `ui/download-file`,
 *   `ui/open-link`, the string-to-DOM sinks of PANE-DOM-001, `eval`/`new
 *   Function`, and anchor `href` construction for PANE-EXFIL-005.
 *
 *   PROPAGATION — assignment chains and parameter binding WITHIN one function.
 *
 * What it deliberately does not do
 *
 *   No interprocedural analysis. When a tainted value is handed to a call this
 *   pass cannot resolve, the value is UNKNOWN: an `Escape` is recorded and the
 *   consuming rule emits `undecided()`, never a finding. A rule that guesses
 *   here would flag conformant code, which docs/GOALS.md G2 treats as fatal.
 *
 * Every rule built on this pass ships at MEDIUM confidence. Per the gate formula
 * in docs/RULES.md that means none of them can EVER fail a build — which is the
 * only honest setting for a one-pass approximation of taint analysis, and must
 * not be "improved" by raising a confidence.
 * ─────────────────────────────────────────────────────────────────────────────
 */

import type { Node } from 'acorn';
import { findMessageListeners, isLiteralExpression } from '../../parse/js.js';
import type { MessageListener, ParsedScript } from '../../parse/js.js';
import type { RuleContext, SourceLocation } from '../../types.js';

// ---------------------------------------------------------------------------
// Untyped-AST plumbing
//
// acorn nodes are plain objects with a `type` discriminant. Rather than casting
// at every access site (the pattern in src/parse/js.ts, which has four of them),
// this module casts once at the boundary and reads through two accessors.
// ---------------------------------------------------------------------------

interface AstNode {
  type: string;
  [key: string]: unknown;
}

function ast(node: Node): AstNode {
  return node as unknown as AstNode;
}

function isNode(v: unknown): v is AstNode {
  return !!v && typeof v === 'object' && typeof (v as AstNode).type === 'string';
}

/** A child node under `key`, or null when absent or not a node. */
function kid(n: AstNode, key: string): AstNode | null {
  const v = n[key];
  return isNode(v) ? v : null;
}

/** Child nodes under `key`, skipping holes (`[a, , b]` is legal JS). */
function kids(n: AstNode, key: string): AstNode[] {
  const v = n[key];
  return Array.isArray(v) ? v.filter(isNode) : [];
}

/** Every child node, for generic traversal. */
function children(n: AstNode): AstNode[] {
  const out: AstNode[] = [];
  for (const value of Object.values(n)) {
    if (isNode(value)) out.push(value);
    else if (Array.isArray(value)) for (const v of value) if (isNode(v)) out.push(v);
  }
  return out;
}

function walk(root: AstNode, visit: (n: AstNode) => void): void {
  const stack: AstNode[] = [root];
  while (stack.length) {
    const n = stack.pop()!;
    visit(n);
    const cs = children(n);
    for (let i = cs.length - 1; i >= 0; i--) stack.push(cs[i]!);
  }
}

function walkWithStack(root: AstNode, visit: (n: AstNode, parents: AstNode[]) => void): void {
  const stack: Array<{ node: AstNode; parents: AstNode[] }> = [{ node: root, parents: [] }];
  while (stack.length) {
    const { node, parents } = stack.pop()!;
    visit(node, parents);
    const next = [node, ...parents];
    for (const c of children(node)) stack.push({ node: c, parents: next });
  }
}

const FUNCTION_TYPES = new Set(['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression']);

function isFunction(n: AstNode): boolean {
  return FUNCTION_TYPES.has(n.type);
}

function identName(n: AstNode | null): string | null {
  return n && n.type === 'Identifier' && typeof n.name === 'string' ? n.name : null;
}

function keyName(n: AstNode | null): string | null {
  if (!n) return null;
  if (n.type === 'Identifier' && typeof n.name === 'string') return n.name;
  if (n.type === 'Literal' && typeof n.value === 'string') return n.value;
  return null;
}

function stringValue(n: AstNode | null): string | null {
  if (!n) return null;
  if (n.type === 'Literal' && typeof n.value === 'string') return n.value;
  if (n.type === 'TemplateLiteral' && kids(n, 'expressions').length === 0) {
    const q = kids(n, 'quasis')[0];
    const cooked = q ? (q['value'] as { cooked?: string } | undefined)?.cooked : undefined;
    return typeof cooked === 'string' ? cooked : null;
  }
  return null;
}

/**
 * A dotted path for an identifier or member chain: `e.data.params`.
 *
 * Computed access with a literal key keeps the key (`a.b[0]`); computed access
 * with a dynamic key collapses to `*`, so `p.content[i]` and `p.content[j]`
 * share a path and taint survives an index this pass cannot evaluate.
 */
export function pathOf(node: Node | AstNode): string | null {
  const n = isNode(node) ? node : ast(node as Node);
  if (n.type === 'Identifier') return identName(n);
  if (n.type === 'ThisExpression') return 'this';
  if (n.type !== 'MemberExpression') return null;
  const base = pathOf(kid(n, 'object') ?? ({ type: 'X' } as AstNode));
  if (!base) return null;
  const prop = kid(n, 'property');
  if (n['computed'] === true) {
    const lit = prop && prop.type === 'Literal' ? String(prop['value']) : null;
    return `${base}.${lit ?? '*'}`;
  }
  const name = keyName(prop);
  return name ? `${base}.${name}` : null;
}

/** Rebase an acorn position onto document coordinates. Mirrors src/parse/js.ts. */
function locationIn(script: ParsedScript, node: AstNode): SourceLocation | undefined {
  const loc = node['loc'] as { start: { line: number; column: number } } | undefined;
  if (!loc) return undefined;
  const line = loc.start.line;
  const col = loc.start.column + 1;
  return {
    startLine: script.startLine + line - 1,
    startCol: line === 1 ? script.startCol + col - 1 : col,
  };
}

// ---------------------------------------------------------------------------
// Public shapes
// ---------------------------------------------------------------------------

export type SourceKind =
  | 'tool-result'
  | 'tool-input'
  | 'tool-input-partial'
  | 'host-context-changed'
  | 'message-event'
  | 'clipboard'
  | 'drop';

export type SinkKind =
  | 'dom-html'
  | 'eval'
  | 'ui/message'
  | 'ui/update-model-context'
  | 'ui/download-file'
  | 'ui/open-link'
  | 'link-href';

/** Sinks that write model context or leave the app. */
export const HOST_RPC_SINKS: readonly SinkKind[] = Object.freeze([
  'ui/message',
  'ui/update-model-context',
  'ui/download-file',
  'ui/open-link',
]);

export const DOM_SINKS: readonly SinkKind[] = Object.freeze(['dom-html', 'eval']);

/** The inbound notification set. `tool-result` is the one that matters most. */
export const NOTIFICATION_SOURCES: readonly SourceKind[] = Object.freeze([
  'tool-result',
  'tool-input',
  'tool-input-partial',
  'host-context-changed',
]);

export interface TaintSource {
  kind: SourceKind;
  /** Human-readable ingress, e.g. `app.ontoolresult`. */
  label: string;
  script: ParsedScript;
  node: Node;
  location?: SourceLocation;
}

export interface SinkSite {
  kind: SinkKind;
  /** The concrete construct, e.g. `innerHTML` or `app.sendMessage`. */
  detail: string;
  script: ParsedScript;
  node: Node;
  /** The expression whose value enters the sink. Null when there is no argument. */
  valueNode: Node | null;
  location?: SourceLocation;
}

export interface Flow {
  source: TaintSource;
  sink: SinkSite;
  /** Identifiers the value passed through, for the finding message. */
  via: string[];
  /**
   * True when the sink sits outside the handler body the source entered.
   * A module-scope variable written by the handler and read elsewhere is the
   * commonest real shape, and also the least precise thing this pass reports.
   */
  crossScope: boolean;
  location?: SourceLocation;
}

/** A tainted value this pass could not follow. The rule must decline to answer. */
export interface Escape {
  sourceKind: SourceKind;
  reason: string;
  script: ParsedScript;
  location?: SourceLocation;
}

export interface ListenerSite {
  script: ParsedScript;
  /** The `addEventListener` CallExpression. */
  node: Node;
  handlerKind: 'inline' | 'reference' | 'unknown';
  /** Null when the handler body is not statically visible. */
  resolved: MessageListener | null;
  location?: SourceLocation;
}

export interface Dataflow {
  sources: TaintSource[];
  sinks: SinkSite[];
  flows: Flow[];
  escapes: Escape[];
  /** Scripts with no AST. An unparsed script is an incomplete analysis. */
  unparsedScripts: ParsedScript[];
  flowsInto(sinkKinds: readonly SinkKind[], sourceKinds?: readonly SourceKind[]): Flow[];
  escapesFrom(sourceKinds: readonly SourceKind[]): Escape[];
}

/** Rules receive `ScriptSource[]`; `collectScripts` produced `ParsedScript[]`. */
export function scriptsOf(ctx: RuleContext): ParsedScript[] {
  return ctx.scripts as ParsedScript[];
}

// ---------------------------------------------------------------------------
// Literal resolution — the correction that keeps PANE-DOM-001 off pdf-server
// ---------------------------------------------------------------------------

/**
 * Module-level `const NAME = '<literal>'` bindings.
 *
 * `const ICON = '<svg…>'; el.innerHTML = ICON` is pdf-server's static-icon
 * pattern with one refactor applied, and an Identifier is non-literal unless
 * somebody resolves it. A name that is declared more than once, declared with
 * `let`/`var`, or assigned anywhere is excluded — resolution must never claim a
 * value the code can change.
 */
export function moduleStringConstants(scripts: readonly ParsedScript[]): Map<string, string> {
  const found = new Map<string, string>();
  const poisoned = new Set<string>();

  for (const script of scripts) {
    if (!script.ast) continue;
    walk(ast(script.ast), (n) => {
      if (n.type === 'VariableDeclaration') {
        const isConst = n['kind'] === 'const';
        for (const d of kids(n, 'declarations')) {
          const name = identName(kid(d, 'id'));
          if (!name) continue;
          const init = kid(d, 'init');
          const value = init ? literalString(init, found) : null;
          if (!isConst || value === null || found.has(name)) poisoned.add(name);
          else found.set(name, value);
        }
        return;
      }
      if (n.type === 'AssignmentExpression') {
        const name = identName(kid(n, 'left'));
        if (name) poisoned.add(name);
      }
      if (isFunction(n)) {
        for (const p of kids(n, 'params')) {
          const name = identName(p);
          if (name) poisoned.add(name);
        }
      }
    });
  }

  for (const name of poisoned) found.delete(name);
  return found;
}

function literalString(n: AstNode, consts: Map<string, string>): string | null {
  const direct = stringValue(n);
  if (direct !== null) return direct;
  if (n.type === 'Literal') return n['value'] === null ? 'null' : String(n['value']);
  if (n.type === 'Identifier') {
    const name = identName(n);
    return name && consts.has(name) ? consts.get(name)! : null;
  }
  if (n.type === 'BinaryExpression' && n['operator'] === '+') {
    const l = kid(n, 'left');
    const r = kid(n, 'right');
    if (!l || !r) return null;
    const ls = literalString(l, consts);
    const rs = literalString(r, consts);
    return ls === null || rs === null ? null : ls + rs;
  }
  return null;
}

/**
 * Is this expression a literal once resolved constants are folded in?
 *
 * `isLiteralExpression` in src/parse/js.ts answers the syntactic question; this
 * adds identifier resolution against `moduleStringConstants`. PANE-DOM-001 uses
 * this one, because the syntactic answer alone produced 11 findings on
 * pdf-server — every one a static icon SVG or an `innerHTML = ""` layer clear.
 */
export function isEffectivelyLiteral(node: Node, consts: Map<string, string>): boolean {
  if (isLiteralExpression(node)) return true;
  return literalString(ast(node), consts) !== null;
}

// ---------------------------------------------------------------------------
// Sinks
// ---------------------------------------------------------------------------

const HTML_PROPS = new Set(['innerHTML', 'outerHTML']);

/** `app.sendMessage(…)` etc. Method names verified against ext-apps 1.7.5. */
const RPC_METHODS: ReadonlyMap<string, SinkKind> = new Map<string, SinkKind>([
  ['sendMessage', 'ui/message'],
  ['updateModelContext', 'ui/update-model-context'],
  ['downloadFile', 'ui/download-file'],
  ['openLink', 'ui/open-link'],
  ['sendOpenLink', 'ui/open-link'],
]);

/** Raw JSON-RPC method literals, matched only as a `method:` property value. */
const RPC_LITERALS: ReadonlyMap<string, SinkKind> = new Map<string, SinkKind>([
  ['ui/message', 'ui/message'],
  ['ui/update-model-context', 'ui/update-model-context'],
  ['ui/download-file', 'ui/download-file'],
  ['ui/open-link', 'ui/open-link'],
]);

/** `location.href = …` belongs to PANE-EXFIL-004, not to the anchor rule. */
function isLocationPath(path: string | null): boolean {
  if (!path) return false;
  return path === 'location' || path.endsWith('.location');
}

/** Would `setTimeout`'s first argument be evaluated as a string of code? */
function isStringish(n: AstNode | null): boolean {
  if (!n) return false;
  if (n.type === 'Literal') return typeof n['value'] === 'string';
  if (n.type === 'TemplateLiteral') return true;
  if (n.type === 'BinaryExpression' && n['operator'] === '+') {
    return isStringish(kid(n, 'left')) || isStringish(kid(n, 'right'));
  }
  return false;
}

function collectSinks(script: ParsedScript): SinkSite[] {
  if (!script.ast) return [];
  const out: SinkSite[] = [];
  const add = (kind: SinkKind, detail: string, node: AstNode, valueNode: AstNode | null) => {
    out.push({
      kind,
      detail,
      script,
      node: node as unknown as Node,
      valueNode: (valueNode as unknown as Node) ?? null,
      location: locationIn(script, node),
    });
  };

  walkWithStack(ast(script.ast), (n, parents) => {
    if (n.type === 'AssignmentExpression') {
      const left = kid(n, 'left');
      const right = kid(n, 'right');
      if (!left || left.type !== 'MemberExpression' || left['computed'] === true) return;
      const prop = keyName(kid(left, 'property'));
      if (!prop) return;
      if (HTML_PROPS.has(prop)) add('dom-html', prop, n, right);
      else if ((prop === 'href' || prop === 'search') && !isLocationPath(pathOf(kid(left, 'object')!))) {
        add('link-href', prop, n, right);
      }
      return;
    }

    if (n.type === 'NewExpression') {
      if (identName(kid(n, 'callee')) === 'Function') {
        const args = kids(n, 'arguments');
        add('eval', 'new Function', n, args[args.length - 1] ?? null);
      }
      return;
    }

    if (n.type === 'Property' && n['computed'] !== true) {
      if (keyName(kid(n, 'key')) !== 'method') return;
      const value = kid(n, 'value');
      const literal = value && value.type === 'Literal' ? value['value'] : null;
      const kind = typeof literal === 'string' ? RPC_LITERALS.get(literal) : undefined;
      if (!kind) return;
      // The sibling `params` value is what actually travels; fall back to the
      // whole object so the sink is never valueless.
      const object = parents[0];
      let params: AstNode | null = null;
      if (object && object.type === 'ObjectExpression') {
        for (const p of kids(object, 'properties')) {
          if (p.type === 'Property' && keyName(kid(p, 'key')) === 'params') params = kid(p, 'value');
        }
      }
      add(kind, `method: "${literal}"`, n, params ?? object ?? null);
      return;
    }

    if (n.type !== 'CallExpression') return;
    const callee = kid(n, 'callee');
    if (!callee) return;
    const args = kids(n, 'arguments');

    const bare = identName(callee);
    if (bare === 'eval') {
      add('eval', 'eval', n, args[0] ?? null);
      return;
    }
    if ((bare === 'setTimeout' || bare === 'setInterval') && isStringish(args[0] ?? null)) {
      add('eval', `${bare} with a string argument`, n, args[0] ?? null);
      return;
    }
    if (callee.type !== 'MemberExpression' || callee['computed'] === true) return;
    const method = keyName(kid(callee, 'property'));
    if (!method) return;
    const objectPath = pathOf(kid(callee, 'object')!);

    if (method === 'insertAdjacentHTML') add('dom-html', method, n, args[1] ?? null);
    else if (method === 'setHTMLUnsafe') add('dom-html', method, n, args[0] ?? null);
    else if ((method === 'write' || method === 'writeln') && (objectPath === 'document' || objectPath?.endsWith('.document'))) {
      add('dom-html', `document.${method}`, n, args[0] ?? null);
    } else if (method === 'setAttribute') {
      const name = stringValue(args[0] ?? null)?.toLowerCase();
      if (name === 'href' && !isLocationPath(objectPath)) add('link-href', "setAttribute('href')", n, args[1] ?? null);
    } else {
      const kind = RPC_METHODS.get(method);
      if (kind) add(kind, `${objectPath ?? '?'}.${method}`, n, args[0] ?? null);
    }
  });

  return out;
}

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

/** SDK event names → the notification each one carries (ext-apps `AppEventMap`). */
const EVENT_SOURCES: ReadonlyMap<string, SourceKind> = new Map<string, SourceKind>([
  ['toolresult', 'tool-result'],
  ['toolinput', 'tool-input'],
  ['toolinputpartial', 'tool-input-partial'],
  ['hostcontextchanged', 'host-context-changed'],
]);

/** `app.ontoolresult = fn` — the singular handler form. */
const ON_HANDLER_SOURCES: ReadonlyMap<string, SourceKind> = new Map<string, SourceKind>([
  ['ontoolresult', 'tool-result'],
  ['ontoolinput', 'tool-input'],
  ['ontoolinputpartial', 'tool-input-partial'],
  ['onhostcontextchanged', 'host-context-changed'],
]);

/** JSON-RPC notification methods, for `setNotificationHandler` and raw dispatch. */
const NOTIFICATION_METHODS: ReadonlyMap<string, SourceKind> = new Map<string, SourceKind>([
  ['ui/notifications/tool-result', 'tool-result'],
  ['ui/notifications/tool-input', 'tool-input'],
  ['ui/notifications/tool-input-partial', 'tool-input-partial'],
  ['ui/notifications/host-context-changed', 'host-context-changed'],
]);

interface Root {
  source: TaintSource;
  /** The subtree taint is propagated through. */
  scope: AstNode;
  seeds: string[];
}

function firstParamName(fn: AstNode | null): string | null {
  if (!fn || !isFunction(fn)) return null;
  return identName(kids(fn, 'params')[0] ?? null);
}

/** The notification kind a `setNotificationHandler` argument identifies. */
function schemaKind(n: AstNode | null): SourceKind | null {
  if (!n) return null;
  const literal = stringValue(n);
  if (literal) return NOTIFICATION_METHODS.get(literal) ?? null;
  if (n.type === 'ObjectExpression') {
    for (const p of kids(n, 'properties')) {
      if (p.type !== 'Property' || keyName(kid(p, 'key')) !== 'method') continue;
      const v = stringValue(kid(p, 'value'));
      if (v) return NOTIFICATION_METHODS.get(v) ?? null;
    }
    return null;
  }
  const name = identName(n) ?? pathOf(n);
  if (!name) return null;
  if (/ToolResult/i.test(name)) return 'tool-result';
  if (/ToolInputPartial/i.test(name)) return 'tool-input-partial';
  if (/ToolInput/i.test(name)) return 'tool-input';
  if (/HostContextChanged/i.test(name)) return 'host-context-changed';
  return null;
}

function collectRoots(script: ParsedScript, listeners: readonly ListenerSite[]): Root[] {
  if (!script.ast) return [];
  const program = ast(script.ast);
  const out: Root[] = [];
  const push = (kind: SourceKind, label: string, node: AstNode, scope: AstNode, seeds: string[]) => {
    if (seeds.length === 0) return;
    out.push({
      source: { kind, label, script, node: node as unknown as Node, location: locationIn(script, node) },
      scope,
      seeds,
    });
  };

  walkWithStack(program, (n, parents) => {
    // `app.ontoolresult = (p) => { … }`
    if (n.type === 'AssignmentExpression') {
      const left = kid(n, 'left');
      if (left?.type === 'MemberExpression' && left['computed'] !== true) {
        const prop = keyName(kid(left, 'property'));
        const kind = prop ? ON_HANDLER_SOURCES.get(prop) : undefined;
        const fn = kid(n, 'right');
        if (kind && fn && isFunction(fn)) {
          const p = firstParamName(fn);
          push(kind, prop!, n, fn, p ? [p] : []);
        }
      }
    }

    // `e.clipboardData` / `e.dataTransfer` — read anywhere, including from an
    // inline `onpaste=` attribute where there is no listener call to find.
    if (n.type === 'MemberExpression' && n['computed'] !== true) {
      const prop = keyName(kid(n, 'property'));
      if (prop === 'clipboardData' || prop === 'dataTransfer') {
        const path = pathOf(n);
        if (path) {
          const scope = parents.find(isFunction) ?? program;
          push(prop === 'clipboardData' ? 'clipboard' : 'drop', prop, n, scope, [path]);
        }
      }
    }

    if (n.type !== 'CallExpression') return;
    const callee = kid(n, 'callee');
    if (!callee || callee.type !== 'MemberExpression' || callee['computed'] === true) return;
    const method = keyName(kid(callee, 'property'));
    const args = kids(n, 'arguments');

    // `app.addEventListener("toolresult", fn)`
    if (method === 'addEventListener') {
      const kind = EVENT_SOURCES.get(stringValue(args[0] ?? null) ?? '');
      const fn = args[1] ?? null;
      if (kind && fn && isFunction(fn)) {
        const p = firstParamName(fn);
        push(kind, `addEventListener("${stringValue(args[0]!)}")`, n, fn, p ? [p] : []);
      }
      return;
    }

    // `app.setNotificationHandler(Schema, fn)`
    if (method === 'setNotificationHandler') {
      const kind = schemaKind(args[0] ?? null);
      const fn = args[1] ?? null;
      if (kind && fn && isFunction(fn)) {
        const p = firstParamName(fn);
        push(kind, 'setNotificationHandler', n, fn, p ? [p] : []);
      }
    }
  });

  // A raw `message` listener. `event.data` is attacker-reachable per
  // SPEC-REFERENCE §4 — the transport validates `event.source` identity only,
  // and `window.frames[]` is cross-origin reachable from a sibling app.
  for (const site of listeners) {
    if (site.script !== script || !site.resolved) continue;
    const param = site.resolved.paramName;
    if (!param) continue;
    const call = ast(site.node);
    const fn = kids(call, 'arguments')[1];
    if (!fn || !isFunction(fn)) continue;
    push('message-event', 'message listener event.data', call, fn, [`${param}.data`]);

    // The same listener is ALSO the tool-result ingress when it dispatches on
    // the notification method itself — the shape an app that does not bundle
    // the SDK uses.
    const methods = new Set<SourceKind>();
    walk(fn, (x) => {
      const literal = stringValue(x);
      const kind = literal ? NOTIFICATION_METHODS.get(literal) : undefined;
      if (kind) methods.add(kind);
    });
    for (const kind of methods) {
      push(kind, `message listener dispatching ${kind}`, call, fn, [`${param}.data`]);
    }
  }

  return out;
}

// ---------------------------------------------------------------------------
// Propagation
// ---------------------------------------------------------------------------

/** Calls that carry a value through unchanged rather than consuming it. */
const PRESERVING_GLOBALS = new Set([
  'String', 'Number', 'Boolean', 'JSON.parse', 'JSON.stringify', 'Array.from',
  'Object.keys', 'Object.values', 'Object.entries', 'encodeURIComponent',
  'decodeURIComponent', 'encodeURI', 'decodeURI', 'atob', 'btoa', 'structuredClone',
]);

/**
 * Calls that neutralise a value.
 *
 * Deliberately name-shaped rather than an allowlist of libraries: an app that
 * routes tool output through anything called `sanitize`, `escapeHtml` or
 * `purify` has made the decision this rule exists to ask about, and reporting it
 * anyway is how a scanner teaches people to ignore it.
 */
const SANITIZER = /sanitiz|escapehtml|escape_html|purif|striptags|strip_tags/i;

/** Array methods whose callback receives the receiver's elements. */
const ITERATORS = new Set(['map', 'forEach', 'filter', 'flatMap', 'find', 'some', 'every']);

interface Propagation {
  paths: Set<string>;
  escapes: Escape[];
}

function propagate(script: ParsedScript, root: Root, sinkNodes: ReadonlySet<AstNode>): Propagation {
  const paths = new Set<string>(root.seeds);
  const escapes: Escape[] = [];
  const escapeSeen = new Set<string>();

  const taintedPath = (p: string | null): boolean => {
    if (!p) return false;
    for (const t of paths) {
      if (p === t || p.startsWith(`${t}.`)) return true;
    }
    return false;
  };

  const tainted = (n: AstNode | null): boolean => {
    if (!n) return false;
    switch (n.type) {
      case 'Identifier':
      case 'MemberExpression':
      case 'ThisExpression':
        return taintedPath(pathOf(n));
      case 'TemplateLiteral':
        return kids(n, 'expressions').some(tainted);
      case 'BinaryExpression':
        return tainted(kid(n, 'left')) || tainted(kid(n, 'right'));
      case 'LogicalExpression':
        return tainted(kid(n, 'left')) || tainted(kid(n, 'right'));
      case 'ConditionalExpression':
        return tainted(kid(n, 'consequent')) || tainted(kid(n, 'alternate'));
      case 'AwaitExpression':
      case 'UnaryExpression':
      case 'SpreadElement':
      case 'ChainExpression':
        return tainted(kid(n, 'argument') ?? kid(n, 'expression'));
      case 'ArrayExpression':
        return kids(n, 'elements').some(tainted);
      case 'ObjectExpression':
        return kids(n, 'properties').some((p) => tainted(kid(p, 'value') ?? kid(p, 'argument')));
      case 'AssignmentExpression':
        return tainted(kid(n, 'right'));
      case 'CallExpression': {
        const callee = kid(n, 'callee');
        if (!callee) return false;
        const calleePath = pathOf(callee) ?? '';
        if (SANITIZER.test(calleePath)) return false;
        // A method called ON tainted data returns data derived from it:
        // `e.clipboardData.getData(…)`, `p.content.map(…)`, `raw.trim()`.
        if (callee.type === 'MemberExpression' && tainted(kid(callee, 'object'))) return true;
        if (PRESERVING_GLOBALS.has(calleePath)) return kids(n, 'arguments').some(tainted);
        return false;
      }
      default:
        return false;
    }
  };

  /** Bind every name a destructuring pattern introduces. */
  const bindPattern = (pattern: AstNode | null, prefix: string | null): boolean => {
    if (!pattern) return false;
    let added = false;
    const addPath = (p: string) => {
      if (!paths.has(p)) {
        paths.add(p);
        added = true;
      }
    };
    if (pattern.type === 'Identifier') {
      const name = identName(pattern);
      if (name) addPath(name);
      return added;
    }
    if (pattern.type === 'ObjectPattern') {
      for (const p of kids(pattern, 'properties')) {
        added = bindPattern(kid(p, 'value') ?? kid(p, 'argument'), prefix) || added;
      }
      return added;
    }
    if (pattern.type === 'ArrayPattern') {
      for (const e of kids(pattern, 'elements')) added = bindPattern(e, prefix) || added;
      return added;
    }
    if (pattern.type === 'AssignmentPattern') return bindPattern(kid(pattern, 'left'), prefix);
    if (pattern.type === 'RestElement') return bindPattern(kid(pattern, 'argument'), prefix);
    return added;
  };

  // Reaching definitions by fixpoint. Three passes settle every shape this pass
  // models; a declaration used before its assignment is the only case needing
  // more than one.
  for (let pass = 0; pass < 3; pass++) {
    let changed = false;
    walk(root.scope, (n) => {
      if (n.type === 'VariableDeclarator') {
        if (tainted(kid(n, 'init'))) changed = bindPattern(kid(n, 'id'), null) || changed;
        return;
      }
      if (n.type === 'AssignmentExpression') {
        const left = kid(n, 'left');
        if (!left || left.type === 'MemberExpression') return;
        if (tainted(kid(n, 'right'))) changed = bindPattern(left, null) || changed;
        return;
      }
      if (n.type === 'CallExpression') {
        const callee = kid(n, 'callee');
        const args = kids(n, 'arguments');
        // An immediately-invoked inline function: parameter passing within the
        // same function, which this pass DOES model.
        if (callee && isFunction(callee)) {
          const params = kids(callee, 'params');
          args.forEach((a, i) => {
            if (tainted(a)) changed = bindPattern(params[i] ?? null, null) || changed;
          });
          return;
        }
        // `tainted.map(cb)` — the callback's first parameter is an element of a
        // tainted collection.
        if (callee?.type === 'MemberExpression') {
          const method = keyName(kid(callee, 'property'));
          if (method && ITERATORS.has(method) && tainted(kid(callee, 'object'))) {
            const cb = args[0];
            if (cb && isFunction(cb)) {
              changed = bindPattern(kids(cb, 'params')[0] ?? null, null) || changed;
            }
          }
        }
      }
    });
    if (!changed) break;
  }

  // Escapes. A tainted value handed to a call this pass cannot resolve is
  // UNKNOWN, and the consuming rule must say so rather than guess.
  walk(root.scope, (n) => {
    if (n.type !== 'CallExpression' || sinkNodes.has(n)) return;
    const callee = kid(n, 'callee');
    if (!callee) return;
    const calleePath = pathOf(callee) ?? '';
    if (SANITIZER.test(calleePath)) return;
    if (PRESERVING_GLOBALS.has(calleePath)) return;
    if (callee.type === 'MemberExpression' && tainted(kid(callee, 'object'))) return;
    if (isFunction(callee)) return;
    if (!kids(n, 'arguments').some(tainted)) return;
    const reason = `tainted value passed to ${calleePath || 'an unresolved call'}(…)`;
    if (escapeSeen.has(reason)) return;
    escapeSeen.add(reason);
    escapes.push({ sourceKind: root.source.kind, reason, script, location: locationIn(script, n) });
  });

  return { paths, escapes };
}

// ---------------------------------------------------------------------------
// Message listeners — including the ones nobody can resolve
// ---------------------------------------------------------------------------

/**
 * Every `addEventListener('message', …)` call site, resolvable or not.
 *
 * `findMessageListeners` in src/parse/js.ts characterises INLINE handlers and
 * silently skips the rest. For PANE-MSG-001, whose finding is the ABSENCE of a
 * check, a silent skip is the worst possible outcome: the shipped ext-apps SDK
 * registers `addEventListener("message", this.messageListener)` — a method
 * reference — so a rule that sees no handler body and concludes "no origin
 * check" fires a gate-eligible HIGH on the SDK's own transport inside every app
 * that bundles it. This function reports the unresolvable sites so the rule can
 * emit `undecided()` for them.
 */
export function messageListenerSites(scripts: readonly ParsedScript[]): ListenerSite[] {
  const resolved = new Map<Node, MessageListener>();
  for (const l of findMessageListeners(scripts as ParsedScript[])) resolved.set(l.node, l);

  const out: ListenerSite[] = [];
  for (const script of scripts) {
    if (!script.ast) continue;
    walk(ast(script.ast), (n) => {
      if (n.type !== 'CallExpression') return;
      const callee = kid(n, 'callee');
      if (!callee || callee.type !== 'MemberExpression' || callee['computed'] === true) return;
      if (keyName(kid(callee, 'property')) !== 'addEventListener') return;
      const args = kids(n, 'arguments');
      if (stringValue(args[0] ?? null) !== 'message') return;

      const handler = args[1] ?? null;
      const node = n as unknown as Node;
      const match = resolved.get(node) ?? null;
      const handlerKind: ListenerSite['handlerKind'] = handler && isFunction(handler)
        ? 'inline'
        : handler && (handler.type === 'Identifier' || handler.type === 'MemberExpression')
          ? 'reference'
          : 'unknown';

      out.push({
        script,
        node,
        handlerKind,
        resolved: handlerKind === 'inline' ? match : null,
        location: locationIn(script, n),
      });
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// The pass
// ---------------------------------------------------------------------------

export function analyseDataflow(scripts: readonly ParsedScript[]): Dataflow {
  const parsed = scripts.filter((s) => s.ast);
  const unparsedScripts = scripts.filter((s) => !s.ast);
  const listeners = messageListenerSites(scripts);

  const sources: TaintSource[] = [];
  const sinks: SinkSite[] = [];
  const flows: Flow[] = [];
  const escapes: Escape[] = [];

  for (const script of parsed) {
    const scriptSinks = collectSinks(script);
    sinks.push(...scriptSinks);

    const sinkNodes = new Set<AstNode>(scriptSinks.map((s) => ast(s.node)));
    const roots = collectRoots(script, listeners);

    for (const root of roots) {
      sources.push(root.source);
      const { paths, escapes: rootEscapes } = propagate(script, root, sinkNodes);
      escapes.push(...rootEscapes);

      const inScope = new Set<AstNode>();
      walk(root.scope, (n) => inScope.add(n));

      for (const sink of scriptSinks) {
        if (!sink.valueNode) continue;
        const value = ast(sink.valueNode);
        const via = identifiersIn(value).filter((name) => paths.has(name));
        if (!isTaintedExpression(value, paths)) continue;
        flows.push({
          source: root.source,
          sink,
          via,
          crossScope: !inScope.has(ast(sink.node)),
          location: sink.location,
        });
      }
    }
  }

  return {
    sources,
    sinks,
    flows,
    escapes,
    unparsedScripts,
    flowsInto(sinkKinds, sourceKinds) {
      return flows.filter(
        (f) =>
          sinkKinds.includes(f.sink.kind) && (!sourceKinds || sourceKinds.includes(f.source.kind)),
      );
    },
    escapesFrom(sourceKinds) {
      return escapes.filter((e) => sourceKinds.includes(e.sourceKind));
    },
  };
}

/**
 * The taint predicate, re-run at flow time against the settled path set.
 *
 * Kept separate from the one inside `propagate` because that one also records
 * escapes; this one is a pure read.
 */
function isTaintedExpression(n: AstNode | null, paths: ReadonlySet<string>): boolean {
  if (!n) return false;
  const taintedPath = (p: string | null): boolean => {
    if (!p) return false;
    for (const t of paths) if (p === t || p.startsWith(`${t}.`)) return true;
    return false;
  };
  const rec = (x: AstNode | null): boolean => {
    if (!x) return false;
    switch (x.type) {
      case 'Identifier':
      case 'MemberExpression':
      case 'ThisExpression':
        return taintedPath(pathOf(x));
      case 'TemplateLiteral':
        return kids(x, 'expressions').some(rec);
      case 'BinaryExpression':
      case 'LogicalExpression':
        return rec(kid(x, 'left')) || rec(kid(x, 'right'));
      case 'ConditionalExpression':
        return rec(kid(x, 'consequent')) || rec(kid(x, 'alternate'));
      case 'AwaitExpression':
      case 'UnaryExpression':
      case 'SpreadElement':
      case 'ChainExpression':
        return rec(kid(x, 'argument') ?? kid(x, 'expression'));
      case 'ArrayExpression':
        return kids(x, 'elements').some(rec);
      case 'ObjectExpression':
        return kids(x, 'properties').some((p) => rec(kid(p, 'value') ?? kid(p, 'argument')));
      case 'CallExpression': {
        const callee = kid(x, 'callee');
        if (!callee) return false;
        const calleePath = pathOf(callee) ?? '';
        if (SANITIZER.test(calleePath)) return false;
        if (callee.type === 'MemberExpression' && rec(kid(callee, 'object'))) return true;
        if (PRESERVING_GLOBALS.has(calleePath)) return kids(x, 'arguments').some(rec);
        return false;
      }
      default:
        return false;
    }
  };
  return rec(n);
}

function identifiersIn(n: AstNode): string[] {
  const out: string[] = [];
  walk(n, (x) => {
    const name = identName(x);
    if (name) out.push(name);
  });
  return out;
}

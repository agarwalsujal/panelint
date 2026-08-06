/**
 * Shared plumbing for the PANE-CONTEXT family — the model-context write surface.
 *
 * The false positive every rule here must dodge: MCP Apps resources are raw
 * HTML with no build step, so apps INLINE the ext-apps SDK bundle. That bundle
 * defines methods named exactly `sendMessage`, `openLink`, `downloadFile`,
 * `updateModelContext` and `requestDisplayMode` on its own transport class, and
 * makes internal `this.request({method:"ui/message", ...})`-shaped calls for
 * every one of them — regardless of whether the embedding app ever calls any
 * of them itself. Verified against the real
 * `@modelcontextprotocol/ext-apps@1.7.5` bundle in
 * fixtures/nondetect/sdk-bundle-inlined.html.
 *
 * Two independent defenses, used per rule as needed:
 *
 *  1. Call-site matching (`findAppMethodCalls`) is scoped to a receiver whose
 *     OWN name looks like the app bridge (`app`, `window.app`, `mcpApp`, ...).
 *     The bundle's internal calls are always `this.request(...)` — `this`
 *     never matches — so call-site matching is immune on its own, with no
 *     extra bundle detection required.
 *
 *  2. The raw JSON-RPC `{ method: "..." }` object-literal form is ambiguous
 *     on its own — the bundle contains a real `{method:"ui/message", ...}`
 *     call site internally, whether or not the embedding app ever calls it.
 *     Rules that need this form either require additional structure the
 *     bundle's internal calls do not have (PANE-CONTEXT-003/-008 also require
 *     a `params.url` object, and the bundle's internal calls pass `params` as
 *     a bare identifier, not an object literal), or explicitly detect the
 *     vendored bundle and stand down with `undecided()` (PANE-CONTEXT-001).
 */

import type { Node } from 'acorn';
import { simple as walkSimple } from 'acorn-walk';
import type { ParsedScript } from '../../parse/js.js';
import type { RuleContext } from '../../types.js';

export interface AstNode {
  type: string;
  [key: string]: unknown;
}

function asNode(n: Node): AstNode {
  return n as unknown as AstNode;
}

/** Case-insensitive "looks like the app bridge" test on a receiver's own name. */
const APP_SHAPED = /app/i;

function identifierName(n: AstNode | null): string | null {
  return n && n.type === 'Identifier' && typeof n['name'] === 'string' ? (n['name'] as string) : null;
}

function propertyKeyName(n: AstNode | null): string | null {
  if (!n) return null;
  if (n.type === 'Identifier' && typeof n['name'] === 'string') return n['name'] as string;
  if (n.type === 'Literal' && typeof n['value'] === 'string') return n['value'] as string;
  return null;
}

/**
 * The rightmost name in a receiver chain: `app` in `app`, `window.app`, and
 * `mcpApp`. Used only for the `/app/i` shape test — a heuristic, never treated
 * as proof of identity.
 */
function receiverName(objectNode: AstNode | null): string | null {
  if (!objectNode) return null;
  if (objectNode.type === 'Identifier') return identifierName(objectNode);
  if (objectNode.type === 'MemberExpression' && !objectNode['computed']) {
    return propertyKeyName(asNode(objectNode['property'] as Node));
  }
  return null;
}

export interface AppMethodCall {
  script: ParsedScript;
  node: Node;
  args: AstNode[];
}

/**
 * `<receiver>.<method>(...)` where the receiver's own name is app-shaped.
 *
 * Deliberately not parse/js.ts's exact-name `object` matcher: that would miss
 * `mcpApp.sendMessage(...)`, a naming convention seen in more than one
 * reference server, while still rejecting `socket.sendMessage(...)`.
 */
export function findAppMethodCalls(scripts: ParsedScript[], methodNames: string[]): AppMethodCall[] {
  const wanted = new Set(methodNames);
  const out: AppMethodCall[] = [];

  for (const script of scripts) {
    if (!script.ast) continue;
    walkSimple(script.ast, {
      CallExpression(node: Node) {
        const n = asNode(node);
        const callee = asNode(n['callee'] as Node);
        if (callee.type !== 'MemberExpression' || callee['computed']) return;
        const method = propertyKeyName(asNode(callee['property'] as Node));
        if (!method || !wanted.has(method)) return;
        const name = receiverName(asNode(callee['object'] as Node));
        if (!name || !APP_SHAPED.test(name)) return;
        out.push({ script, node, args: ((n['arguments'] as Node[] | undefined) ?? []).map(asNode) });
      },
    });
  }

  return out;
}

/** A property's value node, by non-computed key, on an object literal. */
export function objectProp(node: AstNode | null, key: string): AstNode | null {
  if (!node || node.type !== 'ObjectExpression') return null;
  const props = (node['properties'] as AstNode[] | undefined) ?? [];
  for (const p of props) {
    if (p.type !== 'Property' || p['computed']) continue;
    if (propertyKeyName(asNode(p['key'] as Node)) === key) return asNode(p['value'] as Node);
  }
  return null;
}

/** The string a `Literal` or interpolation-free `TemplateLiteral` holds, or null. */
export function literalStringValue(node: AstNode | null): string | null {
  if (!node) return null;
  if (node.type === 'Literal' && typeof node['value'] === 'string') return node['value'] as string;
  if (node.type === 'TemplateLiteral' && ((node['expressions'] as unknown[] | undefined) ?? []).length === 0) {
    const quasis = (node['quasis'] as AstNode[] | undefined) ?? [];
    const cooked = (quasis[0]?.['value'] as { cooked?: string } | undefined)?.cooked;
    return typeof cooked === 'string' ? cooked : null;
  }
  return null;
}

export interface OpenLinkSite {
  script: ParsedScript;
  node: Node;
  urlNode: AstNode;
}

/**
 * Every place this document asks the host to open a URL: the call-site form
 * (`app.openLink(...)`, `app.sendOpenLink(...)`) and the raw JSON-RPC form
 * (`{ method: "ui/open-link", params: { url: ... } }`), matched structurally
 * — see the module doc for why a bare `method:` string match is not enough.
 */
export function findOpenLinkSites(scripts: ParsedScript[]): OpenLinkSite[] {
  const out: OpenLinkSite[] = [];

  for (const call of findAppMethodCalls(scripts, ['openLink', 'sendOpenLink'])) {
    const urlNode = objectProp(call.args[0] ?? null, 'url');
    if (urlNode) out.push({ script: call.script, node: call.node, urlNode });
  }

  for (const script of scripts) {
    if (!script.ast) continue;
    walkSimple(script.ast, {
      ObjectExpression(node: Node) {
        const n = asNode(node);
        const methodVal = objectProp(n, 'method');
        if (!methodVal || methodVal.type !== 'Literal' || methodVal['value'] !== 'ui/open-link') return;
        const params = objectProp(n, 'params');
        const url = objectProp(params, 'url');
        if (!url) return;
        out.push({ script, node, urlNode: url });
      },
    });
  }

  return out;
}

/**
 * Detect an inlined, vendored `@modelcontextprotocol/ext-apps` bundle.
 *
 * Two independent markers, both required: an import specifier that only the
 * SDK's own module graph produces, and either the 76-entry style-variable
 * schema blob or the postMessage transport's JSON-RPC guard. Neither marker
 * alone is safe — `jsonrpc` and `window.parent` both appear in ordinary
 * hand-rolled bridges — but the combination is specific to the real bundle.
 */
export function isVendoredSdkBundle(ctx: RuleContext): boolean {
  for (const s of ctx.scripts) {
    const code = s.code ?? '';
    const hasSdkImport =
      code.includes('@modelcontextprotocol/sdk/shared/protocol.js') ||
      code.includes('@modelcontextprotocol/sdk/types.js');
    if (!hasSdkImport) continue;
    const hasSchemaBlob = code.includes('--color-background-primary') && code.includes('--color-text-primary');
    const hasTransportGuard = code.includes('jsonrpc') && code.includes('window.parent');
    if (hasSchemaBlob || hasTransportGuard) return true;
  }
  return false;
}

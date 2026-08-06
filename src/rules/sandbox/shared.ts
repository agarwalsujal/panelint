/**
 * Shared plumbing for the PANE-SANDBOX family — frame isolation.
 *
 * Two facts govern every rule here (docs/RULES.md § PANE-SANDBOX,
 * SPEC-REFERENCE.md §3.3):
 *
 *   1. A nested browsing context can never exceed its ancestor's sandbox
 *      flags and can never acquire a Permissions Policy feature its parent
 *      lacks. The spec does not enumerate the View iframe's own sandbox
 *      value, so every finding in this family is conditional on it — and
 *      that conditionality must be in the finding TEXT, not only in the
 *      `assumption` field. `withFrameClause` appends it uniformly.
 *
 *   2. `allow-scripts allow-same-origin` is MANDATED for the sandbox proxy.
 *      A scanner must flag it only when the framed document is same-origin
 *      with the HOST, and the host's own origin is knowable only through a
 *      declared `_meta.ui.domain` — which none of the eight reference
 *      servers sets. With no declared origin, PANE-SANDBOX-001 must not
 *      guess.
 */

import type { Node } from 'acorn';
import { simple as walkSimple } from 'acorn-walk';
import type { ParsedScript } from '../../parse/js.js';

export interface AstNode {
  type: string;
  [key: string]: unknown;
}

function asNode(n: Node): AstNode {
  return n as unknown as AstNode;
}

/**
 * Every finding in this family carries this clause in its message text, on
 * top of the `HOST_SANDBOX_ASSUMPTION` field — see the module doc.
 */
export function withFrameClause(text: string): string {
  return (
    `${text} This is conditional on the host's own View-iframe sandbox declaration: a nested ` +
    "frame can never exceed its ancestor's sandbox flags, and the specification does not " +
    'enumerate that value.'
  );
}

/** Permissions-Policy feature name a declared `_meta.ui.permissions` key maps to. */
export const PERMISSION_FEATURES: Record<string, string> = {
  camera: 'camera',
  microphone: 'microphone',
  geolocation: 'geolocation',
  clipboardWrite: 'clipboard-write',
};

/** Does the `allow=` attribute grant a wildcard (`*`) allowlist to any feature? */
export function hasWildcardAllow(allowValue: string): boolean {
  return allowValue
    .split(';')
    .some((directive) => directive.trim().split(/\s+/).slice(1).includes('*'));
}

/** The feature name named first in each `allow=` directive, lower-cased. */
export function allowFeatureNames(allowValue: string): string[] {
  return allowValue
    .split(';')
    .map((d) => d.trim().split(/\s+/)[0]?.toLowerCase())
    .filter((x): x is string => Boolean(x));
}

/** A property's value node, by non-computed key, on an object literal. */
function objectProp(node: AstNode | null, key: string): AstNode | null {
  if (!node || node.type !== 'ObjectExpression') return null;
  const props = (node['properties'] as AstNode[] | undefined) ?? [];
  for (const p of props) {
    if (p.type !== 'Property' || p['computed']) continue;
    const k = p['key'] as AstNode;
    const name =
      k.type === 'Identifier'
        ? (k['name'] as string)
        : k.type === 'Literal' && typeof k['value'] === 'string'
          ? (k['value'] as string)
          : null;
    if (name === key) return p['value'] as AstNode;
  }
  return null;
}

/** Is this property value present and not the literal `false`? "Requested." */
export function isRequested(node: AstNode | null): boolean {
  return node != null && !(node.type === 'Literal' && node['value'] === false);
}

export interface GetUserMediaCall {
  node: Node;
  wantsAudio: boolean;
  wantsVideo: boolean;
}

/** `navigator.mediaDevices.getUserMedia({ audio, video })` constraints, read rather than assumed. */
export function getUserMediaConstraints(argNode: Node | undefined): { audio: boolean; video: boolean } {
  if (!argNode) return { audio: false, video: false };
  const n = asNode(argNode);
  return {
    audio: isRequested(objectProp(n, 'audio')),
    video: isRequested(objectProp(n, 'video')),
  };
}

/**
 * `navigator.<feature>` accessed anywhere — member access is enough, no
 * invocation required. Used by PANE-SANDBOX-005, where feature detection
 * counts as "use" of a declared permission. Deliberately more permissive than
 * PANE-SANDBOX-006's invocation-only test — the asymmetry is the point.
 */
export function navigatorAccessedFeatures(scripts: ParsedScript[]): Set<string> {
  const found = new Set<string>();

  for (const script of scripts) {
    if (!script.ast) continue;
    walkSimple(script.ast, {
      MemberExpression(node: Node) {
        const n = asNode(node);
        if (n['computed']) return;
        const object = n['object'] as AstNode | undefined;
        if (!object || object.type !== 'Identifier' || object['name'] !== 'navigator') return;
        const property = n['property'] as AstNode | undefined;
        const prop = property?.type === 'Identifier' ? (property['name'] as string) : null;
        if (prop === 'geolocation') found.add('geolocation');
        else if (prop === 'mediaDevices') {
          found.add('camera');
          found.add('microphone');
        } else if (prop === 'clipboard') found.add('clipboardWrite');
      },
    });
  }

  return found;
}

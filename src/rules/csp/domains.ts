/**
 * CSP source-expression handling for the PANE-CSP family.
 *
 * `_meta.ui.csp` is four arrays of strings. Every rule in this family has to
 * answer some version of "what does this string permit?", and getting that
 * answer subtly wrong is how the family fires on conformant servers.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * ⚠ A wildcard is not a wildcard.
 *
 *   `*`                      permits every origin.               PANE-CSP-001/002
 *   `https:`                 permits every https origin.         PANE-CSP-001/002
 *   `https://*.github.io`    permits every stranger's page.      PANE-CSP-005
 *   `https://*.mapbox.com`   permits one company's subdomains.   NOTHING
 *
 * The last line is the one that matters. In the 21-server hand-scan on
 * 2026-08-05 **every** wildcard hit was a first-party subdomain wildcard, and
 * the server a naive check would have flagged hardest was `mapbox/mcp-server`:
 *
 *   connectDomains:  ['https://*.mapbox.com', 'https://events.mapbox.com']
 *   resourceDomains: ['https://api.mapbox.com']
 *
 * That is the best-configured server in the corpus. Flagging it would be the
 * GOALS.md G2 failure in its purest form — the tool punishing the one team that
 * did the work properly.
 * ─────────────────────────────────────────────────────────────────────────────
 */

import { parse as parseHost } from 'tldts';
import type { UIResourceCsp, UIResourceMeta } from '../../types.js';

export const CSP_ARRAYS = ['connectDomains', 'resourceDomains', 'frameDomains', 'baseUriDomains'] as const;

export type CspArrayName = (typeof CSP_ARRAYS)[number];

/** One declared string, with the coordinates a finding needs to point back at it. */
export interface DomainEntry {
  array: CspArrayName;
  index: number;
  value: string;
}

// ---------------------------------------------------------------------------
// Reading `_meta.ui.csp` defensively
// ---------------------------------------------------------------------------

/**
 * The `csp` object, or null.
 *
 * `_meta` is attacker-authored. `csp: null`, `csp: "https://a"` and
 * `csp: { connectDomains: 42 }` all reach here, and none of them may throw.
 */
export function cspOf(meta: UIResourceMeta | null): UIResourceCsp | null {
  if (!meta || typeof meta !== 'object') return null;
  const csp = (meta as { csp?: unknown }).csp;
  if (!csp || typeof csp !== 'object' || Array.isArray(csp)) return null;
  return csp as UIResourceCsp;
}

/** The string entries of one array. Non-strings are dropped, not coerced. */
export function entriesOf(csp: UIResourceCsp | null, array: CspArrayName): DomainEntry[] {
  if (!csp) return [];
  const raw = (csp as Record<string, unknown>)[array];
  if (!Array.isArray(raw)) return [];
  const out: DomainEntry[] = [];
  raw.forEach((value, index) => {
    if (typeof value === 'string') out.push({ array, index, value });
  });
  return out;
}

/** Every string entry across all four arrays, in declaration order. */
export function allEntries(csp: UIResourceCsp | null): DomainEntry[] {
  return CSP_ARRAYS.flatMap((array) => entriesOf(csp, array));
}

/**
 * Is a field absent, or present and empty?
 *
 * `Object.keys(csp).length === 0` is the tempting implementation and it is
 * wrong: both real-world confirmations of PANE-CSP-013 carried two keys
 * (`{connectDomains: [], resourceDomains: []}`).
 */
export function fieldIsEmpty(csp: UIResourceCsp, array: CspArrayName): boolean {
  const raw = (csp as Record<string, unknown>)[array];
  if (raw === undefined || raw === null) return true;
  return Array.isArray(raw) && raw.length === 0;
}

/** A JSON pointer into `_meta`, so a report can point at the exact array slot. */
export function pointerFor(array: CspArrayName, index?: number): string {
  return index === undefined ? `/ui/csp/${array}` : `/ui/csp/${array}/${index}`;
}

// ---------------------------------------------------------------------------
// Parsing a source expression
// ---------------------------------------------------------------------------

export type SourceKind =
  /** `'self'`, `'none'` — a keyword, not a host. */
  | 'keyword'
  /** `*`, `https://*`, `//*` — permits every origin. */
  | 'bare-wildcard'
  /** `https:`, `data:` — permits every origin on that scheme. */
  | 'scheme-only'
  /** Anything with a host, wildcard subdomain included. */
  | 'host'
  /** Unparseable. Rules decline rather than guess. */
  | 'other';

export interface ParsedSource {
  raw: string;
  kind: SourceKind;
  scheme?: string;
  /** Lowercased, may carry a leading `*.`. */
  host?: string;
  port?: string;
  path?: string;
}

/**
 * Parse a CSP source expression.
 *
 * Deliberately hand-written rather than delegated to `new URL()`: a CSP source
 * is not a URL. `https://*.example.com`, `https:` and `*` are all legal here and
 * all throw or mis-parse through the URL constructor.
 */
export function parseSource(raw: string): ParsedSource {
  const trimmed = String(raw ?? '').trim();
  if (!trimmed) return { raw: trimmed, kind: 'other' };
  if (trimmed.startsWith("'")) return { raw: trimmed, kind: 'keyword' };

  // `https:` / `data:` / `https://` with nothing after it.
  const schemeOnly = /^([a-z][a-z0-9+.-]*):(\/\/)?$/i.exec(trimmed);
  if (schemeOnly) {
    return { raw: trimmed, kind: 'scheme-only', scheme: schemeOnly[1]!.toLowerCase() };
  }

  let rest = trimmed;
  let scheme: string | undefined;
  const withScheme = /^([a-z*][a-z0-9+.*-]*):\/\//i.exec(rest);
  if (withScheme) {
    scheme = withScheme[1]!.toLowerCase();
    rest = rest.slice(withScheme[0]!.length);
  } else if (rest.startsWith('//')) {
    rest = rest.slice(2);
  }

  let path: string | undefined;
  const slash = rest.indexOf('/');
  if (slash >= 0) {
    path = rest.slice(slash);
    rest = rest.slice(0, slash);
  }

  let port: string | undefined;
  const withPort = /:([0-9*]+)$/.exec(rest);
  if (withPort) {
    port = withPort[1];
    rest = rest.slice(0, withPort.index);
  }
  if (rest.endsWith(':')) rest = rest.slice(0, -1);

  const host = rest.toLowerCase();
  if (host === '*') {
    return {
      raw: trimmed,
      kind: 'bare-wildcard',
      ...(scheme ? { scheme } : {}),
      ...(path ? { path } : {}),
    };
  }
  if (!host) return { raw: trimmed, kind: 'other' };

  return {
    raw: trimmed,
    kind: 'host',
    ...(scheme ? { scheme } : {}),
    host,
    ...(port ? { port } : {}),
    ...(path ? { path } : {}),
  };
}

/**
 * Does this entry permit every origin, or every origin on a scheme?
 *
 * This — and ONLY this — is what PANE-CSP-001 and PANE-CSP-002 fire on. A
 * subdomain wildcard is a different question, answered by
 * `isSharedHostingWildcard`.
 */
export function isUnboundedSource(p: ParsedSource): 'bare-wildcard' | 'scheme-only' | null {
  if (p.kind === 'bare-wildcard') return 'bare-wildcard';
  if (p.kind === 'scheme-only') return 'scheme-only';
  return null;
}

// ---------------------------------------------------------------------------
// Shared hosting — PANE-CSP-005
// ---------------------------------------------------------------------------

/**
 * Suffixes any stranger can publish content to, which the PSL delta misses.
 *
 * The delta test below catches every suffix the Public Suffix List records in
 * its PRIVATE section. `glitch.me` and `surge.sh` are not in it — their private
 * and ICANN suffixes are identical — yet both hand out subdomains to anyone.
 *
 * This list is a supplement to the delta, never a replacement for it: a
 * hand-maintained list of shared-hosting origins is exactly what DESIGN.md §3.3
 * adopted `tldts` to avoid.
 */
const STRANGER_PUBLISHABLE_SUFFIXES = new Set([
  'glitch.me',
  'surge.sh',
  'neocities.org',
  'codesandbox.io',
  'stackblitz.io',
  'val.run',
  'deno.dev',
  'onrender.com',
  'fly.dev',
  'trycloudflare.com',
  'ngrok.io',
  'ngrok-free.app',
  'ngrok.app',
  'loca.lt',
  'serveo.net',
  'repl.co',
  'replit.app',
  'replit.dev',
]);

export interface SharedHostingHit {
  /** The labels the wildcard sits on, e.g. `github.io`. */
  base: string;
  reason: 'public-suffix' | 'known-shared-host';
  detail: string;
}

/**
 * Is this host a wildcard over ground anyone can publish to?
 *
 * Two accepted signals, and the narrowing between them is the whole rule:
 *
 *  1. **Adjacency.** The labels under the `*` are themselves a public suffix,
 *     ICANN or private. `*.github.io`, `*.pages.dev`, `*.s3.amazonaws.com`,
 *     `*.com`. Nobody controls that namespace, so nobody controls what the
 *     wildcard admits.
 *  2. **A short supplement** for stranger-publishable suffixes the PSL private
 *     section does not record.
 *
 * The adjacency requirement is what keeps the PSL delta honest. The delta alone
 * also matches `s3.amazonaws.com`, `blob.core.windows.net`, `appspot.com` and
 * `herokuapp.com` — but `*.mycorp.blob.core.windows.net` is a first-party bucket
 * namespace, not shared hosting, and flagging it is a false positive. Only a
 * wildcard sitting AT the suffix admits strangers.
 *
 * Returns null for `*` itself (PANE-CSP-001/002 owns that) and for every host
 * without a leading `*.` label.
 */
export function isSharedHostingWildcard(host: string): SharedHostingHit | null {
  const h = String(host ?? '').trim().toLowerCase();
  if (!h.startsWith('*.')) return null;

  const base = h.slice(2);
  if (!base || base.includes('*')) return null;

  if (STRANGER_PUBLISHABLE_SUFFIXES.has(base)) {
    return {
      base,
      reason: 'known-shared-host',
      detail: `${base} hands out subdomains to anyone who signs up`,
    };
  }

  const parsed = parseHost(base, { allowPrivateDomains: true });
  // `domain === null` means the labels are a public suffix in their own right,
  // so the wildcard sits directly on it. The isIcann/isPrivate guard rejects
  // hosts tldts cannot place at all — `localhost`, `example`, `invalid`.
  if (parsed.domain === null && (parsed.isIcann === true || parsed.isPrivate === true)) {
    return {
      base,
      reason: 'public-suffix',
      detail:
        parsed.isPrivate === true
          ? `${base} is a Public Suffix List private suffix — its subdomains are handed out to third parties`
          : `${base} is a public suffix, so the wildcard covers every registrable domain under it`,
    };
  }

  return null;
}

// ---------------------------------------------------------------------------
// Coverage — PANE-CSP-006 and PANE-CSP-012
// ---------------------------------------------------------------------------

/** The registrable-ish host a wildcard entry is anchored on, for text search. */
export function anchorHost(p: ParsedSource): string | null {
  if (p.kind !== 'host' || !p.host) return null;
  return p.host.startsWith('*.') ? p.host.slice(2) : p.host;
}

/**
 * Does a declared source expression permit this absolute URL?
 *
 * Deliberately generous. A `PANE-CSP-006` finding says "the host will block
 * this at runtime", so a coverage test that is too strict invents a
 * functionality bug that does not exist. Where the CSP grammar is ambiguous
 * this errs toward "covered".
 */
export function sourceCovers(p: ParsedSource, url: URL): boolean {
  switch (p.kind) {
    case 'bare-wildcard':
      // `*` does not match `data:`/`blob:`, but those are excluded upstream.
      return url.protocol === 'http:' || url.protocol === 'https:';
    case 'scheme-only':
      return `${p.scheme}:` === url.protocol;
    case 'keyword':
      // The app document has an opaque origin; `'self'` reaches no absolute URL.
      return false;
    case 'other':
      return false;
    case 'host':
      break;
  }

  if (!p.host) return false;

  // A schemeless source matches http and https alike; an explicit `http:` source
  // also matches https, per the CSP upgrade rule.
  if (p.scheme && p.scheme !== 'http' && `${p.scheme}:` !== url.protocol) return false;

  const target = url.hostname.toLowerCase();
  if (p.host.startsWith('*.')) {
    if (!target.endsWith(p.host.slice(1))) return false;
  } else if (p.host !== target) {
    return false;
  }

  if (p.port && p.port !== '*') {
    const effective = url.port || (url.protocol === 'https:' ? '443' : '80');
    if (effective !== p.port) return false;
  }

  if (p.path && p.path !== '/') {
    if (p.path.endsWith('/')) {
      if (!url.pathname.startsWith(p.path)) return false;
    } else if (url.pathname !== p.path) {
      return false;
    }
  }

  return true;
}

/** Is any declared entry, anywhere in the four arrays, a cover for this URL? */
export function anyEntryCovers(csp: UIResourceCsp | null, url: URL): boolean {
  return allEntries(csp).some((e) => sourceCovers(parseSource(e.value), url));
}

/**
 * An absolute http(s) URL, or null.
 *
 * `data:`, `blob:`, `mailto:`, fragments, relative paths and protocol-relative
 * references all return null. Every one of those is either not fetch-governed,
 * governed by the mandated default, or same-document — and treating any of them
 * as an external reference is how PANE-CSP-006 would drown a conformant server.
 */
export function absoluteHttpUrl(raw: string | undefined): URL | null {
  if (!raw) return null;
  const trimmed = raw.trim();
  if (!trimmed) return null;
  if (trimmed.startsWith('#') || trimmed.startsWith('/') || trimmed.startsWith('?')) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) return null;
  try {
    const u = new URL(trimmed);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    return u;
  } catch {
    return null;
  }
}

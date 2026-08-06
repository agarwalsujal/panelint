/**
 * URL shape, as the PANE-EXFIL and PANE-INTEGRITY families need it.
 *
 * The organising fact (docs/RULES.md § The finding that reorganized this
 * catalog): the app document's URL is `about:srcdoc`, a `blob:` URL, or an
 * opaque origin. There is no origin to be "same" as, so EVERY absolute URL is
 * off-document and every relative URL is same-document.
 *
 * `shared/helpers.ts` owns `isAbsoluteOffOrigin` and `originOf`, and everything
 * here delegates to them. The one shape they do not cover is the
 * SCHEME-RELATIVE URL, `//host/path`. `new URL("//host")` throws, and the
 * helper's leading-`/` test classifies it as relative — but a srcdoc document
 * inherits its parent's base URL, so `//host/path` resolves to a real origin
 * with a real authority. It cannot be same-document, and treating it as
 * relative is a hole an attacker picks rather than a conservative default.
 *
 * Living in `exfil/` rather than `shared/` is a placement compromise, not a
 * layering claim: PANE-INTEGRITY imports it. Worth hoisting into
 * `rules/shared/helpers.ts` the next time that file is touched.
 */

import type { Node } from 'acorn';
import type { RuleContext, SourceLocation } from '../../types.js';
import type { ParsedScript } from '../../parse/js.js';
import { isAbsoluteOffOrigin, resolveOffDocument } from '../shared/helpers.js';

// The scheme-relative regex that used to live here excluded backslashes and
// whitespace, which is exactly how `//collector.example\\c` and a host split by a
// newline evaded every rule in this file. Classification now goes through
// resolveOffDocument(), which resolves the way a browser does.

/**
 * Is this URL off the app document?
 *
 * True for absolute http(s) and for scheme-relative URLs with an authority.
 * False for the empty string, for `#`, `?`, `/`, `./`, and for every
 * non-network scheme — `javascript:`, `mailto:`, `data:`, `blob:`, `about:`.
 */
export function isOffDocument(url: string): boolean {
  return isAbsoluteOffOrigin(url);
}

/**
 * Origin of an off-document URL, or null.
 *
 * A scheme-relative URL takes the document's scheme, which we do not know. It
 * is normalized to `https:` for comparison against declared domains, since
 * every `_meta.ui.csp` entry observed in the ecosystem is https.
 */
export function offDocumentOrigin(url: string): string | null {
  // A scheme-relative URL takes the document's scheme, which we do not know.
  // resolveOffDocument resolves against an https base, which normalizes it to
  // https — matching every `_meta.ui.csp` entry observed in the ecosystem.
  return resolveOffDocument(url)?.origin ?? null;
}

interface DomainEntry {
  scheme: string | null;
  host: string;
  wildcard: boolean;
}

function parseDomainEntry(raw: string): DomainEntry | null {
  const entry = raw.trim().toLowerCase().replace(/\/+$/, '');
  if (!entry) return null;
  const m = /^(?:([a-z][a-z0-9+.-]*):)?\/\/(.+)$/.exec(entry) ?? /^()(.+)$/.exec(entry);
  if (!m) return null;
  let host = m[2]!;
  const scheme = m[1] ? m[1] : null;
  const wildcard = host.startsWith('*.');
  if (wildcard) host = host.slice(2);
  if (!host) return null;
  return { scheme, host, wildcard };
}

/**
 * Does a declared domain list cover this origin?
 *
 * Handles the two spellings the schema permits in practice: an exact origin and
 * an `https://*.host` subdomain wildcard. A bare `*` covers everything — that
 * is PANE-CSP-001/002's finding to report, not this family's, so here it just
 * means "declared".
 */
export function originDeclared(
  origin: string | null,
  ...lists: Array<readonly string[] | undefined>
): boolean {
  if (!origin) return false;
  let u: URL;
  try {
    u = new URL(origin);
  } catch {
    return false;
  }
  const host = u.hostname.toLowerCase();
  const scheme = u.protocol.replace(/:$/, '');

  for (const list of lists) {
    for (const raw of list ?? []) {
      if (typeof raw !== 'string') continue;
      if (raw.trim() === '*') return true;
      const e = parseDomainEntry(raw);
      if (!e) continue;
      if (e.scheme && e.scheme !== scheme) continue;
      const entryHost = e.host.replace(/:\d+$/, '');
      if (e.wildcard) {
        if (host === entryHost || host.endsWith(`.${entryHost}`)) return true;
      } else if (host === entryHost) {
        return true;
      }
    }
  }
  return false;
}

/**
 * The scripts on a RuleContext, typed as what the engine actually puts there.
 *
 * `RuleContext.scripts` is `ScriptSource[]` with `ast: unknown`, because
 * types.ts must not depend on acorn. `collectScripts` returns `ParsedScript`,
 * which carries the parsed AST and the document line/column rebase. One cast,
 * named, rather than one per call site.
 */
export function scriptsOf(ctx: RuleContext): ParsedScript[] {
  return ctx.scripts as ParsedScript[];
}

/**
 * Rebase an acorn position onto document coordinates.
 *
 * parse/js.ts does this for the queries it exports; a rule walking an AST
 * itself needs the same arithmetic, or every SARIF location inside a `<script>`
 * points at the wrong line.
 */
export function rebase(script: ParsedScript, node: Node): SourceLocation | undefined {
  const n = node as unknown as { loc?: { start: { line: number; column: number } } };
  if (!n.loc) return undefined;
  const line = n.loc.start.line;
  const col = n.loc.start.column + 1;
  return {
    startLine: script.startLine + line - 1,
    startCol: line === 1 ? script.startCol + col - 1 : col,
  };
}

/** Source text of a node, for evidence. Capped at construction by makeFinding. */
export function sourceOf(script: ParsedScript, node: Node): string {
  const n = node as unknown as { start?: number; end?: number };
  if (typeof n.start !== 'number' || typeof n.end !== 'number') return '';
  return script.code.slice(n.start, n.end);
}

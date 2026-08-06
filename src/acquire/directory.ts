/**
 * Directory scanning — partial by construction.
 *
 * Detection order is fixed by docs/DESIGN.md §3.1 and must not be reordered:
 *
 *   1. Walk for the literal `text/html;profile=mcp-app` in any text file.
 *      Language-agnostic and spec-mandated — the ecosystem is not npm-only, so
 *      grepping for `registerAppResource` finds the TypeScript minority and
 *      misses Clojure, Python and hand-rolled Go servers entirely.
 *   2. Walk for the literal `ui://` to collect declared URIs.
 *   3. Resolve each URI by (a) a sibling file whose path tail matches the URI
 *      path, (b) a string or heredoc literal in the same file that parses as
 *      HTML with an <html> or <body> element, (c) a readFile / open / slurp
 *      call with a literal path argument.
 *   4. Anything unresolved emits `resource declared, content not statically
 *      resolvable` — a DIAGNOSTIC, not a finding.
 *
 * Every report prints the resolved/declared ratio. A scan that resolved 2 of 9
 * resources must not read like a clean bill of health.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Two things this module deliberately does NOT do.
 *
 * It never populates `_meta`. A source-level walker cannot tell a declaration
 * from an example of one: measured, three of 21 servers' only apparent
 * `_meta.ui.csp` declarations were `https://api.example.com` placeholders living
 * in READMEs, tests and documentation snippets. So `meta` stays undefined and
 * the rule runner skips every `requires: ['meta']` rule in this mode. The
 * alternative is a scanner that reports a CSP a server does not have.
 *
 * It never follows a path out of the scan root. Every path in step 3(c) is
 * attacker-controlled source in a repository Panelint was pointed at, and
 * `readFileSync("/home/runner/.ssh/id_rsa")` is a one-line arbitrary file read
 * whose bytes would otherwise be hashed, parsed, and emitted as finding evidence
 * into SARIF uploaded to GitHub code scanning. All access goes through
 * src/safe/paths.ts.
 * ─────────────────────────────────────────────────────────────────────────────
 */

import { readdirSync, statSync, lstatSync, realpathSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

import type { ResourceSet, ScanDiagnostic, ScanError, UIResource } from '../types.js';
import { sha256Resource } from './hash.js';
import {
  DIRECTORY_DEFAULTS,
  MCP_APP_MIME,
  SANITIZE_CAPS,
  type DirectoryScanOptions,
  type ResolutionRoute,
} from './types.js';
import {
  hasDeniedFilename,
  hasDeniedSegment,
  readContained,
  resolveContained,
  uriPathTail,
} from '../safe/paths.js';
import { safe } from '../safe/untrusted.js';

/** `ui://` URIs, captured from any quoting style in any language. */
const UI_URI_RE = /ui:\/\/[A-Za-z0-9._~\-]+(?:\/[A-Za-z0-9._~\-%]+)*/g;

/**
 * A literal path handed to a file-reading call.
 *
 * Covers the shapes the ecosystem actually uses: `readFileSync("x")`,
 * `open("x")`, `File.read("x")`, `slurp("x")`, `os.ReadFile("x")`. Only a
 * LITERAL argument is matched — a variable is unresolvable by construction, and
 * guessing at it is how a scanner starts reading files nobody named.
 */
const LITERAL_READ_RE =
  /\b(?:readFileSync|readFile|read_file|ReadFile|open|slurp|load_file|file_get_contents)\s*\(\s*(['"`])([^'"`\n]{1,512})\1/g;

/** A quoted or heredoc literal that looks like a whole HTML document. */
const HTML_LITERAL_RE =
  /(?:"""|'''|`|"|')(\s*(?:<!DOCTYPE[^>]*>)?\s*<(?:html|body)\b[\s\S]{0,200000}?<\/(?:html|body)>\s*)(?:"""|'''|`|"|')/gi;

interface DeclaredUri {
  uri: string;
  /** Repo-relative path of the file that declared it. */
  declaredIn: string;
  /** Absolute path of that file, kept out of all output. */
  declaredInAbsolute: string;
}

export function scanDirectory(root: string, options: DirectoryScanOptions = {}): ResourceSet {
  const opts = { ...DIRECTORY_DEFAULTS, ...options };
  const diagnostics: ScanDiagnostic[] = [];
  const errors: ScanError[] = [];
  const scannedAt = (options.now?.() ?? new Date()).toISOString();

  const empty = (): ResourceSet => ({
    resources: [],
    tools: [],
    diagnostics,
    errors,
    scannedAt,
    source: 'directory',
    resolvedCount: 0,
    declaredCount: 0,
  });

  let rootReal: string;
  try {
    const st = statSync(root);
    if (!st.isDirectory()) {
      errors.push({ code: 'ACQUIRE_FAILED', message: 'Scan target is not a directory.' });
      return empty();
    }
    rootReal = realpathSync(root);
  } catch {
    // Never throw on an unreadable root — report it.
    errors.push({ code: 'ACQUIRE_FAILED', message: 'Scan target could not be read.' });
    return empty();
  }

  // ── Steps 1 and 2: walk, collecting declared URIs and file text ──────────
  const budget = {
    files: 0,
    entries: 0,
    bytes: 0,
    truncated: false,
  };

  /** Repo-relative path → file text. Only files that were read. */
  const fileText = new Map<string, string>();
  const declared = new Map<string, DeclaredUri>();

  const stopWalk = (key: string, observed: number, ceiling: number): boolean => {
    if (observed <= ceiling) return false;
    if (!budget.truncated) {
      budget.truncated = true;
      diagnostics.push({
        code: 'LIMIT_EXCEEDED',
        message: `${key} exceeded: ${observed} > ${ceiling}`,
        detail:
          'The directory scan stopped early, so this result is incomplete and ' +
          'must not be read as an absence of findings.',
      });
    }
    return true;
  };

  const walk = (dir: string): void => {
    if (budget.truncated) return;

    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }

    for (const entry of entries) {
      if (budget.truncated) return;
      if (stopWalk('maxEntries', ++budget.entries, opts.maxEntries)) return;

      const abs = join(dir, entry);
      const rel = relative(rootReal, abs);

      if (hasDeniedSegment(rel) || hasDeniedFilename(rel)) continue;

      let st;
      try {
        st = lstatSync(abs);
      } catch {
        continue;
      }
      // A symlink is never followed during the walk. Following one is how a
      // repo points the scanner at a tree outside the root.
      if (st.isSymbolicLink()) continue;

      if (st.isDirectory()) {
        walk(abs);
        continue;
      }
      if (!st.isFile()) continue;

      if (stopWalk('maxFiles', ++budget.files, opts.maxFiles)) return;

      const contained = resolveContained(rootReal, rel);
      if (!contained.ok) continue;

      const read = readContained(contained.absolute, opts.maxFileBytes);
      if (!read.ok) {
        if (read.reason === 'TOO_LARGE') {
          diagnostics.push({
            code: 'LIMIT_EXCEEDED',
            message: `maxFileBytes exceeded: ${toPosix(rel)} was skipped`,
            detail: 'This file was not read, so anything it declares is invisible to this scan.',
          });
        }
        continue;
      }

      if (stopWalk('maxTotalBytes', (budget.bytes += read.bytes), opts.maxTotalBytes)) return;

      const relPosix = toPosix(contained.relative);
      fileText.set(relPosix, read.text);

      for (const match of read.text.matchAll(UI_URI_RE)) {
        const uri = match[0];
        if (declared.has(uri)) continue;
        if (declared.size >= opts.maxDeclaredUris) {
          stopWalk('maxDeclaredUris', declared.size + 1, opts.maxDeclaredUris);
          return;
        }
        declared.set(uri, {
          uri,
          declaredIn: relPosix,
          declaredInAbsolute: contained.absolute,
        });
      }
    }
  };

  walk(rootReal);

  if (declared.size === 0) {
    diagnostics.push({
      code: 'NO_RESOURCES_FOUND',
      message: 'No ui:// resources were found in this directory.',
      detail:
        'This is not a clean result. Directory mode cannot see runtime-generated ' +
        'HTML; scan the running server or a capture to get a complete picture.',
    });
    return { ...empty(), diagnostics, errors };
  }

  // ── Step 3: resolve, in the fixed order (a) → (b) → (c) ──────────────────
  const resources: UIResource[] = [];

  for (const decl of [...declared.values()].sort((a, b) => a.uri.localeCompare(b.uri))) {
    const resolved =
      resolveBySiblingFile(rootReal, decl, opts.maxFileBytes) ??
      resolveByInlineLiteral(decl, fileText) ??
      resolveByLiteralReadCall(rootReal, decl, fileText, opts.maxFileBytes);

    if (!resolved) {
      // Step 4. A diagnostic, never a finding — and it names only the URI. The
      // paths that failed came from attacker-controlled source and must not be
      // echoed into a report.
      diagnostics.push({
        code: 'UNRESOLVED_URI',
        message: 'resource declared, content not statically resolvable',
        resourceUri: safe(decl.uri, SANITIZE_CAPS.uri),
        detail:
          'Directory mode resolves HTML only from a matching sibling file, an ' +
          'inline literal, or a literal-path read call. Scan the running server ' +
          'or a capture to see what it actually serves.',
      });
      continue;
    }

    resources.push({
      uri: safe(decl.uri, SANITIZE_CAPS.uri),
      // Directory mode cannot observe what a server serves. The spec-mandated
      // type is recorded as the declared intent, not as an observation.
      mimeType: MCP_APP_MIME,
      content: resolved.content,
      contentHash: sha256Resource({ text: resolved.content }),
      schemaErrors: [],
      source: 'directory',
      filePath: safe(resolved.filePath, SANITIZE_CAPS.path),
      // `meta` is deliberately absent. See the header note.
    });
  }

  return {
    resources,
    tools: [],
    diagnostics,
    errors,
    scannedAt,
    source: 'directory',
    resolvedCount: resources.length,
    declaredCount: declared.size,
  };
}

// ---------------------------------------------------------------------------
// Resolution routes
// ---------------------------------------------------------------------------

interface Resolved {
  content: string;
  /** Repo-relative. An absolute host path must never reach a ResourceSet. */
  filePath: string;
  route: ResolutionRoute;
}

/** (a) a sibling file whose path tail matches the URI path. */
function resolveBySiblingFile(root: string, decl: DeclaredUri, maxBytes: number): Resolved | null {
  const tail = uriPathTail(decl.uri);
  if (!tail) return null;

  const contained = resolveContained(root, tail);
  if (!contained.ok) return null;

  const read = readContained(contained.absolute, maxBytes);
  if (!read.ok) return null;

  return { content: read.text, filePath: toPosix(contained.relative), route: 'sibling-file' };
}

/**
 * (b) a string or heredoc literal in the same file that parses as HTML.
 *
 * Requires an `<html>` or `<body>` element specifically. A literal containing
 * `<div>` fragments is a template being assembled at runtime, not a resource —
 * and treating it as one is how directory mode would start reporting on HTML
 * that no server ever serves.
 */
function resolveByInlineLiteral(decl: DeclaredUri, files: Map<string, string>): Resolved | null {
  const source = files.get(decl.declaredIn);
  if (!source) return null;

  HTML_LITERAL_RE.lastIndex = 0;
  const match = HTML_LITERAL_RE.exec(source);
  if (!match?.[1]) return null;

  return { content: match[1].trim(), filePath: decl.declaredIn, route: 'inline-literal' };
}

/** (c) a readFile / open / slurp call with a literal path argument. */
function resolveByLiteralReadCall(
  root: string,
  decl: DeclaredUri,
  files: Map<string, string>,
  maxBytes: number,
): Resolved | null {
  const source = files.get(decl.declaredIn);
  if (!source) return null;

  LITERAL_READ_RE.lastIndex = 0;
  for (const match of source.matchAll(LITERAL_READ_RE)) {
    const candidate = match[2];
    if (!candidate) continue;

    // resolveContained rejects absolute paths, `..` segments, denied
    // directories, denied filenames, symlinks, and anything whose realpath
    // escapes the root. Every rejection here is a file Panelint will not read.
    const contained = resolveContained(root, candidate);
    if (!contained.ok) continue;

    const read = readContained(contained.absolute, maxBytes);
    if (!read.ok) continue;

    return { content: read.text, filePath: toPosix(contained.relative), route: 'literal-read-call' };
  }
  return null;
}

/** Repo-relative paths are reported with forward slashes on every platform. */
function toPosix(p: string): string {
  return sep === '/' ? p : p.split(sep).join('/');
}

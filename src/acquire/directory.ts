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

/**
 * `ui://` URIs, captured from any quoting style in any language.
 *
 * The `i` flag is load-bearing and applies only to the scheme: the character
 * classes already span both cases. RFC 3986 §3.1 makes a scheme
 * case-insensitive, so `UI://server/view` names the same resource — and
 * without the flag a one-character change made a declared resource invisible
 * to directory mode, matching the same gap the live and capture paths had.
 */
const UI_URI_RE = /ui:\/\/[A-Za-z0-9._~\-]+(?:\/[A-Za-z0-9._~\-%]+)*/gi;

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

/**
 * How many distinct files may be remembered as declaring one URI.
 *
 * Every site is a resolution candidate, so this bounds the work a hostile tree
 * can force: mentioning one URI in 50,000 files must not turn into 50,000
 * resolution attempts. Real repositories declare a resource in one file and
 * mention it in a handful more — a README, a test, a changelog — so this is far
 * above any honest use and far below anything expensive.
 */
const MAX_DECLARATION_SITES = 32;

/**
 * How many HTML literals in one file may be treated as candidates.
 *
 * Same bound, one level down. Taking only the FIRST literal made a decoy
 * string above the real template a deletion rather than an addition, which is
 * the invariant this module is supposed to hold.
 */
const MAX_INLINE_LITERALS = 16;

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
  /**
   * URI → **every** file that mentions it, in walk order.
   *
   * This was `Map<string, DeclaredUri>` — first mention wins — and that was an
   * attacker-controlled gate bypass. Routes (b) and (c) below look inside the
   * declaring file, so whichever file the walk happened to reach first decided
   * whether the resource resolved at all. A file that merely *mentions* the URI
   * — a README line, a changelog entry, a test fixture — stole the declaration
   * from the code that actually registers it, the real resource became
   * UNRESOLVED_URI, and the scan reported zero findings and exited 0.
   *
   * Reproduced before the fix: a tree with a hostile `<form action=...>` gated
   * at exit 1; adding one markdown file containing the URI took it to 0
   * findings and exit 0. `UNRESOLVED_URI` is a diagnostic, so `--on-error fail`
   * did not react either.
   *
   * Collecting every site and trying each is what closes it. Walk order stops
   * mattering: a decoy can add a site, but it cannot remove the real one.
   */
  const declared = new Map<string, DeclaredUri[]>();
  /** URIs whose declaration-site list hit MAX_DECLARATION_SITES and lost sites. */
  const sitesTruncated = new Set<string>();
  /** Top-level names pruned by the deny list, so the report can name them. */
  const pruned = new Set<string>();
  /** Files skipped because their extension is not in the allowlist. */
  let skippedByExtension = 0;

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

      if (hasDeniedSegment(rel) || hasDeniedFilename(rel)) {
        // Counted, not silent. `dist/` and `build/` are on the deny list, and
        // they are exactly where a TypeScript MCP server's compiled `server.js`
        // — with its inline `registerAppResource` HTML — ends up. Pruning them
        // is right, but a scan that printed `resolved 0 of 0` and said nothing
        // read as a complete scan of a repository with no app resources.
        if (hasDeniedSegment(rel)) pruned.add(toPosix(rel).split('/')[0] ?? toPosix(rel));
        // A denied FILENAME is a skip too, and it was the one walk skip with no
        // counter left in a change whose whole point was counting walk skips.
        // `DENY_FILE_PATTERNS` includes `/^id_(rsa|dsa|ecdsa|ed25519)/i`, which
        // matches an ordinary `id_rsa.js`.
        else skippedByExtension++;
        continue;
      }

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
        } else if (read.reason === 'EXTENSION') {
          // Aggregated, not one per file: a repository has thousands of these
          // and they are overwhelmingly images and lockfiles. The count is what
          // matters — it says the walk did not read everything.
          skippedByExtension++;
        } else {
          // Every other reason used to `continue` with NO diagnostic at all, so
          // a file the scanner refused was indistinguishable from a file that
          // said nothing. That is a deletion the scanned tree can perform.
          diagnostics.push({
            code: 'LIMIT_EXCEEDED',
            message: `${toPosix(rel)} could not be read (${read.reason}) and was skipped`,
            detail:
              'This file was not read, so anything it declares is invisible to this scan. ' +
              'A resource declared only here resolves to nothing.',
          });
        }
        continue;
      }

      if (stopWalk('maxTotalBytes', (budget.bytes += read.bytes), opts.maxTotalBytes)) return;

      const relPosix = toPosix(contained.relative);
      fileText.set(relPosix, read.text);

      for (const match of read.text.matchAll(UI_URI_RE)) {
        const uri = match[0];
        const site: DeclaredUri = {
          uri,
          declaredIn: relPosix,
          declaredInAbsolute: contained.absolute,
        };

        const sites = declared.get(uri);
        if (sites) {
          // One file mentioning the same URI twice adds nothing to resolve
          // from, and MAX_DECLARATION_SITES bounds a tree that mentions one URI
          // in thousands of files.
          //
          // The cap fills in walk order, so 32 decoy files that merely NAME the
          // URI evict the one that declares it — measured, 31 decoys exit 1 and
          // 32 exit 0. Dropping is recorded so the resolution loop can turn it
          // into LIMIT_EXCEEDED instead of a silent clean report.
          if (sites[sites.length - 1]?.declaredIn === relPosix) {
            continue;
          }
          if (sites.length < MAX_DECLARATION_SITES) {
            sites.push(site);
          } else {
            sitesTruncated.add(uri);
          }
          continue;
        }

        if (declared.size >= opts.maxDeclaredUris) {
          stopWalk('maxDeclaredUris', declared.size + 1, opts.maxDeclaredUris);
          return;
        }
        declared.set(uri, [site]);
      }
    }
  };

  walk(rootReal);

  // What the walk chose not to look at. Without this the ratio line reads as a
  // complete scan: a TypeScript server whose only built artefact is `dist/`
  // reported `resolved 0 of 0` and named nothing it had skipped.
  if (pruned.size > 0 || skippedByExtension > 0) {
    const parts: string[] = [];
    if (pruned.size > 0) parts.push(`pruned ${[...pruned].sort().join(', ')}`);
    if (skippedByExtension > 0) parts.push(`${skippedByExtension} file(s) of unscanned type`);
    diagnostics.push({
      code: 'CAPABILITY_NOT_DECLARED',
      message: `Directory walk skipped part of the tree: ${parts.join('; ')}.`,
      detail:
        'Build output and dependency directories are not read, and only source-shaped ' +
        'extensions are. A server whose only app HTML lives in a build artefact resolves ' +
        'nothing here — scan the running server or a capture instead.',
    });
  }

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

  const declaredSorted = [...declared.values()].sort((a, b) =>
    (a[0]?.uri ?? '').localeCompare(b[0]?.uri ?? ''),
  );

  for (const sites of declaredSorted) {
    const decl = sites[0]!;

    // ── Every route is resolved, not just the first that answers ───────────
    // (a) used to be tried first and win outright, so a hostile PR author who
    // controls both files added a 38-byte `app/panel.html` containing
    // `<h1>ok</h1>` and the real inline literal in `server.js` was never read:
    // 7 findings and 5 gating became 0 findings at exit 0, with no diagnostic
    // that a second candidate had ever existed.
    //
    // The earlier fix here made (b) and (c) try every declaring SITE, which
    // stopped a decoy declaration site from hiding a real one. It did not stop
    // a decoy ROUTE from hiding a real one, because the routes are still
    // ordered and the first still wins.
    //
    // Candidates are collected from all three routes and deduplicated by
    // content hash. When they disagree, every distinct content is scanned:
    // adding a benign file can then only ADD a resource, never remove one.
    const candidates: Array<{ resolved: Resolved; hash: string }> = [];
    const seenHashes = new Set<string>();
    const addCandidate = (r: Resolved | null): void => {
      if (!r) return;
      const hash = sha256Resource({ text: r.content });
      if (seenHashes.has(hash)) return;
      seenHashes.add(hash);
      candidates.push({ resolved: r, hash });
    };

    addCandidate(resolveBySiblingFile(rootReal, decl, opts.maxFileBytes));
    let literalsTruncated = false;
    for (const site of sites) {
      const literals = resolveByInlineLiterals(site, fileText);
      if (literals.truncated) literalsTruncated = true;
      for (const r of literals.resolved) addCandidate(r);

      const reads = resolveByLiteralReadCalls(rootReal, site, fileText, opts.maxFileBytes);
      if (reads.truncated) literalsTruncated = true;
      for (const r of reads.resolved) addCandidate(r);
    }

    // Either cap dropped a candidate the scanned tree chose the position of, so
    // whatever was dropped is exactly what an attacker would want dropped. This
    // is LIMIT_EXCEEDED rather than a note because `scanWasTruncated` reads it
    // and `--on-error fail` then exits 2 — the analysis is incomplete, and an
    // incomplete analysis must not be reportable as clean.
    if (literalsTruncated || sitesTruncated.has(decl.uri)) {
      diagnostics.push({
        code: 'LIMIT_EXCEEDED',
        resourceUri: safe(decl.uri, SANITIZE_CAPS.uri),
        message: literalsTruncated
          ? `more than ${MAX_INLINE_LITERALS} HTML literals declare this URI in one file`
          : `more than ${MAX_DECLARATION_SITES} files declare this URI`,
        detail:
          'Candidates past the cap were not resolved, so a zero-finding result for this URI is ' +
          'an absence of analysis rather than an absence of findings. Both caps fill in walk ' +
          'order, which the scanned tree chooses.',
      });
    }

    if (candidates.length > 1) {
      diagnostics.push({
        code: 'UNRESOLVED_URI',
        resourceUri: safe(decl.uri, SANITIZE_CAPS.uri),
        message:
          `${candidates.length} different contents resolve for this URI; ` +
          (literalsTruncated || sitesTruncated.has(decl.uri)
            ? 'those that fit within the caps were scanned.'
            : 'all were scanned.'),
        detail:
          'A sibling file, an inline literal and a literal-path read call disagreed. Which one the ' +
          'server actually serves is not decidable from source, so none was preferred.',
      });
    }

    if (candidates.length === 0) {
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

    for (const { resolved, hash } of candidates) {
      resources.push({
        uri: safe(decl.uri, SANITIZE_CAPS.uri),
        // Directory mode cannot observe what a server serves. The spec-mandated
        // type is recorded as the declared intent, not as an observation.
        mimeType: MCP_APP_MIME,
        content: resolved.content,
        contentHash: hash,
        schemaErrors: [],
        source: 'directory',
        filePath: safe(resolved.filePath, SANITIZE_CAPS.path),
        // `meta` is deliberately absent. See the header note.
      });
    }
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
function resolveByInlineLiterals(
  decl: DeclaredUri,
  files: Map<string, string>,
): { resolved: Resolved[]; truncated: boolean } {
  const empty = { resolved: [], truncated: false };
  const source = files.get(decl.declaredIn);
  if (!source) return empty;

  // The lazy `[\s\S]{0,200000}?` in HTML_LITERAL_RE scans up to 200 KB from
  // every `"<html` looking for a close tag. In a file with many opens and no
  // close, that is quadratic (512 KB of `'"<html '` → 16s). A match is
  // impossible without a close tag, so its absence is a linear-time bail.
  if (!/<\/(?:html|body)>/i.test(source)) return empty;

  // EVERY literal, not the first one.
  //
  // `exec` took the earliest match in the file, and the earliest match is a
  // position a contributor controls: one line above the real template, in the
  // very file that declares the URI, `const help = "<html><body><h1>ok</h1>…"`
  // became the resource. Measured before this changed — 3 gating findings went
  // to 0 while the report still said `resolved 1 of 1` and printed a 37-byte
  // resource in place of the real 250-byte one.
  //
  // The caller hashes and de-duplicates these and warns when more than one
  // distinct content survives, so returning several is cheap and adding a
  // literal can only add a candidate.
  // Truncation here is reported, never silent. Capping at N and stopping would
  // rebuild the very bug this function exists to fix: the cap fills from the
  // FRONT of the file, so N decoys above the real template push it out again —
  // measured at exactly MAX_INLINE_LITERALS, 1 gating finding went to 0 at
  // exit 0. A bound the scanned party can reach must cost it an exit 2, not buy
  // it a clean report.
  const out: Resolved[] = [];
  let truncated = false;
  for (const match of source.matchAll(HTML_LITERAL_RE)) {
    const content = match[1]?.trim();
    if (!content) continue;
    if (out.length >= MAX_INLINE_LITERALS) {
      truncated = true;
      break;
    }
    out.push({ content, filePath: decl.declaredIn, route: 'inline-literal' });
  }
  return { resolved: out, truncated };
}

/** (c) a readFile / open / slurp call with a literal path argument. */
function resolveByLiteralReadCalls(
  root: string,
  decl: DeclaredUri,
  files: Map<string, string>,
  maxBytes: number,
): { resolved: Resolved[]; truncated: boolean } {
  const empty = { resolved: [], truncated: false };
  const source = files.get(decl.declaredIn);
  if (!source) return empty;

  // EVERY read call, not the first that resolves.
  //
  // This was the same first-match-wins shape that route (b) had, and the fix
  // there did not reach here. The earliest `readFileSync("…")` in the file won
  // outright, and its position is a position a contributor controls:
  //
  //   const pkg  = JSON.parse(fs.readFileSync("package.json", "utf8"));
  //   const html = fs.readFileSync("templates/board.html", "utf8");
  //
  // Measured — one added line took 1 gating finding to 0 at exit 0, while the
  // report said `resolved 1 of 1` and printed package.json as the app
  // resource. It is not only an attack: reading a config file before a
  // template is how most Python and Node servers are written, so first-match
  // was also a systematic false negative.
  const out: Resolved[] = [];
  let truncated = false;
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

    if (out.length >= MAX_INLINE_LITERALS) {
      truncated = true;
      break;
    }
    out.push({
      content: read.text,
      filePath: toPosix(contained.relative),
      route: 'literal-read-call',
    });
  }
  return { resolved: out, truncated };
}

/** Repo-relative paths are reported with forward slashes on every platform. */
function toPosix(p: string): string {
  return sep === '/' ? p : p.split(sep).join('/');
}

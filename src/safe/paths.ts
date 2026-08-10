/**
 * Path containment for directory mode.
 *
 * Directory scanning resolves a `ui://` URI to a file by, among other routes,
 * "a `readFile` / `open` / `slurp` call with a literal path argument" — and
 * that literal is attacker-controlled source in a repository Panelint was
 * pointed at. A hostile or merely typosquatted MCP server repo containing
 *
 *     const html = readFileSync("/home/runner/.ssh/id_rsa");
 *
 * would otherwise be resolved, hashed, parsed, and have its bytes emitted as
 * finding evidence — into SARIF uploaded to GitHub code scanning, and into the
 * JSON envelope the public directory consumes. A symlink `view.html ->
 * /proc/self/environ` reaches the same place by a shorter route.
 *
 * So every candidate path goes through `resolveContained`, which:
 *   - rejects absolute paths and `..` segments before resolving,
 *   - realpaths the result and requires it to stay under the root,
 *   - refuses symlinks outright at the final component,
 *   - re-checks containment on the OPEN FILE DESCRIPTOR, because a repo can
 *     swap a symlink between the check and the read,
 *   - enforces an extension allowlist and a byte cap.
 */

import { openSync, fstatSync, readSync, closeSync, lstatSync, realpathSync } from 'node:fs';
import { resolve, sep, extname, relative, isAbsolute, normalize } from 'node:path';

/** Content Panelint will treat as a candidate UI resource. */
const ALLOWED_EXTENSIONS = new Set(['.html', '.htm', '.xhtml', '.tpl', '.hbs', '.ejs', '.svelte', '.vue', '.jsx', '.tsx', '.js', '.ts', '.mjs', '.cjs', '.py', '.rb', '.go', '.rs', '.clj', '.php', '.java', '.kt', '.cs', '.json', '.yaml', '.yml', '.md', '.txt']);

/** Content that must never be read, regardless of where it sits. */
const DENY_SEGMENTS = new Set(['.git', 'node_modules', '.svn', '.hg', 'vendor', 'dist', 'build', '.venv', 'venv', '__pycache__', 'target', '.next', '.cache']);

const DENY_FILE_PATTERNS = [
  /^\.env($|\.)/i,
  /\.pem$/i,
  /\.key$/i,
  /^id_(rsa|dsa|ecdsa|ed25519)/i,
  /\.p12$/i,
  /\.pfx$/i,
  /\.keystore$/i,
  /^\.npmrc$/i,
  /^\.netrc$/i,
];

export type PathRejection =
  | 'ABSOLUTE'
  | 'TRAVERSAL'
  | 'ESCAPES_ROOT'
  | 'SYMLINK'
  | 'DENIED_DIRECTORY'
  | 'DENIED_FILENAME'
  | 'EXTENSION'
  | 'TOO_LARGE'
  | 'NOT_A_FILE'
  | 'UNREADABLE'
  | 'BINARY';

export type ContainedPath =
  | { ok: true; absolute: string; relative: string }
  | { ok: false; reason: PathRejection };

/** Is any segment of this path on the deny list? */
export function hasDeniedSegment(relPath: string): boolean {
  return relPath.split(/[\\/]/).some((s) => DENY_SEGMENTS.has(s));
}

export function hasDeniedFilename(relPath: string): boolean {
  const base = relPath.split(/[\\/]/).pop() ?? '';
  return DENY_FILE_PATTERNS.some((re) => re.test(base));
}

/**
 * Resolve `candidate` under `root`, refusing anything that escapes.
 *
 * `candidate` may be repo-relative or a URI path tail. It may never be
 * absolute, and it may never contain a `..` segment — both are rejected before
 * resolution rather than relying on the containment check alone, so the check
 * is not the single barrier.
 */
export function resolveContained(root: string, candidate: string): ContainedPath {
  if (candidate.includes('\0')) return { ok: false, reason: 'TRAVERSAL' };
  if (isAbsolute(candidate)) return { ok: false, reason: 'ABSOLUTE' };

  const normalized = normalize(candidate);
  if (normalized.split(/[\\/]/).includes('..')) return { ok: false, reason: 'TRAVERSAL' };
  if (hasDeniedSegment(normalized)) return { ok: false, reason: 'DENIED_DIRECTORY' };
  if (hasDeniedFilename(normalized)) return { ok: false, reason: 'DENIED_FILENAME' };

  const rootReal = safeRealpath(root);
  if (!rootReal) return { ok: false, reason: 'UNREADABLE' };

  const absolute = resolve(rootReal, normalized);
  if (!isUnder(rootReal, absolute)) return { ok: false, reason: 'ESCAPES_ROOT' };

  // Refuse a symlink at the final component. Following one is how
  // `view.html -> /proc/self/environ` becomes an arbitrary file read.
  let stat;
  try {
    stat = lstatSync(absolute);
  } catch {
    return { ok: false, reason: 'UNREADABLE' };
  }
  if (stat.isSymbolicLink()) return { ok: false, reason: 'SYMLINK' };
  if (!stat.isFile()) return { ok: false, reason: 'NOT_A_FILE' };

  const real = safeRealpath(absolute);
  if (!real || !isUnder(rootReal, real)) return { ok: false, reason: 'ESCAPES_ROOT' };

  return { ok: true, absolute: real, relative: relative(rootReal, real) };
}

/**
 * Is `candidate` the same file as, or inside, `root`?
 *
 * Both sides are realpath'd first, so a symlink cannot answer "outside" for a
 * file that is really inside. Used to refuse a baseline file that lives in the
 * tree being scanned — a baseline accepts findings, so a scanned repository
 * supplying its own is the same class of hole as a repo config lowering its own
 * severities.
 *
 * Falls back to the lexical answer when either path cannot be realpath'd, and
 * a path that cannot be resolved is treated as inside: the caller uses this to
 * REFUSE, so an unresolvable path should fail closed.
 */
export function isInside(root: string, candidate: string): boolean {
  const rootReal = safeRealpath(root);
  const candReal = safeRealpath(candidate);
  if (!rootReal) return true;
  return isUnder(rootReal, candReal ?? resolve(candidate));
}

function isUnder(root: string, candidate: string): boolean {
  if (candidate === root) return true;
  return candidate.startsWith(root.endsWith(sep) ? root : root + sep);
}

function safeRealpath(p: string): string | null {
  try {
    return realpathSync(p);
  } catch {
    return null;
  }
}

export interface ReadResult {
  ok: true;
  text: string;
  bytes: number;
}

/**
 * Read a contained file, re-checking on the descriptor.
 *
 * The containment check above operates on a path string. A repository can
 * replace that path with a symlink between the check and the read, so the size
 * and type checks that actually gate the read are done via `fstat` on the open
 * descriptor rather than by trusting the earlier `lstat`.
 */
export function readContained(
  absolute: string,
  maxBytes: number,
  enforceExtension = true,
): ReadResult | { ok: false; reason: PathRejection } {
  if (enforceExtension && !ALLOWED_EXTENSIONS.has(extname(absolute).toLowerCase())) {
    return { ok: false, reason: 'EXTENSION' };
  }

  let fd: number;
  try {
    fd = openSync(absolute, 'r');
  } catch {
    return { ok: false, reason: 'UNREADABLE' };
  }

  try {
    const st = fstatSync(fd);
    if (!st.isFile()) return { ok: false, reason: 'NOT_A_FILE' };
    if (st.size > maxBytes) return { ok: false, reason: 'TOO_LARGE' };

    const buf = Buffer.allocUnsafe(st.size);
    let read = 0;
    while (read < st.size) {
      const n = readSync(fd, buf, read, st.size - read, read);
      if (n <= 0) break;
      read += n;
    }
    const slice = buf.subarray(0, read);

    // Binary detection is PROPORTIONAL, not "contains a NUL".
    //
    // The goal is keeping binary out of evidence strings, and a single NUL does
    // not make a file binary — it makes it a text file with a NUL in it. The
    // old test refused the whole file, so `<!--\0-->` prepended to a template
    // took it out of the scan entirely: `resolved 0 of 1`, UNRESOLVED_URI,
    // exit 0, and the diagnostic claimed the content was "not statically
    // resolvable" when parse5 reads it identically to the original. A NUL in a
    // block comment did the same to a `.js` file that Node still executes.
    //
    // A real binary is dense with control bytes; source text is not. Sample the
    // head, and refuse only when the density says image or archive. HTML's own
    // tokenizer replaces U+0000 with U+FFFD, which is what happens below.
    const sample = slice.subarray(0, 4096);
    let control = 0;
    for (const b of sample) {
      if (b === 9 || b === 10 || b === 13) continue;
      if (b === 0 || b < 8 || (b >= 14 && b <= 31) || b === 127) control++;
    }
    // Decisively binary, not merely suspicious. Source text sits near zero;
    // images and archives sit far above this. The threshold is deliberately
    // permissive because the two failure directions are not symmetric: reading
    // a binary as text yields garbage nobody acts on, while refusing a text
    // file deletes it from the scan, and the scanned tree picks the bytes. A
    // 1% test refused a 93-byte source file over a single NUL.
    if (sample.length > 0 && control / sample.length > 0.1) {
      return { ok: false, reason: 'BINARY' };
    }

    // `toString('utf8')` already maps a lone NUL to U+0000 rather than to a
    // replacement character, so strip it explicitly — nothing downstream should
    // ever quote a NUL into a report.
    return { ok: true, text: slice.toString('utf8').replace(/\0/g, '�'), bytes: read };
  } catch {
    return { ok: false, reason: 'UNREADABLE' };
  } finally {
    try {
      closeSync(fd);
    } catch {
      /* already closed */
    }
  }
}

/**
 * Normalize the path component of a `ui://` URI before using it to match files.
 *
 * The URI is server-supplied. Percent-decoded once, then rejected if it
 * contains a traversal segment, a NUL, or an absolute path — the same rules the
 * filesystem side applies, because this string becomes a filesystem query.
 */
export function uriPathTail(uri: string): string | null {
  const withoutScheme = uri.replace(/^ui:\/\//i, '');
  let decoded: string;
  try {
    decoded = decodeURIComponent(withoutScheme);
  } catch {
    return null;
  }
  if (decoded.includes('\0')) return null;
  const parts = decoded.split('/').filter((s) => s.length > 0);
  if (parts.includes('..') || parts.includes('.')) return null;
  return parts.join('/') || null;
}

export { ALLOWED_EXTENSIONS };

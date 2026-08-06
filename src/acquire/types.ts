/**
 * Shared types for the acquire stage.
 *
 * Four sources produce one output type (`ResourceSet`, src/types.ts). This file
 * carries the things two or more of them need: the capture file format, the
 * directory-scan budgets, and the sanitisation caps applied at the acquire
 * boundary.
 *
 * Everything a scanned server or a scanned repository authored is untrusted at
 * this boundary — server name, resource URI, MIME type, tool name, tool
 * description. `safe()` runs here, once, so no later stage has to remember.
 */

import type { Limits } from '../types.js';

/**
 * Does this URI use the `ui://` scheme?
 *
 * Case-INSENSITIVE on the scheme, per RFC 3986 §3.1 — which is the position
 * `src/rules/spec/uri.ts` already takes: `UI://server/view` names the same
 * resource as `ui://server/view`.
 *
 * All three acquire paths used `startsWith('ui://')`, matching lowercase only.
 * A hostile resource at `UI://evil/panel.html` produced zero resources, exit 0,
 * and not even a NO_RESOURCES_FOUND diagnostic, because the entry existed and
 * was filtered out rather than being absent. One uppercase character bypassed
 * the whole scanner. The alternative reading — that hosts are case-sensitive
 * here — makes PANE-SPEC-001 unreachable dead code, since the acquire filter
 * would be stricter than the rule it feeds. Both readings required this fix.
 */
export function isUiUri(uri: unknown): uri is string {
  return typeof uri === 'string' && uri.slice(0, 5).toLowerCase() === 'ui://';
}

// ---------------------------------------------------------------------------
// Sanitisation caps
// ---------------------------------------------------------------------------

/**
 * Caps for `safe()` at the acquire boundary. These bound the *identifier*
 * strings only. Resource content is never sanitised here — rules parse the real
 * markup, and evidence is escaped and capped at finding-construction time
 * instead (`Limits.maxEvidenceChars`).
 */
export const SANITIZE_CAPS = Object.freeze({
  uri: 512,
  name: 256,
  mimeType: 256,
  version: 128,
  description: 4_096,
  path: 512,
});

// ---------------------------------------------------------------------------
// Capture file format
// ---------------------------------------------------------------------------

/**
 * A capture is JSON someone else produced and committed, and CI scans it
 * unattended. It is therefore treated as hostile input, not as a trusted cache:
 *
 *   - `contentHash` is ALWAYS recomputed. A hash carried in the file is ignored,
 *     and a mismatch is reported. Otherwise a vendor hands you a capture whose
 *     hash is that of a clean resource, and the census entry and the disclosure
 *     email both cite a hash that never existed.
 *   - Unknown top-level keys are rejected rather than ignored, so a capture can
 *     never grow a field that a future version would act on.
 *   - A capture can never carry a spawn command, an argv, an environment, a URL
 *     or a config block. Replay reads JSON; it does not start processes.
 */
export const CAPTURE_FORMAT_VERSION = 1;

export interface CaptureServerInfo {
  name?: string;
  version?: string;
}

/**
 * The `initialize` result, retained whole.
 *
 * PANE-SPEC-007 asserts that the declared extension `mimeTypes` array contains
 * `text/html;profile=mcp-app`. It cannot run at all if the capture format drops
 * server capabilities, so `initialize` is required, not optional.
 */
export interface CaptureInitializeResult {
  protocolVersion?: string;
  capabilities?: Record<string, unknown>;
  serverInfo?: CaptureServerInfo;
  instructions?: string;
  _meta?: Record<string, unknown>;
}

/** One `resources/list` entry, with its `_meta` — the connection-time default. */
export interface CaptureListedResource {
  uri: string;
  name?: string;
  title?: string;
  description?: string;
  mimeType?: string;
  _meta?: Record<string, unknown>;
}

/** One content item from a `resources/read` result. */
export interface CaptureContentItem {
  uri?: string;
  mimeType?: string;
  text?: string;
  /** base64, exactly as it arrived on the wire. Validated strictly before decode. */
  blob?: string;
  _meta?: Record<string, unknown>;
}

/** One `resources/read` result, keyed by the URI that was read. */
export interface CaptureReadEntry {
  uri: string;
  contents: CaptureContentItem[];
}

/** One `tools/list` entry. Six rules die without these. */
export interface CaptureTool {
  name: string;
  title?: string;
  description?: string;
  inputSchema?: unknown;
  outputSchema?: unknown;
  annotations?: Record<string, unknown>;
  _meta?: Record<string, unknown>;
}

export interface CaptureFile {
  /** Format version. Unknown versions are refused, never best-effort parsed. */
  panelintCapture: number;
  capturedAt?: string;
  initialize: CaptureInitializeResult;
  resourcesList: CaptureListedResource[];
  /**
   * `resources/read` results. An array rather than a URI-keyed object: an object
   * invites `__proto__` and `constructor` as keys, and an array does not.
   */
  resourcesRead: CaptureReadEntry[];
  /** Present even when empty — a missing key is a recording bug, not "no tools". */
  toolsList: CaptureTool[];
}

export const CAPTURE_TOP_LEVEL_KEYS: readonly string[] = Object.freeze([
  'panelintCapture',
  'capturedAt',
  'initialize',
  'resourcesList',
  'resourcesRead',
  'toolsList',
]);

/**
 * Keys that name an execution or a network target.
 *
 * Rejecting unknown keys already excludes these. They are enumerated anyway so
 * the refusal carries a specific message, and so a future format version cannot
 * add one of them without deleting a line from this list first.
 */
export const CAPTURE_FORBIDDEN_KEYS: readonly string[] = Object.freeze([
  'command',
  'args',
  'argv',
  'env',
  'environment',
  'cwd',
  'config',
  'spawn',
  'transport',
  'url',
  'endpoint',
  'headers',
  'server',
  'exec',
  'shell',
]);

export type CaptureErrorCode =
  | 'UNREADABLE'
  | 'TOO_LARGE'
  | 'INVALID_JSON'
  | 'UNSUPPORTED_VERSION'
  | 'UNKNOWN_KEY'
  | 'FORBIDDEN_KEY'
  | 'INVALID_SHAPE'
  | 'EXISTS'
  | 'REFUSED';

/** A capture that cannot be replayed at all. Per-resource problems are diagnostics. */
export class CaptureError extends Error {
  readonly code: CaptureErrorCode;
  constructor(code: CaptureErrorCode, message: string) {
    super(message);
    this.name = 'CaptureError';
    this.code = code;
  }
}

export interface CaptureLoadOptions {
  limits?: Limits;
  /** Ceiling on the capture file itself. Default 64 MB. */
  maxCaptureBytes?: number;
  now?: () => Date;
}

export interface WriteCaptureOptions {
  /**
   * Overwrite an existing file. Off by default: a hostile repository can
   * pre-plant `panelint.capture.json` as a symlink to `~/.zshrc`, and the
   * default open mode is `wx` so that plant fails instead of truncating.
   */
  force?: boolean;
}

/** Default ceiling on a capture file, before JSON.parse ever sees it. */
export const DEFAULT_MAX_CAPTURE_BYTES = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Directory scanning
// ---------------------------------------------------------------------------

/** The literal the spec reserves. Detection step 1, language-agnostic. */
export const MCP_APP_MIME = 'text/html;profile=mcp-app';

/**
 * Directory-mode budgets.
 *
 * Directory mode walks a repository Panelint was pointed at, so the tree, the
 * file sizes and the file count are all attacker-chosen. Exceeding a budget
 * emits a LIMIT_EXCEEDED diagnostic and truncates the scan; it never throws, and
 * it never silently produces a clean-looking result.
 */
export const DIRECTORY_DEFAULTS = Object.freeze({
  maxFiles: 5_000,
  maxTotalBytes: 64 * 1024 * 1024,
  maxFileBytes: 2 * 1024 * 1024,
  /** Directory entries visited, including ones that are skipped. */
  maxEntries: 50_000,
  /** Distinct `ui://` URIs collected before the walk stops adding more. */
  maxDeclaredUris: 500,
});

export interface DirectoryScanOptions {
  limits?: Limits;
  maxFiles?: number;
  maxTotalBytes?: number;
  maxFileBytes?: number;
  maxEntries?: number;
  maxDeclaredUris?: number;
  now?: () => Date;
}

/** How a `ui://` URI got its content. Reported so a reader can weigh it. */
export type ResolutionRoute =
  /** (a) a sibling file whose path tail matches the URI path */
  | 'sibling-file'
  /** (b) a string or heredoc literal in the same file that parses as HTML */
  | 'inline-literal'
  /** (c) a readFile / open / slurp call with a literal path argument */
  | 'literal-read-call';

/**
 * Does this MIME type name an MCP App resource?
 *
 * Compared on the essence — type/subtype plus the `profile` parameter — with
 * whitespace and case normalised, because `text/html; profile=mcp-app` and
 * `text/html;profile=mcp-app` are the same media type and a server chooses the
 * spacing. Charset and other parameters are ignored.
 */
export function isAppMime(mimeType: string): boolean {
  const normalised = mimeType.toLowerCase().replace(/\s+/g, '');
  return normalised.startsWith('text/html') && normalised.includes('profile=mcp-app');
}

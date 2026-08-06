/**
 * Capture files: record once, replay in CI.
 *
 * A capture is JSON someone else produced and committed, and CI scans it
 * unattended. Three things follow, and they are the whole design of this file:
 *
 * 1. **`contentHash` is always recomputed.** A hash carried in the capture is
 *    never trusted and never propagated. Otherwise a vendor hands you a capture
 *    whose hash is that of a clean resource, and the census entry and the
 *    disclosure email both cite a hash that never existed. A carried hash that
 *    disagrees with the recomputed one is reported as a diagnostic — that
 *    disagreement is a fact worth surfacing, not a thing to silently correct.
 *
 * 2. **`blob` is validated with `isStrictBase64` before it is decoded.**
 *    `Buffer.from(s, 'base64')` accepts the URL-safe alphabet, missing padding
 *    and interior garbage, so two distinct blob strings can decode to identical
 *    bytes and produce an identical hash. The one field the census keys on
 *    cannot be ambiguous.
 *
 * 3. **A capture can never carry a spawn command, an argv, an environment or a
 *    URL.** Unknown top-level keys are refused outright, and the execution-shaped
 *    ones are named explicitly so the refusal says why. Replay reads JSON. It
 *    does not start processes and it does not open sockets.
 *
 * The format retains `resources/list` entries with their `_meta.ui`,
 * `resources/read` results with theirs, `tools/list`, and the `initialize`
 * result. Six rules die without tools, PANE-SPEC-007 dies without capabilities,
 * and PANE-SPEC-010 is invisible unless BOTH `_meta.ui` sources survive
 * separately.
 */

import {
  openSync,
  fstatSync,
  readSync,
  closeSync,
  writeSync,
  fchmodSync,
  lstatSync,
  unlinkSync,
} from 'node:fs';

import type {
  ResourceSet,
  ScanDiagnostic,
  ScanError,
  ToolWithUIMeta,
  UIResource,
  Limits,
} from '../types.js';
import { DEFAULT_LIMITS } from '../limits.js';
import { isStrictBase64 } from '../safe/guard.js';
import { safe, errorSummary } from '../safe/untrusted.js';
import { extractUiMeta, extractToolUiMeta, resolveMeta } from '../parse/meta.js';
import { sha256Bytes, sha256Resource } from './hash.js';
import {
  CAPTURE_FORBIDDEN_KEYS,
  CAPTURE_FORMAT_VERSION,
  CAPTURE_TOP_LEVEL_KEYS,
  CaptureError,
  DEFAULT_MAX_CAPTURE_BYTES,
  SANITIZE_CAPS,
} from './types.js';
import type {
  CaptureContentItem,
  CaptureFile,
  CaptureInitializeResult,
  CaptureListedResource,
  CaptureLoadOptions,
  CaptureReadEntry,
  CaptureTool,
  WriteCaptureOptions,
} from './types.js';

const UI_EXTENSION = 'io.modelcontextprotocol/ui';

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/** Replay a capture file from disk. */
export function loadCapture(filePath: string, options: CaptureLoadOptions = {}): ResourceSet {
  const text = readCaptureText(filePath, options.maxCaptureBytes ?? DEFAULT_MAX_CAPTURE_BYTES);
  return parseCaptureText(text, options);
}

/** Replay a capture already in memory. */
export function parseCaptureText(text: string, options: CaptureLoadOptions = {}): ResourceSet {
  return replayCapture(validateCapture(parseJson(text)), options);
}

/**
 * Read the file with a ceiling applied on the descriptor.
 *
 * The size check is `fstat` on the open fd rather than a prior `stat`, for the
 * same reason `readContained` does it that way: the path can be replaced between
 * the two calls.
 */
function readCaptureText(filePath: string, maxBytes: number): string {
  let fd: number;
  try {
    fd = openSync(filePath, 'r');
  } catch (e) {
    throw new CaptureError('UNREADABLE', `cannot read capture file: ${errorSummary(e)}`);
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new CaptureError('UNREADABLE', 'capture path is not a regular file');
    if (st.size > maxBytes) {
      throw new CaptureError(
        'TOO_LARGE',
        `capture file is too large: ${st.size} bytes exceeds the ${maxBytes}-byte ceiling`,
      );
    }
    const buf = Buffer.allocUnsafe(st.size);
    let read = 0;
    while (read < st.size) {
      const n = readSync(fd, buf, read, st.size - read, read);
      if (n <= 0) break;
      read += n;
    }
    return buf.subarray(0, read).toString('utf8');
  } finally {
    try {
      closeSync(fd);
    } catch {
      /* already closed */
    }
  }
}

/** `JSON.parse`, without echoing the file contents into the error. */
function parseJson(text: string): unknown {
  const body = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  try {
    return JSON.parse(body) as unknown;
  } catch (e) {
    // Never String(error) — a JSON parse error quotes the offending region.
    throw new CaptureError('INVALID_JSON', `capture file is not valid JSON: ${errorSummary(e)}`);
  }
}

// ---------------------------------------------------------------------------
// Schema validation
// ---------------------------------------------------------------------------

/**
 * Structural validation. Throws `CaptureError`; it never half-accepts.
 *
 * A per-resource problem (a bad blob, an oversized body) is a diagnostic on the
 * ResourceSet. A structural problem means the file is not a capture at all, and
 * carrying on with it would be guessing.
 */
export function validateCapture(value: unknown): CaptureFile {
  const obj = asObject(value, 'capture');

  const present = Object.keys(obj);
  const forbidden = present.filter((k) => CAPTURE_FORBIDDEN_KEYS.includes(k));
  if (forbidden.length > 0) {
    throw new CaptureError(
      'FORBIDDEN_KEY',
      `capture carries execution-shaped key(s): ${forbidden.map(keyName).join(', ')}. ` +
        'A capture is replayed, never executed: it may not carry a command, argv, environment, config or URL.',
    );
  }
  const unknown = present.filter((k) => !CAPTURE_TOP_LEVEL_KEYS.includes(k));
  if (unknown.length > 0) {
    throw new CaptureError(
      'UNKNOWN_KEY',
      `capture carries unknown top-level key(s): ${unknown.map(keyName).join(', ')}`,
    );
  }

  const version = obj['panelintCapture'];
  if (version !== CAPTURE_FORMAT_VERSION) {
    throw new CaptureError(
      'UNSUPPORTED_VERSION',
      `unsupported capture format version: expected panelintCapture ${CAPTURE_FORMAT_VERSION}, got ${describe(version)}`,
    );
  }

  if (obj['capturedAt'] !== undefined && typeof obj['capturedAt'] !== 'string') {
    throw new CaptureError('INVALID_SHAPE', 'capturedAt must be a string when present');
  }

  if (obj['initialize'] === undefined) {
    throw new CaptureError(
      'INVALID_SHAPE',
      'capture omits initialize. Record the initialize result: PANE-SPEC-007 checks the declared extension mimeTypes and cannot run without server capabilities.',
    );
  }
  const initialize = asObject(obj['initialize'], 'initialize') as CaptureInitializeResult;

  const resourcesList = asArray(obj['resourcesList'], 'resourcesList').map((entry, i) => {
    const e = asObject(entry, `resourcesList[${i}]`);
    if (typeof e['uri'] !== 'string') {
      throw new CaptureError('INVALID_SHAPE', `resourcesList[${i}].uri must be a string`);
    }
    return e as unknown as CaptureListedResource;
  });

  const resourcesRead = asArray(obj['resourcesRead'], 'resourcesRead').map((entry, i) => {
    const e = asObject(entry, `resourcesRead[${i}]`);
    if (typeof e['uri'] !== 'string') {
      throw new CaptureError('INVALID_SHAPE', `resourcesRead[${i}].uri must be a string`);
    }
    const contents = asArray(e['contents'], `resourcesRead[${i}].contents`);
    contents.forEach((c, j) => asObject(c, `resourcesRead[${i}].contents[${j}]`));
    return e as unknown as CaptureReadEntry;
  });

  if (obj['toolsList'] === undefined) {
    throw new CaptureError(
      'INVALID_SHAPE',
      'capture omits toolsList. Record the tools/list result: six rules read tool `_meta.ui`, and an absent key is a recording bug rather than "this server has no tools". An empty array is valid.',
    );
  }
  const toolsList = asArray(obj['toolsList'], 'toolsList').map((entry, i) => {
    const e = asObject(entry, `toolsList[${i}]`);
    if (typeof e['name'] !== 'string') {
      throw new CaptureError('INVALID_SHAPE', `toolsList[${i}].name must be a string`);
    }
    return e as unknown as CaptureTool;
  });

  const out: CaptureFile = {
    panelintCapture: CAPTURE_FORMAT_VERSION,
    initialize,
    resourcesList,
    resourcesRead,
    toolsList,
  };
  if (typeof obj['capturedAt'] === 'string') out.capturedAt = obj['capturedAt'];
  return out;
}

function asObject(v: unknown, what: string): Record<string, unknown> {
  if (!v || typeof v !== 'object' || Array.isArray(v)) {
    throw new CaptureError('INVALID_SHAPE', `${what} must be a JSON object, got ${describe(v)}`);
  }
  return v as Record<string, unknown>;
}

function asArray(v: unknown, what: string): unknown[] {
  if (!Array.isArray(v)) {
    throw new CaptureError('INVALID_SHAPE', `${what} must be an array, got ${describe(v)}`);
  }
  return v;
}

function describe(v: unknown): string {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'an array';
  if (typeof v === 'object') return 'an object';
  if (typeof v === 'string') return `a string (${keyName(v)})`;
  return String(v);
}

/** A key or short scalar from the capture, escaped before it enters a message. */
function keyName(k: string): string {
  return safe(k, 64);
}

// ---------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------

export function replayCapture(capture: CaptureFile, options: CaptureLoadOptions = {}): ResourceSet {
  const limits: Limits = options.limits ?? DEFAULT_LIMITS;
  const now = options.now ?? (() => new Date());
  const diagnostics: ScanDiagnostic[] = [];
  const errors: ScanError[] = [];

  const listByUri = new Map<string, CaptureListedResource>();
  for (const entry of capture.resourcesList) {
    if (!listByUri.has(entry.uri)) listByUri.set(entry.uri, entry);
  }

  const resources: UIResource[] = [];
  const readSeen = new Set<string>();

  for (const entry of capture.resourcesRead) {
    if (!isUiUri(entry.uri)) continue;
    if (readSeen.has(entry.uri)) {
      diagnostics.push({
        code: 'PARSE_FAILED',
        resourceUri: safe(entry.uri, SANITIZE_CAPS.uri),
        message: 'duplicate resources/read entry in capture; the first was used',
      });
      continue;
    }
    readSeen.add(entry.uri);

    if (resources.length >= limits.maxTotalResources) {
      diagnostics.push({
        code: 'LIMIT_EXCEEDED',
        message: `maxTotalResources exceeded: the capture carries more than ${limits.maxTotalResources} ui:// resources`,
        detail: 'Analysis of this capture is incomplete; the remaining resources were not replayed.',
      });
      break;
    }

    const resource = toResource(entry, listByUri.get(entry.uri), limits, diagnostics);
    if (resource) resources.push(resource);
  }

  for (const [uri] of listByUri) {
    if (!isUiUri(uri) || readSeen.has(uri)) continue;
    diagnostics.push({
      code: 'UNRESOLVED_URI',
      resourceUri: safe(uri, SANITIZE_CAPS.uri),
      message: 'resource listed, no resources/read result recorded in this capture',
      detail: 'Re-record the capture so every listed ui:// resource carries its read result.',
    });
  }

  if (resources.length === 0 && listByUri.size === 0) {
    diagnostics.push({
      code: 'NO_RESOURCES_FOUND',
      message: 'the capture records no ui:// resources',
    });
  }

  const init = readInitialize(capture.initialize);
  const set: ResourceSet = {
    resources,
    tools: capture.toolsList.map(toTool),
    diagnostics,
    errors,
    scannedAt: now().toISOString(),
    source: 'capture',
  };
  if (init.serverName !== undefined) set.serverName = init.serverName;
  if (init.serverVersion !== undefined) set.serverVersion = init.serverVersion;
  if (init.protocolVersion !== undefined) set.protocolVersion = init.protocolVersion;
  set.declaresUiExtension = init.declaresUiExtension;
  if (init.declaredMimeTypes !== undefined) set.declaredMimeTypes = init.declaredMimeTypes;
  return set;
}

function isUiUri(uri: string): boolean {
  return uri.startsWith('ui://');
}

function toResource(
  entry: CaptureReadEntry,
  listed: CaptureListedResource | undefined,
  limits: Limits,
  diagnostics: ScanDiagnostic[],
): UIResource | null {
  const uri = safe(entry.uri, SANITIZE_CAPS.uri);
  const item = entry.contents.find(
    (c) => typeof (c as CaptureContentItem).text === 'string' || typeof (c as CaptureContentItem).blob === 'string',
  ) as CaptureContentItem | undefined;

  if (!item) {
    diagnostics.push({
      code: 'PARSE_FAILED',
      resourceUri: uri,
      message: 'resources/read result carries no text or blob content item',
    });
    return null;
  }

  const hasText = typeof item.text === 'string';
  const hasBlob = typeof item.blob === 'string';
  if (hasText && hasBlob) {
    // The hash is defined over `text` OR the decoded bytes of `blob`. A content
    // item carrying both leaves no defensible answer to "which bytes?".
    diagnostics.push({
      code: 'PARSE_FAILED',
      resourceUri: uri,
      message: 'content item carries both text and blob; the contentHash would be ambiguous',
    });
    return null;
  }

  let content: string;
  let contentHash: string;
  let byteLength: number;
  let fromBlob = false;

  if (hasBlob) {
    const blob = item.blob!;
    if (!isStrictBase64(blob)) {
      diagnostics.push({
        code: 'PARSE_FAILED',
        resourceUri: uri,
        message:
          'blob is not strict base64 (padded, standard alphabet, no whitespace); refusing to decode it',
        detail:
          'Buffer.from tolerates the URL-safe alphabet and missing padding, so two distinct blobs would hash identically.',
      });
      return null;
    }
    const bytes = Buffer.from(blob, 'base64');
    byteLength = bytes.length;
    if (byteLength > limits.maxResourceBytes) {
      diagnostics.push(overBudget(uri, byteLength, limits.maxResourceBytes));
      return null;
    }
    content = bytes.toString('utf8');
    contentHash = sha256Bytes(bytes);
    fromBlob = true;
  } else {
    content = item.text!;
    byteLength = Buffer.byteLength(content, 'utf8');
    if (byteLength > limits.maxResourceBytes) {
      diagnostics.push(overBudget(uri, byteLength, limits.maxResourceBytes));
      return null;
    }
    contentHash = sha256Resource({ text: content });
  }

  // A hash carried in the capture is never used. It is only compared, because a
  // disagreement means the capture and its contents no longer describe the same
  // bytes — which is exactly the substitution the recompute rule exists to catch.
  const carried = carriedHash(item);
  if (carried && carried.toLowerCase() !== contentHash) {
    diagnostics.push({
      code: 'PARSE_FAILED',
      resourceUri: uri,
      message:
        'the contentHash recorded in the capture does not match the hash of the content it carries; the recomputed hash is authoritative',
      detail: `recorded ${safe(carried, 80)}, recomputed ${contentHash}`,
    });
  }

  const metaFromList = extractUiMeta(listed?._meta);
  const metaFromRead = extractUiMeta(item._meta);
  const resolved = resolveMeta(metaFromList, metaFromRead);

  const resource: UIResource = {
    uri,
    mimeType: safe(item.mimeType ?? listed?.mimeType ?? '', SANITIZE_CAPS.mimeType),
    content,
    schemaErrors: [],
    contentHash,
    source: 'capture',
  };
  if (listed?.mimeType !== undefined) {
    resource.listedMimeType = safe(listed.mimeType, SANITIZE_CAPS.mimeType);
  }
  if (fromBlob) resource.fromBlob = true;
  if (metaFromList !== undefined) resource.metaFromList = metaFromList;
  if (metaFromRead !== undefined) resource.metaFromRead = metaFromRead;
  if (resolved !== null) resource.meta = resolved;
  return resource;
}

function carriedHash(item: CaptureContentItem): string | undefined {
  const raw = item as unknown as Record<string, unknown>;
  const v = raw['contentHash'] ?? raw['sha256'];
  return typeof v === 'string' ? v : undefined;
}

function overBudget(uri: string, observed: number, ceiling: number): ScanDiagnostic {
  return {
    code: 'LIMIT_EXCEEDED',
    resourceUri: uri,
    message: `maxResourceBytes exceeded: ${observed} > ${ceiling}`,
    detail: 'The resource was not analysed. Raise --max-resource-bytes if the input is trusted.',
  };
}

function toTool(tool: CaptureTool): ToolWithUIMeta {
  const out: ToolWithUIMeta = {
    name: safe(tool.name, SANITIZE_CAPS.name),
    schemaErrors: [],
  };
  if (typeof tool.description === 'string') {
    out.description = safe(tool.description, SANITIZE_CAPS.description);
  }
  if (tool.annotations && typeof tool.annotations === 'object' && !Array.isArray(tool.annotations)) {
    out.annotations = tool.annotations as ToolWithUIMeta['annotations'];
  }
  const meta = extractToolUiMeta(tool._meta);
  if (meta !== undefined) out.meta = meta;
  // The raw `_meta` is kept whole so the deprecated flat `ui/resourceUri` key
  // stays visible — the SDK dual-writes it, and PANE-SPEC-006/011 compares the
  // two. Normalising it away here would silently retire both rules.
  if (tool._meta && typeof tool._meta === 'object' && !Array.isArray(tool._meta)) {
    out.rawMeta = tool._meta;
  }
  return out;
}

interface InitializeFacts {
  serverName?: string;
  serverVersion?: string;
  protocolVersion?: string;
  declaresUiExtension: boolean;
  declaredMimeTypes?: string[];
}

/**
 * Read the facts PANE-SPEC-007 needs out of the initialize result.
 *
 * Capability negotiation puts the extension under `capabilities.extensions`
 * (SPEC-REFERENCE.md §2). `capabilities.experimental` is also accepted because
 * pre-Stable servers shipped it there, and reading both cannot cause a finding —
 * only the absence of both can.
 */
function readInitialize(init: CaptureInitializeResult): InitializeFacts {
  const facts: InitializeFacts = { declaresUiExtension: false };

  const name = init.serverInfo?.name;
  if (typeof name === 'string') facts.serverName = safe(name, SANITIZE_CAPS.name);
  const version = init.serverInfo?.version;
  if (typeof version === 'string') facts.serverVersion = safe(version, SANITIZE_CAPS.version);
  if (typeof init.protocolVersion === 'string') {
    facts.protocolVersion = safe(init.protocolVersion, SANITIZE_CAPS.version);
  }

  const caps = init.capabilities;
  if (!caps || typeof caps !== 'object') return facts;

  for (const bucketName of ['extensions', 'experimental'] as const) {
    const bucket = (caps as Record<string, unknown>)[bucketName];
    if (!bucket || typeof bucket !== 'object' || Array.isArray(bucket)) continue;
    const ext = (bucket as Record<string, unknown>)[UI_EXTENSION];
    if (ext === undefined) continue;
    facts.declaresUiExtension = true;
    if (ext && typeof ext === 'object' && !Array.isArray(ext)) {
      const mimeTypes = (ext as Record<string, unknown>)['mimeTypes'];
      if (Array.isArray(mimeTypes)) {
        facts.declaredMimeTypes = mimeTypes
          .filter((m): m is string => typeof m === 'string')
          .map((m) => safe(m, SANITIZE_CAPS.mimeType));
      }
    }
    break;
  }

  return facts;
}

// ---------------------------------------------------------------------------
// Writing — `panelint capture -o <file>`
// ---------------------------------------------------------------------------

export interface BuildCaptureInput {
  initialize: CaptureInitializeResult;
  resourcesList: CaptureListedResource[];
  resourcesRead: CaptureReadEntry[];
  toolsList: CaptureTool[];
  capturedAt?: string;
}

/** Build a capture and validate it before anyone can write it out. */
export function buildCaptureFile(input: BuildCaptureInput): CaptureFile {
  const candidate: Record<string, unknown> = {
    ...(input as unknown as Record<string, unknown>),
    panelintCapture: CAPTURE_FORMAT_VERSION,
  };
  if (candidate['capturedAt'] === undefined) candidate['capturedAt'] = new Date().toISOString();
  return validateCapture(candidate);
}

/**
 * Write a capture to disk.
 *
 * Opened `wx` at mode 0600. A hostile repository can pre-plant
 * `panelint.capture.json` as a symlink to `~/.zshrc` before CI runs, and `wx`
 * fails on a symlink rather than following it. `force` still refuses a symlink:
 * it means "replace the file I can see", not "follow whatever this points at".
 */
export function writeCapture(
  filePath: string,
  capture: CaptureFile,
  options: WriteCaptureOptions = {},
): void {
  const validated = validateCapture(capture as unknown);
  const json = JSON.stringify(validated, null, 2) + '\n';

  if (options.force) {
    let existing: ReturnType<typeof lstatSync> | null = null;
    try {
      existing = lstatSync(filePath);
    } catch {
      existing = null;
    }
    if (existing) {
      if (existing.isSymbolicLink()) {
        throw new CaptureError(
          'REFUSED',
          'refusing to write the capture: the destination is a symlink. Delete it and re-run if that is really what you meant.',
        );
      }
      if (!existing.isFile()) {
        throw new CaptureError('REFUSED', 'refusing to write the capture: the destination is not a regular file');
      }
      // Unlink rather than truncate, so the create below stays exclusive.
      try {
        unlinkSync(filePath);
      } catch (e) {
        throw new CaptureError('REFUSED', `cannot replace the destination: ${errorSummary(e)}`);
      }
    }
  }

  let fd: number;
  try {
    fd = openSync(filePath, 'wx', 0o600);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'EEXIST') {
      throw new CaptureError(
        'EXISTS',
        'the destination already exists; refusing to overwrite it without an explicit force flag',
      );
    }
    throw new CaptureError('UNREADABLE', `cannot create the capture file: ${errorSummary(e)}`);
  }

  try {
    // Explicit, so the process umask cannot widen the mode.
    fchmodSync(fd, 0o600);
    const buf = Buffer.from(json, 'utf8');
    let written = 0;
    while (written < buf.length) {
      written += writeSync(fd, buf, written, buf.length - written);
    }
  } finally {
    try {
      closeSync(fd);
    } catch {
      /* already closed */
    }
  }
}

/**
 * Rebuild a replayable capture from a completed live scan.
 *
 * `buildCaptureFile` takes raw protocol records; a live scan has already
 * folded those into a `ResourceSet`. This reconstructs the wire shapes from
 * what the set retains, which is everything a rule can read — crucially BOTH
 * `_meta.ui` sources, because a capture that collapses them makes
 * PANE-SPEC-010 unfalsifiable on replay.
 *
 * The reconstruction is faithful, not byte-exact: it records what the scanner
 * observed, not the literal JSON-RPC frames. Content is re-emitted as `text`,
 * so `contentHash` recomputes identically on replay (a `blob` and a `text`
 * resource with identical decoded bytes hash the same by definition).
 */
export function captureFromResourceSet(
  set: ResourceSet,
  capturedAt?: string,
): CaptureFile {
  const initialize: CaptureInitializeResult = {
    ...(set.protocolVersion ? { protocolVersion: set.protocolVersion } : {}),
    ...(set.serverName || set.serverVersion
      ? {
          serverInfo: {
            ...(set.serverName ? { name: set.serverName } : {}),
            ...(set.serverVersion ? { version: set.serverVersion } : {}),
          },
        }
      : {}),
    ...(set.declaresUiExtension
      ? {
          capabilities: {
            extensions: {
              'io.modelcontextprotocol/ui': {
                mimeTypes: set.declaredMimeTypes ?? [],
              },
            },
          },
        }
      : {}),
  };

  return buildCaptureFile({
    initialize,
    resourcesList: set.resources.map((r) => ({
      uri: r.uri,
      ...(r.listedMimeType ?? r.mimeType ? { mimeType: r.listedMimeType ?? r.mimeType } : {}),
      ...(r.metaFromList ? { _meta: { ui: r.metaFromList } } : {}),
    })),
    resourcesRead: set.resources.map((r) => ({
      uri: r.uri,
      contents: [
        {
          uri: r.uri,
          mimeType: r.mimeType,
          text: r.content,
          ...(r.metaFromRead ? { _meta: { ui: r.metaFromRead } } : {}),
        },
      ],
    })),
    toolsList: set.tools.map((t) => ({
      name: t.name,
      ...(t.description ? { description: t.description } : {}),
      ...(t.annotations ? { annotations: t.annotations } : {}),
      ...(t.rawMeta ? { _meta: t.rawMeta } : t.meta ? { _meta: { ui: t.meta } } : {}),
    })),
    ...(capturedAt ? { capturedAt } : {}),
  });
}

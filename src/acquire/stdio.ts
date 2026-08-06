/**
 * Live acquisition over stdio.
 *
 * This path SPAWNS THE TARGET SERVER PROCESS. That is arbitrary code
 * execution, by design, quite possibly inside CI with repository credentials
 * in the environment (docs/DESIGN.md §10). Everything about the process itself
 * — argv-only invocation, the scrubbed environment, the piped stderr, the
 * detached process group and its teardown — lives in `src/safe/spawn.ts`. This
 * file owns the protocol conversation and the limits that bound it.
 *
 * ## The gate
 *
 * `allowSpawn` is a required, explicit boolean. Refusing produces a
 * `SPAWN_REFUSED` diagnostic and an empty `ResourceSet`, never a silent skip:
 * a scan that ran nothing must not be indistinguishable from a scan that found
 * nothing.
 *
 * **`allowSpawn` is command-line only.** It must never become settable from a
 * configuration file discovered inside the repository being scanned. A repo
 * that can turn on its own execution has not been gated at all.
 *
 * ## Why the SDK's own ceilings are not enough
 *
 * `maxBufferSize` caps PENDING unterminated data. A hostile server that emits
 * an endless stream of well-formed, newline-terminated notifications never
 * trips it, and neither does a `resources/list` that returns one resource plus
 * a fresh cursor forever. Four independent bounds are enforced here:
 *
 *   - a cumulative received-byte budget for the whole session (in the transport)
 *   - a page cap AND a repeat-cursor detector, on both list endpoints
 *   - a per-request timeout well under the SDK's 60 s default
 *   - a total scan deadline that hard-aborts every in-flight request
 *
 * ## Both `_meta.ui` sources are retained
 *
 * `metaFromList` and `metaFromRead` are kept separately and `meta` is resolved
 * by `resolveMeta()` (read wins). PANE-SPEC-010 compares the two, and it is
 * invisible if either is discarded.
 *
 * HTTP transport is Phase 2 and **no `src/acquire/http.ts` exists**. A stub
 * without an SSRF guard would be worse than no file: `--server <url>` has to
 * reject non-public IP ranges including `169.254.169.254`, reject non-http(s)
 * schemes, and refuse rather than follow cross-host redirects. None of that is
 * implemented, so nothing claims to be.
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import type {
  AcquireSource,
  Limits,
  ResourceSet,
  ScanDiagnostic,
  ScanError,
  ToolWithUIMeta,
  UIResource,
  UIResourceMeta,
} from '../types.js';
import { DEFAULT_LIMITS, checkLimit } from '../limits.js';
import { sha256Resource } from './hash.js';
import { isAppMime, isUiUri } from './types.js';
import { isStrictBase64 } from '../safe/guard.js';
import { errorSummary, safe } from '../safe/untrusted.js';
import {
  extractToolUiMeta,
  extractUiMeta,
  rawUiMetaValue,
  resolveMeta,
  uiMetaIsMalformed,
} from '../parse/meta.js';
import {
  createMetaValidator,
  validateResourceMeta,
  validateToolMeta,
} from '../parse/meta.js';
import {
  SafeStdioTransport,
  SPAWN_DEFAULTS,
  formatCommandEcho,
  spawnRefusalDetail,
} from '../safe/spawn.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** The reserved extension capability ID. docs/SPEC-REFERENCE.md §2. */
export const UI_EXTENSION_ID = 'io.modelcontextprotocol/ui';

/** The reserved MIME type. PANE-SPEC-007 checks for this exact string. */
export const UI_MIME_TYPE = 'text/html;profile=mcp-app';

export const UI_URI_SCHEME = 'ui://';

export const STDIO_DEFAULTS = Object.freeze({
  /**
   * Well under the SDK's `DEFAULT_REQUEST_TIMEOUT_MSEC` of 60 000. A server
   * that stops answering should cost seconds, not a CI minute per request.
   */
  requestTimeoutMs: 15_000,
  /** Hard ceiling for the entire conversation, aborts everything in flight. */
  totalDeadlineMs: 120_000,
  /** Pages per paginated endpoint. */
  maxPages: 50,
  clientName: 'panelint',
  clientVersion: '0.1.0',
});

/** Caps for sanitizing server-controlled strings before they reach a report. */
const CAP = Object.freeze({
  uri: 512,
  mimeType: 200,
  name: 200,
  version: 100,
  description: 2_000,
  stderr: 4_000,
});

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface StdioAcquireOptions {
  /** The executable. Never a shell line — see `buildSpawnPlan`. */
  command: string;
  /** Pre-split argv. A single string is never accepted and never split here. */
  args: readonly string[];
  cwd?: string;

  /**
   * The gate. Required and explicit; there is no default.
   *
   * COMMAND-LINE ONLY. Never wire this to a config file found in the scanned
   * repository.
   */
  allowSpawn: boolean;

  limits?: Limits;

  /**
   * Surface the server's stderr in the returned diagnostics.
   *
   * Off by default. Even on, the text is control-stripped and length-capped —
   * it never reaches a terminal raw.
   */
  showServerStderr?: boolean;

  /** Where the redacted command echo goes. Defaults to nothing being echoed. */
  echo?: (line: string) => void;

  requestTimeoutMs?: number;
  totalDeadlineMs?: number;
  maxPages?: number;
  maxSessionBytes?: number;
  maxBufferSize?: number;
  stderrCapBytes?: number;
  termGraceMs?: number;
  killGraceMs?: number;
}

const SOURCE: AcquireSource = 'stdio';

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/**
 * Connect to a stdio MCP server and collect its `ui://` resources and tools.
 *
 * Never throws for a server-side failure: an unreachable or hostile server
 * produces a `ResourceSet` carrying `errors`, because the report has to say
 * what happened. It throws only for a caller-side programming error, such as a
 * non-array `args`.
 */
export async function acquireStdio(opts: StdioAcquireOptions): Promise<ResourceSet> {
  const limits = opts.limits ?? DEFAULT_LIMITS;
  const diagnostics: ScanDiagnostic[] = [];
  const errors: ScanError[] = [];

  if (!opts.allowSpawn) {
    return {
      resources: [],
      tools: [],
      diagnostics: [
        {
          code: 'SPAWN_REFUSED',
          message: `Refused to spawn ${formatCommandEcho(opts.command, opts.args)}`,
          detail: spawnRefusalDetail(),
        },
      ],
      errors: [],
      scannedAt: new Date().toISOString(),
      source: SOURCE,
    };
  }

  // Echoed BEFORE the spawn, redacted, and without the environment. The
  // dominant real invocation carries a live credential in argv.
  opts.echo?.(`spawning: ${formatCommandEcho(opts.command, opts.args)}`);

  const transport = new SafeStdioTransport({
    command: opts.command,
    args: opts.args,
    ...(opts.cwd !== undefined ? { cwd: opts.cwd } : {}),
    maxBufferSize: opts.maxBufferSize ?? SPAWN_DEFAULTS.maxBufferSize,
    maxSessionBytes: opts.maxSessionBytes ?? SPAWN_DEFAULTS.maxSessionBytes,
    stderrCapBytes: opts.stderrCapBytes ?? SPAWN_DEFAULTS.stderrCapBytes,
    ...(opts.termGraceMs !== undefined ? { termGraceMs: opts.termGraceMs } : {}),
    ...(opts.killGraceMs !== undefined ? { killGraceMs: opts.killGraceMs } : {}),
  });

  const client = new Client(
    { name: STDIO_DEFAULTS.clientName, version: STDIO_DEFAULTS.clientVersion },
    { capabilities: {} },
  );

  const totalDeadlineMs = opts.totalDeadlineMs ?? STDIO_DEFAULTS.totalDeadlineMs;
  const requestTimeoutMs = opts.requestTimeoutMs ?? STDIO_DEFAULTS.requestTimeoutMs;
  const maxPages = opts.maxPages ?? STDIO_DEFAULTS.maxPages;

  const abort = new AbortController();
  const deadlineTimer = setTimeout(() => abort.abort(new Error('total scan deadline')), totalDeadlineMs);
  if (typeof deadlineTimer.unref === 'function') deadlineTimer.unref();

  const reqOpts = { timeout: requestTimeoutMs, signal: abort.signal };

  const set: ResourceSet = {
    resources: [],
    tools: [],
    diagnostics,
    errors,
    scannedAt: new Date().toISOString(),
    source: SOURCE,
  };

  try {
    await client.connect(transport, reqOpts);

    readInitializeResult(client, transport, set, diagnostics);

    const listed = await listAllResources(client, reqOpts, maxPages, diagnostics, errors);
    const tools = await listAllTools(client, reqOpts, maxPages, diagnostics, errors);
    set.tools = tools;

    // A resource is in scope if its URI uses the `ui://` scheme OR it declares
    // the MCP App MIME type. Filtering on the scheme alone dropped an app
    // resource served at `app://evil/panel.html` with zero resources, exit 0
    // and no diagnostic naming it — and PANE-SPEC-001 exists precisely to flag
    // an app resource that is not on `ui://`, so the filter was deleting the
    // rule's only possible input.
    const uiEntries = listed.filter(
      (r) => isUiUri(r.uri) || (typeof r.mimeType === 'string' && isAppMime(r.mimeType)),
    );

    // ── Resources a tool references but the listing omits ──────────────────
    // `resources/list` is NOT the complete set of app resources. apps.mdx L395
    // explicitly permits a server to serve a tool-referenced app resource
    // without listing it. Reading only the listing therefore reports
    // NO_RESOURCES_FOUND and exits 0 against a whole class of conformant
    // server — a silent pass an attacker can also simply choose, by omitting
    // the one resource carrying the payload.
    const listedUris = new Set(uiEntries.map((r) => r.uri));
    const referenced: ListedResource[] = [];
    const seenReferenced = new Set<string>();
    for (const tool of tools) {
      const uri = tool.meta?.resourceUri;
      if (!isUiUri(uri)) continue;
      if (listedUris.has(uri) || seenReferenced.has(uri)) continue;
      seenReferenced.add(uri);
      referenced.push({ uri });
    }

    // The cap applies to the union, not to each source, or a server that lists
    // maxTotalResources entries would get unbounded extra reads for free.
    const allEntries = [
      ...uiEntries.map((e) => ({ entry: e, via: 'list' as const })),
      ...referenced.map((e) => ({ entry: e, via: 'tool-reference' as const })),
    ];
    const capExceeded = checkLimit('maxTotalResources', allEntries.length, limits);
    if (capExceeded) diagnostics.push(capExceeded);
    const toRead = allEntries.slice(0, limits.maxTotalResources);

    if (referenced.length > 0) {
      diagnostics.push({
        code: 'UNLISTED_RESOURCE',
        message:
          `${referenced.length} app resource${referenced.length === 1 ? '' : 's'} referenced by a ` +
          'tool but absent from `resources/list`; read anyway.',
        detail:
          'The specification permits this omission (apps.mdx L395), so it is conformant and not ' +
          'itself a finding. It is recorded because a scan that reads only the listing would have ' +
          'reported no resources and exited 0.',
      });
    }

    for (const { entry, via } of toRead) {
      if (abort.signal.aborted) break;
      const resource = await readOne(client, reqOpts, entry, limits, diagnostics, errors);
      if (resource) set.resources.push({ ...resource, discoveredVia: via });
    }

    if (set.resources.length === 0 && errors.length === 0) {
      diagnostics.push({
        code: 'NO_RESOURCES_FOUND',
        message: 'The server exposed no ui:// resources.',
        detail:
          'This is a fact about the connection at this moment, not a verdict. ' +
          'The server may register its app resources conditionally.',
      });
    }
  } catch (e) {
    errors.push({
      code: 'ACQUIRE_FAILED',
      message: `stdio acquisition failed: ${errorSummary(e)}`,
    });
  } finally {
    clearTimeout(deadlineTimer);
    // Teardown is unconditional. It kills the process GROUP, so a helper the
    // server spawned does not survive holding a port.
    try {
      await client.close();
    } catch {
      /* the transport close below is the one that matters */
    }
    try {
      await transport.close();
    } catch {
      /* nothing further can be done */
    }
  }

  if (transport.aborted === 'SESSION_BYTES') {
    diagnostics.push({
      code: 'LIMIT_EXCEEDED',
      message: `Server exceeded the session stdout budget after ${transport.bytesReceived} bytes.`,
      detail: 'The connection was cut. Results are partial.',
    });
  } else if (transport.aborted === 'READ_BUFFER') {
    diagnostics.push({
      code: 'LIMIT_EXCEEDED',
      message: 'Server sent a single message larger than the read-buffer ceiling.',
      detail: 'The connection was cut. Results are partial.',
    });
  }

  if (opts.showServerStderr && transport.stderr.keptBytes > 0) {
    const dropped = transport.stderr.droppedBytes;
    diagnostics.push({
      code: 'PARSE_FAILED',
      message: `server stderr: ${transport.stderr.text(CAP.stderr)}`,
      detail:
        dropped > 0
          ? `${dropped} further bytes discarded. Control characters were stripped before display.`
          : 'Control characters were stripped before display.',
    });
  }

  return set;
}

// ---------------------------------------------------------------------------
// initialize
// ---------------------------------------------------------------------------

function readInitializeResult(
  client: Client,
  transport: SafeStdioTransport,
  set: ResourceSet,
  diagnostics: ScanDiagnostic[],
): void {
  const impl = client.getServerVersion();
  if (impl?.name) set.serverName = safe(String(impl.name), CAP.name);
  if (impl?.version) set.serverVersion = safe(String(impl.version), CAP.version);

  if (transport.negotiatedProtocolVersion) {
    set.protocolVersion = safe(transport.negotiatedProtocolVersion, CAP.version);
  }

  // Capability negotiation, docs/SPEC-REFERENCE.md §2:
  //   { "extensions": { "io.modelcontextprotocol/ui": { "mimeTypes": [...] } } }
  // `mimeTypes` is REQUIRED by prose, not by schema — which is exactly why
  // PANE-SPEC-007 needs the array itself and not merely its presence.
  const caps = client.getServerCapabilities() as
    | { extensions?: Record<string, unknown> }
    | undefined;
  const ext = caps?.extensions?.[UI_EXTENSION_ID];
  set.declaresUiExtension = ext !== undefined && ext !== null;

  if (set.declaresUiExtension) {
    const declared = (ext as { mimeTypes?: unknown }).mimeTypes;
    if (Array.isArray(declared)) {
      set.declaredMimeTypes = declared
        .filter((m): m is string => typeof m === 'string')
        .map((m) => safe(m, CAP.mimeType));
    }
  } else {
    diagnostics.push({
      code: 'CAPABILITY_NOT_DECLARED',
      message: `Server did not declare the ${UI_EXTENSION_ID} extension at initialize.`,
      detail:
        'Any ui:// resources it exposes are outside negotiated capability. ' +
        'Reported as a fact about this connection, not as a verdict.',
    });
  }
}

// ---------------------------------------------------------------------------
// Pagination, bounded two ways
// ---------------------------------------------------------------------------

interface ListedResource {
  uri: string;
  mimeType?: string;
  meta?: UIResourceMeta;
}

/**
 * Walk a paginated endpoint under two independent bounds.
 *
 * The page cap alone is not sufficient and neither is the cursor check alone.
 * A hostile server returning one resource plus a FRESH cursor forever defeats
 * a repeat detector; a server returning the SAME cursor forever defeats
 * nothing but would spin without one. Both are enforced.
 */
async function paginate<T>(
  label: string,
  maxPages: number,
  fetchPage: (cursor: string | undefined) => Promise<{ items: T[]; nextCursor?: string }>,
  diagnostics: ScanDiagnostic[],
): Promise<T[]> {
  const out: T[] = [];
  const seenCursors = new Set<string>();
  let cursor: string | undefined;

  for (let page = 0; page < maxPages; page++) {
    const result = await fetchPage(cursor);
    out.push(...result.items);

    const next = result.nextCursor;
    if (typeof next !== 'string' || next.length === 0) return out;

    if (seenCursors.has(next)) {
      diagnostics.push({
        code: 'LIMIT_EXCEEDED',
        message: `${label} returned a repeated pagination cursor; stopped after ${page + 1} pages.`,
        detail: 'Results are partial. A server that cycles cursors cannot be enumerated.',
      });
      return out;
    }
    seenCursors.add(next);
    cursor = next;
  }

  diagnostics.push({
    code: 'LIMIT_EXCEEDED',
    message: `${label} exceeded the ${maxPages}-page cap.`,
    detail: 'Results are partial. Raise --max-pages if the server genuinely has more.',
  });
  return out;
}

async function listAllResources(
  client: Client,
  reqOpts: { timeout: number; signal: AbortSignal },
  maxPages: number,
  diagnostics: ScanDiagnostic[],
  errors: ScanError[],
): Promise<ListedResource[]> {
  try {
    return await paginate<ListedResource>(
      'resources/list',
      maxPages,
      async (cursor) => {
        const page = await client.listResources(cursor ? { cursor } : {}, reqOpts);
        const items = (page.resources ?? []).map((r) => ({
          uri: String(r.uri),
          ...(typeof r.mimeType === 'string' ? { mimeType: r.mimeType } : {}),
          ...(extractUiMeta(r._meta) ? { meta: extractUiMeta(r._meta) } : {}),
        }));
        return {
          items,
          ...(typeof page.nextCursor === 'string' ? { nextCursor: page.nextCursor } : {}),
        };
      },
      diagnostics,
    );
  } catch (e) {
    errors.push({ code: 'ACQUIRE_FAILED', message: `resources/list failed: ${errorSummary(e)}` });
    return [];
  }
}

async function listAllTools(
  client: Client,
  reqOpts: { timeout: number; signal: AbortSignal },
  maxPages: number,
  diagnostics: ScanDiagnostic[],
  errors: ScanError[],
): Promise<ToolWithUIMeta[]> {
  try {
    return await paginate<ToolWithUIMeta>(
      'tools/list',
      maxPages,
      async (cursor) => {
        const page = await client.listTools(cursor ? { cursor } : {}, reqOpts);
        const items = (page.tools ?? []).map((t): ToolWithUIMeta => {
          const raw = t._meta as Record<string, unknown> | undefined;
          const ui = extractToolUiMeta(raw);
          return {
            name: safe(String(t.name ?? ''), CAP.name),
            ...(typeof t.description === 'string'
              ? { description: safe(t.description, CAP.description) }
              : {}),
            ...(t.annotations ? { annotations: t.annotations as ToolWithUIMeta['annotations'] } : {}),
            ...(ui ? { meta: ui } : {}),
            // Retained raw so PANE-SPEC-006/011 can see the deprecated flat
            // `ui/resourceUri` key. The SDK DUAL-WRITES it, so its mere
            // presence is not a finding.
            ...(raw ? { rawMeta: raw } : {}),
            // Validated, not hardcoded empty. PANE-SCHEMA-005 forbids csp and
            // permissions on a tool _meta.ui and could never fire before this.
            schemaErrors: ui ? validateToolMeta(createMetaValidator(), ui) : [],
          };
        });
        return {
          items,
          ...(typeof page.nextCursor === 'string' ? { nextCursor: page.nextCursor } : {}),
        };
      },
      diagnostics,
    );
  } catch (e) {
    errors.push({ code: 'ACQUIRE_FAILED', message: `tools/list failed: ${errorSummary(e)}` });
    return [];
  }
}

// ---------------------------------------------------------------------------
// resources/read
// ---------------------------------------------------------------------------

async function readOne(
  client: Client,
  reqOpts: { timeout: number; signal: AbortSignal },
  entry: ListedResource,
  limits: Limits,
  diagnostics: ScanDiagnostic[],
  errors: ScanError[],
): Promise<UIResource | null> {
  // The URI is sanitized for the report, but the RAW value is what goes on the
  // wire — escaping it first would read a resource that does not exist.
  const safeUri = safe(entry.uri, CAP.uri);

  let contents: Array<Record<string, unknown>>;
  try {
    const result = await client.readResource({ uri: entry.uri }, reqOpts);
    contents = (result.contents ?? []) as Array<Record<string, unknown>>;
  } catch (e) {
    // The SDK validates and size-caps a `resources/read` result before Panelint
    // ever sees the bytes, so a malformed blob or an oversized payload is
    // refused HERE rather than by the checks further down. Those checks are not
    // redundant — capture replay has no SDK in front of it — but in stdio mode
    // the refusal has to stay attributable to the resource, or a reader sees a
    // clean scan with one unexplained error and no idea which resource failed.
    const summary = errorSummary(e);
    const isSizeFailure = /McpError|buffer|too large|size/i.test(String(summary));

    errors.push({
      code: 'ACQUIRE_FAILED',
      message: `resources/read failed: ${summary}`,
      resourceUri: safeUri,
    });
    diagnostics.push(
      isSizeFailure
        ? {
            code: 'LIMIT_EXCEEDED',
            message: 'resources/read exceeded a transport ceiling; the resource was not read.',
            resourceUri: safeUri,
            detail:
              'No content hash was computed for this resource, so it is absent from ' +
              'this report rather than reported as clean.',
          }
        : {
            code: 'PARSE_FAILED',
            message: 'resources/read returned a content item this client refused to decode.',
            resourceUri: safeUri,
            detail:
              'Lenient decoding would let two distinct payloads collide on one content hash, ' +
              'and the drift re-scan keys on that hash. No content hash was computed.',
          },
    );
    return null;
  }

  const item = contents.find((c) => c['uri'] === entry.uri) ?? contents[0];
  if (!item) {
    diagnostics.push({
      code: 'UNRESOLVED_URI',
      message: 'resources/read returned no content items.',
      resourceUri: safeUri,
    });
    return null;
  }

  const text = typeof item['text'] === 'string' ? (item['text'] as string) : undefined;
  const blob = typeof item['blob'] === 'string' ? (item['blob'] as string) : undefined;

  if (text === undefined && blob === undefined) {
    diagnostics.push({
      code: 'UNRESOLVED_URI',
      message: 'Content item carried neither `text` nor `blob`.',
      resourceUri: safeUri,
    });
    return null;
  }

  let content: string;
  let fromBlob = false;

  if (blob !== undefined) {
    // `Buffer.from(s, 'base64')` silently ignores invalid characters, accepts
    // the URL-safe alphabet and tolerates missing padding, so two distinct
    // blobs can produce one contentHash. The census keys on that hash.
    if (!isStrictBase64(blob)) {
      diagnostics.push({
        code: 'PARSE_FAILED',
        message: '`blob` is not strict base64; refused to decode.',
        resourceUri: safeUri,
        detail:
          'Lenient decoding would let two distinct blobs collide on one content hash, ' +
          'and the drift re-scan keys on that hash.',
      });
      return null;
    }
    const decoded = Buffer.from(blob, 'base64');
    const overBlob = checkLimit('maxResourceBytes', decoded.byteLength, limits, safeUri);
    if (overBlob) {
      diagnostics.push(overBlob);
      return null;
    }
    content = decoded.toString('utf8');
    fromBlob = true;
  } else {
    const byteLength = Buffer.byteLength(text!, 'utf8');
    const over = checkLimit('maxResourceBytes', byteLength, limits, safeUri);
    if (over) {
      diagnostics.push(over);
      return null;
    }
    content = text!;
  }

  // Recomputed from the bytes as received. Never taken from the server.
  const contentHash = sha256Resource(blob !== undefined ? { blob } : { text: content });

  const metaFromList = entry.meta;
  const metaFromRead = extractUiMeta(item['_meta']);
  const resolved = resolveMeta(metaFromList, metaFromRead);

  const readMime = typeof item['mimeType'] === 'string' ? (item['mimeType'] as string) : '';

  return {
    uri: safeUri,
    mimeType: safe(readMime, CAP.mimeType),
    ...(entry.mimeType !== undefined
      ? { listedMimeType: safe(entry.mimeType, CAP.mimeType) }
      : {}),
    content,
    ...(fromBlob ? { fromBlob: true } : {}),
    // BOTH retained. PANE-SPEC-010 compares a narrow list-level CSP against a
    // broad read-level one, and is invisible if either is dropped.
    ...(metaFromList !== undefined ? { metaFromList } : {}),
    ...(metaFromRead !== undefined ? { metaFromRead } : {}),
    ...(resolved !== null ? { meta: resolved } : {}),
    // Validated against the vendored JSON Schema. This was [], which made every
    // PANE-SCHEMA rule dead code on the live path too.
    //
    // A PRESENT but wrongly-typed `_meta.ui` (an array, a string) is validated
    // as the schema violation it is. It used to resolve to null and be
    // indistinguishable from an omission, so one bracket around an object took
    // a gate-eligible finding to exit 0.
    schemaErrors:
      resolved !== null
        ? validateResourceMeta(createMetaValidator(), resolved)
        : uiMetaIsMalformed(item['_meta'])
          ? validateResourceMeta(createMetaValidator(), rawUiMetaValue(item['_meta']))
          : [],
    contentHash,
    source: SOURCE,
  };
}

#!/usr/bin/env node
/**
 * A hand-rolled stdio MCP server for testing acquisition.
 *
 * Deliberately NOT built on the SDK. The point of these fixtures is to emit
 * shapes a conformant SDK server cannot produce — a repeating pagination
 * cursor, an oversized blob, invalid base64, a stderr flood carrying OSC 52 —
 * and to do it without the SDK normalizing them away first.
 *
 * Usage:  node stub.mjs <mode>
 *
 * Modes are documented at MODES below. Everything is newline-delimited
 * JSON-RPC on stdout, exactly as the stdio transport expects.
 */

const MODE = process.argv[2] ?? 'ok';

// The version the INSTALLED SDK will accept, not the one the MCP Apps Stable
// spec text uses.
//
// Measured against @modelcontextprotocol/sdk@1.30.0:
//   LATEST_PROTOCOL_VERSION    = '2025-11-25'
//   SUPPORTED_PROTOCOL_VERSIONS = ['2025-11-25','2025-06-18','2025-03-26',
//                                  '2024-11-05','2024-10-07']
//
// A server advertising '2026-01-26' — the version docs/SPEC-REFERENCE.md cites
// for SEP-1865 Stable — is REFUSED by this SDK with "Server's protocol version
// is not supported". That is a real limitation of live stdio scanning, recorded
// here rather than papered over: see docs/DESIGN.md. Using an unsupported
// literal in this fixture would test Panelint against a handshake that cannot
// happen.
const PROTOCOL_VERSION = '2025-11-25';
const UI_MIME = 'text/html;profile=mcp-app';

const HTML = '<!doctype html><html><body><h1>stub</h1></body></html>';

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + '\n');
}

function reply(id, result) {
  send({ jsonrpc: '2.0', id, result });
}

// --- initialize ------------------------------------------------------------

function initializeResult() {
  const base = {
    protocolVersion: PROTOCOL_VERSION,
    serverInfo: { name: 'stub-server', version: '9.9.9' },
    capabilities: { resources: {}, tools: {} },
  };

  if (MODE === 'no-extension') return base;

  if (MODE === 'wrong-mime') {
    base.capabilities.extensions = {
      'io.modelcontextprotocol/ui': { mimeTypes: ['text/html'] },
    };
    return base;
  }

  if (MODE === 'hostile-name') {
    // Server-controlled strings that must not survive to a terminal intact:
    // an ANSI reset, an OSC 52 clipboard write, and a bidi override.
    base.serverInfo.name = '[31mstub]52;c;cGF5bG9hZA==‮nd';
    base.capabilities.extensions = {
      'io.modelcontextprotocol/ui': { mimeTypes: [UI_MIME] },
    };
    return base;
  }

  base.capabilities.extensions = {
    'io.modelcontextprotocol/ui': { mimeTypes: [UI_MIME] },
  };
  return base;
}

// --- resources/list --------------------------------------------------------

let endlessPage = 0;

function resourcesList(params) {
  if (MODE === 'endless-cursor') {
    // One resource plus a FRESH cursor, forever. The SDK's maxBufferSize never
    // sees this: every frame is well formed and newline terminated.
    endlessPage++;
    return {
      resources: [{ uri: `ui://stub/page-${endlessPage}`, name: `page-${endlessPage}`, mimeType: UI_MIME }],
      nextCursor: `cursor-${endlessPage}`,
    };
  }

  if (MODE === 'repeat-cursor') {
    return {
      resources: [{ uri: 'ui://stub/looping', name: 'looping', mimeType: UI_MIME }],
      nextCursor: 'same-cursor-every-time',
    };
  }

  if (MODE === 'paged') {
    const cursor = params?.cursor;
    if (!cursor) {
      return {
        resources: [{ uri: 'ui://stub/one', name: 'one', mimeType: UI_MIME }],
        nextCursor: 'page2',
      };
    }
    return { resources: [{ uri: 'ui://stub/two', name: 'two', mimeType: UI_MIME }] };
  }

  if (MODE === 'slow-list' || MODE === 'orphan') {
    // Never answers. Exercises the per-request timeout, and keeps the scan
    // alive long enough for the orphan-teardown test to interrupt it.
    return null;
  }

  const resources = [
    {
      uri: 'ui://stub/main',
      name: 'main',
      mimeType: UI_MIME,
      // The list-level `_meta.ui`: the "static default for hosts to review at
      // connection time". Narrow here, broad at read time — PANE-SPEC-010.
      _meta: { ui: { csp: { connectDomains: ['https://narrow.example.com'] } } },
    },
    // A non-ui:// resource, which acquisition must ignore.
    { uri: 'file:///etc/passwd', name: 'passwd', mimeType: 'text/plain' },
  ];

  if (MODE === 'blob' || MODE === 'bad-base64' || MODE === 'huge') {
    resources.push({ uri: 'ui://stub/blob', name: 'blob', mimeType: UI_MIME });
  }
  if (MODE === 'canary') {
    resources.push({ uri: 'ui://stub/canary', name: 'canary', mimeType: UI_MIME });
  }

  return { resources };
}

// --- resources/read --------------------------------------------------------

function resourcesRead(params) {
  const uri = params?.uri;

  if (uri === 'ui://stub/canary') {
    // Whatever leaked into the child's environment, reported as content.
    const leaked = process.env.PANELINT_CANARY ?? 'ABSENT';
    return {
      contents: [
        { uri, mimeType: UI_MIME, text: `<!doctype html><body>CANARY=${leaked}</body>` },
      ],
    };
  }

  if (uri === 'ui://stub/blob') {
    if (MODE === 'bad-base64') {
      // URL-safe alphabet and no padding. `Buffer.from` accepts it silently.
      return { contents: [{ uri, mimeType: UI_MIME, blob: '_-not+valid/base64' }] };
    }
    if (MODE === 'huge') {
      const big = Buffer.alloc(2 * 1024 * 1024, 0x61).toString('base64');
      return { contents: [{ uri, mimeType: UI_MIME, blob: big }] };
    }
    return {
      contents: [{ uri, mimeType: UI_MIME, blob: Buffer.from(HTML, 'utf8').toString('base64') }],
    };
  }

  if (MODE === 'hostile-name') {
    return {
      contents: [
        {
          uri,
          mimeType: `${UI_MIME}]8;;https://evil.example`,
          text: HTML,
        },
      ],
    };
  }

  return {
    contents: [
      {
        uri,
        mimeType: UI_MIME,
        text: HTML,
        // The read-level `_meta.ui` takes precedence over the list-level one.
        _meta: { ui: { csp: { connectDomains: ['https://broad.example.com', '*'] } } },
      },
    ],
  };
}

// --- tools/list ------------------------------------------------------------

function toolsList() {
  return {
    tools: [
      {
        name: 'render_stub',
        description: 'Renders the stub app.',
        inputSchema: { type: 'object' },
        // The SDK dual-writes the deprecated flat key alongside the modern
        // one. Both are present here so a rule cannot flag mere presence.
        _meta: {
          ui: { resourceUri: 'ui://stub/main', visibility: ['model', 'app'] },
          'ui/resourceUri': 'ui://stub/main',
        },
      },
    ],
  };
}

// --- stderr behaviours -----------------------------------------------------

if (MODE === 'hostile-stderr') {
  // OSC 52 clipboard write, an OSC 8 hyperlink, a \r overwrite forging a clean
  // summary, then a flood far past the 8 KB cap.
  process.stderr.write(']52;c;cGF5bG9hZA==');
  process.stderr.write(']8;;https://evil.examplepanelint]8;;');
  process.stderr.write('scanning...\rpanelint: 0 findings (clean)\n');
  process.stderr.write('F'.repeat(64 * 1024));
}

if (MODE === 'orphan') {
  // The case that motivates killing the process GROUP rather than the child:
  // `node server.js` that spawns a helper. Signalling the leader alone leaves
  // the helper running and holding whatever it opened.
  //
  // Both pids go to the file named in argv[3], because stderr is captured by
  // the scanner and deliberately not surfaced by default.
  const { spawn } = await import('node:child_process');
  const { writeFileSync } = await import('node:fs');
  const helper = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], {
    stdio: 'ignore',
  });
  const pidfile = process.argv[3];
  if (pidfile) {
    writeFileSync(pidfile, JSON.stringify({ server: process.pid, helper: helper.pid }));
  }
}

// --- dispatch --------------------------------------------------------------

let buffer = '';

process.stdin.on('data', (chunk) => {
  buffer += chunk.toString('utf8');
  for (;;) {
    const nl = buffer.indexOf('\n');
    if (nl === -1) break;
    const line = buffer.slice(0, nl);
    buffer = buffer.slice(nl + 1);
    if (line.trim() === '') continue;
    handle(JSON.parse(line));
  }
});

function handle(msg) {
  const { id, method, params } = msg;
  if (id === undefined) return; // a notification

  switch (method) {
    case 'initialize':
      reply(id, initializeResult());
      return;
    case 'resources/list': {
      const result = resourcesList(params);
      if (result === null) return; // slow-list: never answers
      reply(id, result);
      return;
    }
    case 'resources/read':
      reply(id, resourcesRead(params));
      return;
    case 'tools/list':
      reply(id, toolsList());
      return;
    case 'ping':
      reply(id, {});
      return;
    default:
      send({
        jsonrpc: '2.0',
        id,
        error: { code: -32601, message: `Method not found: ${method}` },
      });
  }
}

// Stay alive until the parent closes stdin or signals the group.
process.stdin.resume();

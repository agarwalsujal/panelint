# MCP Apps — Verified Specification Reference

**Purpose.** Every fact a scanner rule depends on, verified against primary sources, so no rule is
ever built on a guessed field name. If a rule cites a requirement, that requirement is quoted here.

**Verified:** 2026-08-04, by direct fetch of spec and schema files from the source repository —
not from blog summaries. Re-verified 2026-08-04 against `src/generated/schema.json` decoded and
inspected field-by-field; corrections from that pass are marked **[v2]** below.

> ### ⚠ The vendored schema is not the Stable spec's schema
> `src/generated/schema.json` is generated from the SDK's **current `src/`**, which tracks `main`.
> It is *not* a frozen artifact of `specification/2026-01-26/`. Confirmed: the generated schema
> contains `McpUiAppCapabilities.tools` ("App exposes MCP-style tools that the host can call") —
> the app-provided-tools feature that §7 records as **draft, unratified**.
>
> **Consequence for rule design.** Validating a server against this file conflates Stable and draft.
> A server that is perfectly conformant to Stable could be flagged, and a draft-only construct
> could be silently accepted. The vendored copy must be pinned to a commit SHA, and every
> `PANE-SCHEMA` rule must assert against fields verified present in the **2026-01-26** spec text,
> not merely present in the generated schema. See [DESIGN.md](DESIGN.md) §3.2.

**Primary sources**
- `modelcontextprotocol/ext-apps` → `specification/2026-01-26/apps.mdx` — Status: **Stable (2026-01-26)**
- `modelcontextprotocol/ext-apps` → `specification/draft/apps.mdx` — draft, **not ratified**
- `modelcontextprotocol/ext-apps` → `src/generated/schema.json` — generated JSON Schema, package `1.7.5`
- `modelcontextprotocol/ext-apps` → `src/message-transport.ts`, `src/app-bridge.ts`
- `modelcontextprotocol/ext-apps` → `tests/e2e/security.spec.ts` — the project's own security tests
- `modelcontextprotocol/modelcontextprotocol` → `schema/2026-07-28/schema.ts` — `LATEST_PROTOCOL_VERSION = "2026-07-28"`
- SEP-1865 — merged **2026-01-28**, Track: Extensions, Status: Final

> **Timeline correction.** MCP Apps did **not** ship with the 2026-07-28 spec rewrite. SEP-1865
> reached Final and merged **2026-01-28**. The July rewrite formalized the extensions framework
> that Apps rides on. The feature has had a six-month adoption runway, not a one-week one.

---

## 1. Exact identifiers

| Item | Exact string |
|---|---|
| Extension capability ID | `io.modelcontextprotocol/ui` |
| URI scheme | `ui://` |
| MIME type | `text/html;profile=mcp-app` |
| Tool → resource link | `_meta.ui.resourceUri` |
| **Deprecated** flat form | `_meta["ui/resourceUri"]` — *"Will be removed before GA"* |
| Resource metadata | `_meta.ui` (type `UIResourceMeta`) |
| Lifecycle handshake | `ui/initialize` → `ui/notifications/initialized` |
| Sandbox proxy messages | `ui/notifications/sandbox-proxy-ready`, `ui/notifications/sandbox-resource-ready` |

Reservations, verbatim:
> - The resource prefix `ui://` will be reserved for MCP Apps
> - The label `io.modelcontextprotocol/ui` is reserved

> **[v2] On matching the MIME type.** The literal `text/html;profile=mcp-app` — no space after the
> semicolon — is the only form appearing anywhere in `schema.json`. But RFC 9110 §8.3 makes media-type
> parameters whitespace-tolerant and the parameter *name* case-insensitive, so
> `text/html; profile=mcp-app` is a semantically identical declaration that a byte-for-byte
> comparison would reject.
>
> `PANE-SPEC-002` must therefore **normalize before comparing** (trim parameter whitespace,
> lowercase the type and parameter name, preserve the parameter *value* case) and report a
> *separate, lower-severity* finding for a non-canonical-but-equivalent spelling. Flagging
> `text/html; profile=mcp-app` as a spec violation would be a false positive of exactly the kind
> goal G2 forbids.

---

## 2. Resource model

**Resource declaration** (`resources/list`):
```json
{
  "uri": "ui://weather-server/dashboard-template",
  "name": "weather_dashboard",
  "description": "Interactive weather dashboard view",
  "mimeType": "text/html;profile=mcp-app"
}
```

**Resource content** (`resources/read`):
```json
{
  "contents": [{
    "uri": "ui://weather-server/dashboard-template",
    "mimeType": "text/html;profile=mcp-app",
    "text": "<!DOCTYPE html><html>...</html>",
    "_meta": {
      "ui": {
        "csp": {
          "connectDomains": ["https://api.openweathermap.org"],
          "resourceDomains": ["https://cdn.jsdelivr.net"]
        },
        "prefersBorder": true
      }
    }
  }]
}
```

**Tool linked to a UI resource:**
```json
{
  "name": "get_weather",
  "inputSchema": { "type": "object", "properties": { "location": { "type": "string" } } },
  "_meta": {
    "ui": {
      "resourceUri": "ui://weather-server/dashboard-template",
      "visibility": ["model", "app"]
    }
  }
}
```

### 2.1 `_meta.ui` on a **resource** — the complete field set **[v2]**

`McpUiResourceMeta` is `additionalProperties: false` and has **exactly four** properties. Earlier
revisions of this document listed only two.

| Field | Type | Meaning |
|---|---|---|
| `csp` | object | §3.1. Four sub-fields, `additionalProperties: false` |
| `permissions` | object | §3.2. Four sub-fields, `additionalProperties: false` |
| **`domain`** | string | **Dedicated origin for the view sandbox** — see §3.4 |
| `prefersBorder` | boolean | Requests a visible border + background from the host — see §3.5 |

### 2.2 `_meta.ui` on a **tool** — constraints are stricter than expected **[v2]**

`McpUiToolMeta` is `additionalProperties: false`, and two of its properties are declared
`{"not": {}}` — a JSON Schema construct that nothing validates against, i.e. **the property must be
absent**:

```json
{
  "resourceUri":  { "type": "string" },
  "visibility":   { "type": "array", "items": { "const": "model" | "app" } },
  "csp":          { "not": {} },
  "permissions":  { "not": {} }
}
```

> **Rule-design consequence.** A server author who declares `csp` or `permissions` under a *tool's*
> `_meta.ui` — an entirely natural mistake, since that is where `resourceUri` lives — produces a
> schema-invalid document **and receives none of the restriction they believe they declared**. This
> is the same silent-inversion failure that motivates `PANE-SCHEMA-001/002`, and it was missing
> from the rule catalog. Added as `PANE-SCHEMA-005`.

`visibility` defaults to `["model", "app"]`. `"model"` = agent may call it. `"app"` = only the UI
app on the same connection may call it.

> Host MUST NOT include tools in the agent's tool list when their visibility does not include `"model"`
> Host MUST reject `tools/call` requests from apps for tools that don't include `"app"` in visibility.

Cross-server app-initiated tool calls are **always blocked**.

**Capability negotiation** at `initialize`:
```json
{
  "extensions": {
    "io.modelcontextprotocol/ui": {
      "mimeTypes": ["text/html;profile=mcp-app"]
    }
  }
}
```
`mimeTypes` is **REQUIRED** — but by prose, not by schema. **[v2]** `McpUiClientCapabilities` has
no `required` array; the constraint lives in the field description (*"Must include
`text/html;profile=mcp-app` for MCP Apps support"*) and in the spec text.

> **Rule-design consequence.** `PANE-SPEC-007` cannot be implemented as a schema assertion and must
> not claim `CERTAIN` confidence on schema grounds. Its confidence rests on the normative prose.
> Downgraded to `HIGH`. Checking that the array *contains the exact MIME type* matters more than
> checking mere presence, and that is the check to implement.

---

## 3. Security model

### 3.1 CSP — declared by server, enforced by host

Key: `_meta.ui.csp`, type `McpUiResourceCsp`. `additionalProperties: false` — **exactly four fields**:

```typescript
interface McpUiResourceCsp {
    connectDomains?: string[],   // → connect-src
    resourceDomains?: string[],  // → img-src, script-src, style-src, font-src, media-src
    frameDomains?: string[],     // → frame-src.  Omitted ⇒ frame-src 'none'
    baseUriDomains?: string[],   // → base-uri.   Omitted ⇒ base-uri 'self'
}
```

Wildcard subdomains (`https://*.example.com`) are supported in `resourceDomains`.

**Mandated default when `_meta.ui.csp` is omitted:**
```
default-src 'none';
script-src 'self' 'unsafe-inline';
style-src  'self' 'unsafe-inline';
img-src    'self' data:;
media-src  'self' data:;
connect-src 'none';
```

Normative statements, verbatim:
- "**CSP Enforcement:** Host MUST construct CSP headers based on declared domains"
- "**Restrictive Default:** If `ui.csp` is omitted, Host MUST use: [above]"
- "**No Loosening:** Host MAY further restrict but MUST NOT allow undeclared domains"
- "**Audit Trail:** Host SHOULD log CSP configurations for security review"
- "Host MUST block connections to undeclared domains"
- "Host SHOULD warn users when UI requires external domain access"

> ### ⚠ Rule-design consequence — `'unsafe-inline'` is MANDATED, not a flaw
> The spec's enforced default CSP includes `'unsafe-inline'` in `script-src` and `style-src`
> **unconditionally**, because raw HTML resources have no build step to externalize inline
> `<script>` tags.
>
> **A scanner MUST NOT flag inline scripts or `'unsafe-inline'` as a violation.** Doing so would
> flag every conformant server in the ecosystem. This is the single most likely way to ship a
> scanner that is instantly discredited.

### 3.2 Permissions — exactly four

Key: `_meta.ui.permissions`, `additionalProperties: false`:

```typescript
permissions?: {
  camera?: {},          // Permission Policy `camera`
  microphone?: {},      // Permission Policy `microphone`
  geolocation?: {},     // Permission Policy `geolocation`
  clipboardWrite?: {},  // Permission Policy `clipboard-write`
}
```

This is the **complete** enumeration in the Stable schema. Any other key is schema-invalid.

- "Hosts MAY honor these by setting appropriate iframe `allow` attributes."
- "Apps SHOULD NOT assume permissions are granted; use JS feature detection as fallback."

### 3.3 Sandboxing

> "All View content MUST be rendered in sandboxed iframes with restricted permissions. The sandbox
> limits the View from accessing the host or manipulating it. All communication with the host is
> done via `postMessage`, where the host is in control."

**The spec does not enumerate an exact `sandbox=` value for the View iframe.** "Restricted
permissions" is not a checkable literal. This is a real gap.

For the **sandbox proxy** specifically, the spec does pin values:
1. "The Host and the Sandbox MUST have different origins."
2. "The Sandbox MUST have the following permissions: `allow-scripts`, `allow-same-origin`."

> ### ⚠ Rule-design consequence — `allow-scripts allow-same-origin` is REQUIRED here
> In general web security this combination defeats sandbox isolation. In MCP Apps it is
> **mandated for the sandbox proxy**, and is safe only because the proxy sits on a different
> origin from the host (requirement 1 above).
>
> A scanner must flag this combination **only** when the framed document is same-origin with the
> host. Flagging the documented double-iframe pattern is a false positive.

`allow-downloads` is explicitly not set on the iframe. **[v2] This does not mean downloads are
impossible.** The protocol provides a host-mediated download API, `ui/download-file`, gated by the
host capability `downloadFile`. Downloads are removed from the *iframe's* control and handed to the
host — a narrower claim than "blocked by design," which is what this document previously said. See
§4.

### 3.4 `_meta.ui.domain` — server-requested sandbox origin **[v2]**

Undocumented in earlier revisions of this file, and directly load-bearing for every origin-based
rule. Schema description, verbatim:

> "Dedicated origin for view sandbox.
> Useful when views need stable, dedicated origins for OAuth callbacks, CORS policies, or API key
> allowlists.
> **Host-dependent:** The format and validation rules for this field are determined by each host.
> Servers MUST consult host-specific documentation for the expected domain format. Common patterns
> include: Hash-based subdomains (e.g., `{hash}.claudemcpcontent.com`), URL-derived subdomains
> (e.g., `www-example-com.oaiusercontent.com`).
> If omitted, host uses default sandbox origin (typically **per-conversation**)."

Three consequences, all new:

1. **It changes the origin model the sandbox rules depend on.** `PANE-SANDBOX-001` fires on
   `allow-scripts` + `allow-same-origin` *when same-origin with the host*. A server that sets
   `domain` has asserted a specific origin, and any same-origin reasoning must be evaluated
   against that value rather than against an assumed per-conversation origin.
2. **It converts ephemeral storage into persistent storage.** The default origin is *per
   conversation*, so `localStorage`, `sessionStorage`, IndexedDB, and cookies are naturally
   discarded between conversations. Declaring a stable `domain` makes app-side storage survive
   across conversations — a cross-conversation correlation and persistence surface that no other
   field creates. It is legitimate (OAuth callbacks genuinely need it) and it is worth disclosing.
3. **The format is host-defined, so it cannot be schema-validated.** It is a bare `string`. A
   scanner can report its presence and shape; it cannot judge its correctness.

Rules added: `PANE-SPEC-008` (declared), `PANE-CONTEXT-006` (persistence disclosure).

### 3.5 `prefersBorder` — the only boundary signal, and the server controls it **[v2]**

Schema description, verbatim:

> "Visual boundary preference - true if view prefers a visible border.
> Boolean requesting whether a visible border and background is provided by the host. Specifying an
> explicit value for this is recommended because hosts' defaults may vary.
> `true`: request visible border + background · `false`: request no visible border + background ·
> omitted: host decides border"

The spec's own social-engineering mitigation is *"Hosts should clearly indicate sandboxed UI
boundaries"* (§5). `prefersBorder: false` is a server **asking the host to remove that indicator**.

> **This is the strongest phishing signal in the entire protocol, and it is a declared boolean —
> no heuristic required.** It is not suspicious alone; plenty of apps want a seamless chart. It is
> highly suspicious in combination with credential-shaped content or host-mimicking markup.
> Rule added: `PANE-MIMIC-007`, which fires only on that combination.

### 3.6 Host-provided style variables — theming is sanctioned **[v2]**

`McpUiStyleVariableKey` enumerates a fixed set of CSS custom properties the host passes into the
app (`--color-background-primary`, `--color-text-primary`, `--color-border-primary`, and the
`secondary` / `tertiary` / `inverse` / `ghost` / `info` / `danger` / `success` / `warning` /
`disabled` variants across background, text, and border). `McpUiHostCss` additionally carries
`fonts`.

> ### ⚠ Rule-design consequence — visual blending is the intended design
> The protocol **deliberately supplies apps with the host's own colours and fonts so they blend
> in.** An app that looks like the host is doing exactly what the spec provides for.
>
> This materially weakens `PANE-MIMIC-004` as originally written ("host design tokens in untrusted
> markup"). Using `--color-text-primary` is conformance, not evidence. Only tokens **outside this
> enumerated set** that are specific to a particular host's private design system (`--vscode-*`,
> GitHub Primer class names) carry any signal at all — and that signal remains weak. `PANE-MIMIC-004`
> is rewritten accordingly and stays `LOW` confidence.
>
> It also *strengthens* the threat argument: the protocol removes visual distinguishability by
> design, then declines to mitigate phishing normatively. See [THREAT-MODEL.md](THREAT-MODEL.md) §3, T1.

---

## 4. Host ↔ App communication

**Transport:** JSON-RPC 2.0 over `window.postMessage`.

From `src/message-transport.ts` (`PostMessageTransport`):
- **Outbound** uses `postMessage(message, "*")` — a **wildcard target origin**. The doc comment
  states: *"Messages are sent using postMessage with `\"*\"` origin, meaning they are visible to
  all frames. The receiver should validate the message source for security."*
- **Inbound** validates `event.source !== this.eventSource` — **window-object identity, not
  `event.origin`**. Non-JSON-RPC messages are silently ignored.

**Acknowledged attack, from the project's own test suite** (`tests/e2e/security.spec.ts`,
"Cross-App Message Injection Protection"), verbatim:

> "This tests protection against the attack where a malicious app tries to inject messages into
> another app via: `window.parent.parent.frames[i].frames[0].postMessage(fakeResponse, "*")` …
> `window.frames[]` IS cross-origin accessible per HTML spec … a malicious sibling app can reach
> `window.parent.parent.frames[victimIdx].frames[0].postMessage(...)` and the message WILL be
> delivered. `PostMessageTransport`'s `event.source` check is the only defense."

Cross-frame injection between sibling apps is a real, tested-against attack path, and
`event.source` identity checking is the **only** defense — no origin check, no nonce, no secret.

### Methods the View can call on the Host

| Method | Effect | Consent required? |
|---|---|---|
Complete list of `ui/*` methods and notifications in the schema **[v2]** — the previous table
omitted `ui/download-file` and the entire inbound notification set.

| Method | Effect | Consent required? |
|---|---|---|
| `ui/open-link` | Open external URL in host browser | Host discretion |
| **`ui/message`** | **Inject a message with role `"user"` into the conversation** | **MAY — not required** |
| **`ui/update-model-context`** | **Overwrite the model's context for future turns** | Not specified |
| **`ui/download-file`** **[v2]** | **Write attacker-chosen bytes, with an attacker-chosen filename, to the user's disk.** Gated by host capability `downloadFile` | Not specified |
| `ui/request-display-mode` | Request inline / fullscreen / pip | — |
| `ui/resource-teardown` **[v2]** | Tear down the resource | — |
| `ui/initialize` | Lifecycle handshake | — |
| `tools/call` | Execute a tool on the connected server | Visibility-gated |
| `resources/read` | Read a resource | — |
| `notifications/message` | Log to host | — |

**Notifications the app *receives* — the untrusted-data ingress points [v2]:**

| Notification | Carries |
|---|---|
| **`ui/notifications/tool-result`** | **Tool output. This is where hostile data enters the app** |
| `ui/notifications/tool-input` · `...tool-input-partial` | Tool arguments, streamed |
| `ui/notifications/tool-cancelled` | Cancellation |
| `ui/notifications/host-context-changed` | Host context (theme, styles, display mode) |
| `ui/notifications/size-changed` · `...request-teardown` | Layout / lifecycle |
| `ui/notifications/initialized` · `...sandbox-proxy-ready` · `...sandbox-resource-ready` | Lifecycle |

> **This names the taint source `PANE-CONTEXT-005` needs.** That rule was specified as "model-context
> write reachable from a path that interpolates tool output" without identifying how tool output
> reaches the app. It arrives on `ui/notifications/tool-result`. The taint analysis is therefore
> concrete: **source** = the `tool-result` notification handler, **sinks** = `ui/message`,
> `ui/update-model-context`, `ui/download-file`, and DOM sinks (`innerHTML`, `document.write`,
> `insertAdjacentHTML`). See [RULES.md](RULES.md).

> ### ⚠ `ui/download-file` is a materially under-rated surface **[v2]**
> An app that has ingested hostile data via `tool-result` can hand the user a file. The spec
> specifies **no consent requirement** on this method — the host capability gates whether downloads
> work at all, not whether any individual download is approved. Combined with an attacker-controlled
> filename, this is a malware-delivery path that this document previously described as "blocked by
> design." Rule added: `PANE-CONTEXT-007`.

> ### ⚠ The most security-relevant fact in this document
> `ui/message` lets app-authored text enter the model's context **as if the user typed it**, and
> the spec only says the host **MAY** request consent. `ui/update-model-context` overwrites model
> context outright.
>
> This is prompt injection as a **supported protocol feature**. It is not a bug and cannot be
> "fixed" by a scanner — but a scanner can and should report, for every app, whether it uses these
> methods, so an operator knows what they are enabling.

---

## 5. Documented threat model (verbatim)

> **Threat Model**
> Attackers may use the embedded UI in different scenarios. For example:
> - Malicious server delivers harmful HTML content
> - Compromised View attempts to escape sandbox
> - View attempts unauthorized tool execution
> - View exfiltrates sensitive host data
> - View performs phishing or social engineering

> **Other risks**
> - **Social engineering:** UI can still display misleading content. Hosts should clearly indicate
>   sandboxed UI boundaries.
> - **Resource consumption:** Malicious View can consume CPU/memory. Hosts should implement
>   resource limits.

Four mitigations are given: Iframe Sandboxing, Auditable Communication, Predeclared Resource
Review, CSP Enforcement.

**Note the asymmetry:** five threats are listed, but phishing/social engineering and resource
exhaustion are demoted to "Other risks" with **no MUST or SHOULD keyword anywhere** — only "Hosts
should" in prose. The spec acknowledges UI phishing and declines to mitigate it normatively.
That gap is Panelint's core opportunity.

---

## 6. Lifecycle and integrity

- **Registration:** predeclared server-side, discovered via `resources/list` / `tools/list`.
  Servers MAY omit UI-only resources from `resources/list`.
- **Fetch:** "Host MUST use `resources/read` to fetch the referenced resource URI." Host MAY cache.
- **Versioning:** ❌ **No version field exists** on `UIResource`.
- **Integrity:** ❌ **No signing, hashing, or pinning mechanism is specified.** There is no
  `signature`, `hash`, `integrity`, or `nonce` property anywhere in `schema.json` — **re-confirmed
  [v2]** by case-insensitive search across all 39 definitions: `signature` 0 hits, `integrity` 0,
  `hash` 0, `nonce` 0. The only `version` occurrences are `protocolVersion`, which versions the
  protocol, not the resource.

The spec suggests hosts *may* "Generate hash/signature for resources" and "Implement
allowlists/blocklists based on resource hashes" — as host-side prose, with no RFC 2119 keyword and
no protocol fields to support it.

> **Product consequence.** Because the protocol has no integrity mechanism, a resource can change
> at any time with no signal. A scan is a point-in-time claim. This is why Panelint records a
> content hash per scan and re-scans on a schedule — see [DESIGN.md](DESIGN.md).

---

## 7. Draft-only — do NOT build against yet

The **draft** spec adds "App-Provided Tools Security": apps register their own agent-callable
tools via `app.registerTool()`, with suggested limits (max 50 tools/app, 30s timeout, 10MB result
cap). This materially expands the attack surface — apps become tool providers the model calls
directly.

**Status: proposed, not ratified as of 2026-08-04.** No Panelint rule may assume this behavior.
Track it; do not depend on it.

---

## 8. Known unverified items

- Whether Claude Desktop, ChatGPT, VS Code Copilot et al. **actually implement** each MUST
  (e.g. enforce the default CSP correctly) — **UNVERIFIED**. Spec and reference implementation are
  verifiable; production host conformance is not.
- ~~Production behavior of host content domains (`{hash}.claudemcpcontent.com`,
  `www-example-com.oaiusercontent.com`) — illustrative only~~ **Corrected [v2]:** these strings are
  not rumour. They appear verbatim in the `_meta.ui.domain` field description in `schema.json` as
  documented host patterns (§3.4). What remains unverified is only their *runtime* behaviour; their
  status as spec-documented examples is confirmed.
- SEP-2133's relationship to SEP-1724 / the extensions framework — **UNVERIFIED**, not fetched.
- A spec inconsistency: the `initialize` example in `apps.mdx` uses `"protocolVersion":
  "2024-11-05"` while other examples use `"2026-01-26"`. Do not copy that literal into fixtures.

# Panelint — Spec Coverage Matrix

**Last updated:** 2026-08-04 · Spec basis: SEP-1865 Stable (2026-01-26), schema `1.7.5`

---

## Why this file exists

[GOALS.md](GOALS.md) goal **G1** reads: *"Every requirement in SEP-1865 that is statically checkable has
a rule."*

That was an assertion with nothing behind it. A reader could not check it, and neither could we —
there was no list of requirements to check against. This file is the list. Every normative statement
and every schema constraint maps to exactly one of:

- **a rule** — with its ID;
- **out of scope** — with the reason, drawn from [GOALS.md](GOALS.md) §3 non-goals;
- **not statically checkable** — with what would be needed instead.

**A requirement with no row here is a gap in this file, not a gap that does not exist.** CI asserts
that every rule ID in [RULES.md](RULES.md) appears in at least one row below, so the catalog cannot
grow without this matrix growing with it. The reverse — a spec requirement with no rule and no
recorded reason — is a review failure.

---

## 1. Identifiers and resource shape

| Requirement | Source | Coverage |
|---|---|---|
| Resource URI uses the reserved `ui://` prefix | spec §Identifiers | `PANE-SPEC-001` |
| MIME type is `text/html;profile=mcp-app` | spec §Identifiers | `PANE-SPEC-002`, `PANE-SPEC-009` |
| Content supplied via `text` or `blob` | schema `ResourceContents` | `PANE-SPEC-003` |
| Extension label `io.modelcontextprotocol/ui` is reserved and declared | spec §Capability | `PANE-SPEC-007` |
| Client capability `mimeTypes` includes the MIME type | schema `McpUiClientCapabilities` + prose | `PANE-SPEC-007` — prose-only, no `required` array, hence `HIGH` not `CERTAIN` |
| Tool → resource link via `_meta.ui.resourceUri` | schema `McpUiToolMeta` | `PANE-SPEC-005` (resolves), `PANE-SPEC-011` (forms disagree) |
| Flat `_meta["ui/resourceUri"]` is deprecated, "removed before GA" | spec §Identifiers | `PANE-SPEC-006` — **only when the modern key is absent**; the SDK dual-writes it |
| `_meta.ui` list-level vs read-level precedence | ext-apps `McpUiAppResourceConfig` | `PANE-SPEC-010` |

## 2. Schema constraints

Every row here is `additionalProperties: false` or an explicit prohibition, so all are `CERTAIN`.

| Requirement | Source | Coverage |
|---|---|---|
| `_meta.ui.csp` permits exactly 4 keys | schema `McpUiResourceCsp` | `PANE-SCHEMA-001` |
| `_meta.ui.permissions` permits exactly 4 keys | schema `McpUiResourcePermissions` | `PANE-SCHEMA-002` |
| `_meta.ui` (resource) permits exactly 4 keys | schema `McpUiResourceMeta` | `PANE-SCHEMA-006` |
| `_meta.ui` (tool) **forbids** `csp` and `permissions` | schema `McpUiToolMeta` — `{"not":{}}` | `PANE-SCHEMA-005` |
| `_meta.ui` validates against the published schema | schema, whole | `PANE-SCHEMA-004` |
| Domain entries are origins or `https://*.host` wildcards | *prose only — schema types them as bare `string[]`* | `PANE-SCHEMA-003`, class `RISK` not `SCHEMA` for that reason |
| `visibility` items are `"model"` or `"app"` | schema `McpUiToolVisibility` | `PANE-SCHEMA-004` |

## 3. CSP — "Host MUST construct CSP headers based on declared domains"

| Requirement | Source | Coverage |
|---|---|---|
| `connectDomains` → `connect-src` | schema | `PANE-CSP-001`, `-009` |
| `resourceDomains` → `img/script/style/font/media-src` | schema | `PANE-CSP-002`, `-005`, `-007`, `-008`, `-012` |
| `frameDomains` → `frame-src`; omitted ⇒ `'none'` | schema | `PANE-CSP-003`, `-011` |
| `baseUriDomains` → `base-uri`; omitted ⇒ `'self'` | schema | `PANE-CSP-004`, `PANE-EXFIL-006` |
| "Host MUST use the restrictive default if `ui.csp` omitted" | spec §Security | `PANE-CSP-006` (INFO — the app will break, not a risk) |
| "Host MUST block connections to undeclared domains" | spec §Security | `PANE-CSP-006` — **host-side enforcement is N2, out of scope** |
| "No Loosening: Host MAY restrict further but MUST NOT allow undeclared" | spec §Security | **Out of scope — N2.** Host behaviour, not server-observable |
| "Audit Trail: Host SHOULD log CSP configurations" | spec §Security | **Out of scope — N2** |
| "Host SHOULD warn users when UI requires external domain access" | spec §Security | **Out of scope — N2** |
| `'unsafe-inline'` in the mandated default | spec §Security | **🚫 Never-flag.** Guarded by test. See [RULES.md](RULES.md) |

### CSP requirements that do not exist, and the rules that exist because of that

The four fields map only to **fetch** directives. These channels have no field, no default, and no
`default-src` fallback — so no server declaration can constrain them:

| Channel | Governing directive | Status | Coverage |
|---|---|---|---|
| Form submission | `form-action` | **No field. No fallback. Absent from the mandated default** | `PANE-EXFIL-001`, `-002` |
| Self-navigation | `navigate-to` | Never shipped in any browser | `PANE-EXFIL-004`, `-005` |
| Meta refresh | *(none)* | Governed by nothing | `PANE-EXFIL-003` |
| `<base href>` | `base-uri` | No `default-src` fallback, but the CSP construction **does** default it to `'self'` (apps.mdx L1743) | `PANE-EXFIL-006` |
| Resource hints | *(none in practice)* | Not CSP-subject in shipping browsers | `PANE-EXFIL-007` |
| `ui/open-link` | *(none)* | Host RPC — not subject to the app CSP at all | `PANE-CONTEXT-003`, `-008` |

## 4. Permissions and sandboxing

| Requirement | Source | Coverage |
|---|---|---|
| Four permissions, mapped to Permission Policy features | schema | `PANE-SCHEMA-002`, `PANE-SANDBOX-005`, `-006` |
| "Hosts MAY honor these via iframe `allow`" | spec §Permissions | **Out of scope — N2** (host-side) |
| "Apps SHOULD NOT assume permissions are granted" | spec §Permissions | **Not statically checkable** — requires knowing whether feature detection is *correct*, not merely present |
| "All View content MUST be rendered in sandboxed iframes" | spec §Sandboxing | **Out of scope — N2.** Host-side |
| "restricted permissions" on the View iframe | spec §Sandboxing | **Not checkable — the spec enumerates no value.** A real gap, recorded in [SPEC-REFERENCE.md](SPEC-REFERENCE.md) §3.3 |
| "Host and Sandbox MUST have different origins" | spec §Sandbox proxy | Partially — `PANE-SANDBOX-001` via `_meta.ui.domain`; host side is N2 |
| "Sandbox MUST have `allow-scripts`, `allow-same-origin`" | spec §Sandbox proxy | **🚫 Never-flag** unless same-origin with host |
| `allow-downloads` not set | spec §Sandbox proxy | Nested frames: `PANE-SANDBOX-002`. **But downloads are not blocked** — `ui/download-file` exists → `PANE-CONTEXT-007` |
| Nested frame permission re-delegation | *not addressed by the spec* | `PANE-SANDBOX-007` |

## 5. Host ↔ App methods

Every method in the schema has a row. `INFO` class throughout except where tainted.

| Method | Coverage |
|---|---|
| `ui/message` | `PANE-CONTEXT-001` · consent is **MAY**, recorded as capability |
| `ui/update-model-context` | `PANE-CONTEXT-002` · no consent specified |
| `ui/open-link` | `PANE-CONTEXT-003` (literal URL) · `PANE-CONTEXT-008` (built at runtime — `RISK`/`HIGH`) |
| `ui/download-file` | `PANE-CONTEXT-007` · no consent specified |
| `ui/request-display-mode` | `PANE-CONTEXT-009` (fullscreen only) |
| `tools/call` from the app | `PANE-CONTEXT-004`, `PANE-CONTEXT-010` |
| `resources/read` from the app | **No rule.** Reads a resource on the same server; no privilege gain beyond what the app already has |
| `ui/initialize`, `ui/resource-teardown`, `notifications/message` | **No rule.** Lifecycle and logging; no security-relevant capability |
| `ui/notifications/tool-result` and the other inbound notifications | Not a capability — the **taint source** for `PANE-CONTEXT-005` |
| "Host MUST NOT include non-`model`-visible tools in the agent's list" | **Out of scope — N2** |
| "Host MUST reject `tools/call` for tools without `app` visibility" | **Out of scope — N2** |

## 6. Lifecycle and integrity

| Requirement | Source | Coverage |
|---|---|---|
| Resources predeclared, discovered via `resources/list` | spec §Lifecycle | `PANE-SPEC-005` |
| "Host MUST use `resources/read` to fetch the resource" | spec §Lifecycle | **Out of scope — N2** |
| Servers MAY omit UI-only resources from `resources/list` | spec §Lifecycle | **Not checkable** — an omitted resource is unobservable by definition. Noted as a coverage limit in every report |
| **No version field on `UIResource`** | schema — verified absent | Not a requirement. Motivates `contentHash`, [DESIGN.md](DESIGN.md) §7 |
| **No signing / hashing / pinning mechanism** | schema — verified absent | Not a requirement. Motivates point-in-time framing |
| `_meta.ui.domain` — dedicated sandbox origin | schema | `PANE-SPEC-008`, `PANE-CONTEXT-006` |
| `prefersBorder` | schema | `PANE-MIMIC-007` |

## 7. Requirements the spec states ambiguously

Recorded because a rule built on an ambiguity is a rule that will be wrong half the time.

| Ambiguity | The conflict | How Panelint behaves |
|---|---|---|
| **`base-uri` default** | Schema says `baseUriDomains` omitted ⇒ `base-uri 'self'`. The mandated default policy quoted in the spec contains **no `base-uri` directive**, and `base-uri` has no `default-src` fallback | `PANE-EXFIL-006` fires on a `<base>` element **either way**, so the rule is correct under both readings. The ambiguity is reported upstream, not resolved by us |
| **CSP synthesis from a non-empty `csp`** | The spec pins the *omitted* default. It never states the policy a host builds from declared domains — is `default-src 'none'` retained? is `form-action` ever emitted? | Panelint's synthesis is an **assumption**, named as one in every CSP finding. [DESIGN.md](DESIGN.md) §3.3 |
| **View iframe sandbox value** | "restricted permissions" is prose, not a literal | No rule asserts a specific value. `PANE-SANDBOX-*` findings state their conditionality in the finding text |
| **Which `resourceUri` form wins when both are present and differ** | The SDK passes both through with no reconciliation | `PANE-SPEC-011` reports the disagreement without asserting a winner |
| **`protocolVersion` in the spec's own example** | `apps.mdx` shows `"2024-11-05"` while other examples use `"2026-01-26"` | Never copied into a fixture. Recorded in [SPEC-REFERENCE.md](SPEC-REFERENCE.md) §8 |

## 8. Rules with no spec requirement behind them

These exist because the **absence** of a requirement is the finding. Listed separately so nobody
mistakes them for conformance checks — they are risk observations, and a server can be fully
conformant and still trigger every one.

| Family | Why it exists |
|---|---|
| `PANE-EXFIL` | The spec provides no control for these channels at all — §3 above |
| `PANE-HIDDEN` | The spec has nothing to say about invisible content. ~87% of injections are non-visible |
| `PANE-OVERLAY` | Phishing and social engineering are named in the spec's threat model and given **no MUST or SHOULD** |
| `PANE-DOM` | The spec does not constrain how an app builds its DOM |
| `PANE-MSG` | The spec specifies the *host's* transport hygiene, never the app's handler |
| `PANE-INPUT` | No permission is required to write the clipboard from a `copy` handler |
| `PANE-INTEGRITY` | SRI is never mentioned in the spec, and the protocol has no integrity mechanism of its own |
| `PANE-MIMIC` | The threat is named in the spec and normatively unmitigated |

## 9. Coverage summary

| Category | Count |
|---|---|
| Statically checkable requirements **with a rule** | 34 |
| Out of scope — host behaviour (**N2**) | 9 |
| Not statically checkable, with reason recorded | 4 |
| Ambiguities recorded rather than guessed | 5 |
| Rules covering an **absent** requirement | 8 families |

**G1 is satisfied for every row above.** The honest caveat: G1 is scoped to SEP-1865 **Stable
(2026-01-26)**. The draft's app-provided-tools feature is deliberately uncovered
([SPEC-REFERENCE.md](SPEC-REFERENCE.md) §7), and the vendored schema is generated from SDK `main`
rather than the frozen Stable spec — so "present in `schema.json`" is not by itself evidence that
something is a Stable requirement.

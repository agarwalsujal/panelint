# Panelint — Threat Model

**Last updated:** 2026-08-04 · Spec basis: SEP-1865 Stable (2026-01-26), protocol 2026-07-28

---

## 1. The trust inversion

A browser renders untrusted HTML into a context the user knows is untrusted. There is a URL bar,
an origin, a padlock, a mental model built over two decades.

An AI assistant renders untrusted HTML into a conversation the user believes is **the assistant
speaking**. There is no origin indicator, no address bar, and no established instinct that part of
the window belongs to a third party.

Every attack below follows from that inversion.

---

## 2. Who the attacker is

Ranked by likelihood, not by drama.

### A1 — Data-supply attacker *(primary)*

Cannot modify the server. **Can place content that the server will render.**

An attacker who can write to a Notion page shared with the victim, insert a row into a monitored
database, file an issue in a tracked repository, or send a message into a synced channel, gets
their content passed through an honest server into the victim's agent.

This is the design centre. The vendor is not compromised and has done nothing wrong. It is
classical XSS through a door nobody has locked yet.

### A2 — Careless server author *(most common findings)*

No malice. Ships without declaring `connectDomains`; sets `["*"]` during development and forgets;
interpolates tool output into HTML without escaping. Produces most real findings.

### A3 — Sibling app

Another MCP App running in the same host. The ext-apps test suite documents this path directly:

> "a malicious sibling app can reach `window.parent.parent.frames[victimIdx].frames[0].postMessage(...)`
> and the message WILL be delivered. `PostMessageTransport`'s `event.source` check is the only defense."

Acknowledged, tested against, and defended by exactly one identity check.

### A4 — Supply-chain attacker

Compromises a dependency of an honest server. Precedent: `eslint-config-prettier`, 30M weekly
downloads, shipped Windows malware in July 2025 after a maintainer phish.

### A5 — Malicious server author

A server built to attack. **Least likely and least interesting.** The MCP registry holds ~19,800
servers, 52% abandoned, and anyone may publish — so the population exists. But this attacker is
also the easiest to handle by reputation, and dwelling on it produces a product that accuses
vendors instead of helping them.

---

## 3. Attack classes

### T1 — Credential harvesting via UI mimicry
**Attacker:** A5, A4 · **Severity: Critical** · **Detection: heuristic**

The app renders a login prompt visually identical to the host's own. The published example:

> "a server ships HTML identical to VS Code's native auth prompt… you just handed your login
> credentials to a server-rendered form."

The spec names this ("View performs phishing or social engineering") and then places it under
"Other risks" with **no MUST or SHOULD**. It is acknowledged and normatively unmitigated.

**What Panelint can do:** structural signals only — password input plus brand keyword, hidden
credential-shaped fields, `prefersBorder: false` combined with credential content, and *host-private*
design tokens (`--vscode-*`, Primer class names). Visual similarity requires rendering and is out of
scope. **Ships behind `--experimental`.**

> **One caveat that cuts against the tool and belongs here rather than buried in the rule catalog:
> the protocol deliberately makes apps look like the host.** `McpUiStyleVariableKey` supplies apps
> with the host's own colour tokens and `McpUiHostCss` with its fonts. So visual blending is
> *conformance*, and only tokens outside that sanctioned set carry any signal at all. This both
> weakens the detector and strengthens the threat: the spec removes visual distinguishability by
> design, then declines to mitigate phishing normatively.

### T2 — Prompt injection via invisible content
**Attacker:** A1, A2 · **Severity: High** · **Detection: deterministic**

Text present in the DOM but invisible to the human, positioned to be read by the model. An
empirical study found **~87% of injections are non-visible**.

Carriers: `display:none`, `visibility:hidden`, `opacity:0`, `font-size:0`, text colour matching
background, off-screen absolute positioning, collapsed `clip-path`, HTML comments containing
prose, `aria-hidden="true"` wrapping substantial text, zero-width and invisible Unicode.

**This is the highest-value rule class in the product.** "Is this content in the DOM but not
visible" is a structural fact — answerable deterministically, without judging meaning. It is where
XSS-style rigor genuinely transfers.

**Caveat:** benign hidden content is common (`sr-only` accessibility text, SEO). Severity must key
off *volume and shape* of hidden text, not mere presence.

### T3 — Context poisoning through sanctioned APIs
**Attacker:** A1, A5 · **Severity: High** · **Detection: deterministic (usage reporting)**

`ui/message` injects text with role `"user"` into the conversation. `ui/update-model-context`
overwrites model context for future turns. The spec requires consent for **neither** — `ui/message`
consent is **MAY**.

This is prompt injection **as a supported protocol feature**. No scanner can fix it. Panelint
reports, per app, whether these methods are used, so an operator knows what capability they are
enabling.

### T4 — Exfiltration via declared domains
**Attacker:** A1, A2 · **Severity: High** · **Detection: deterministic**

`connectDomains: ["*"]` or a wide wildcard means any data reaching the app can be sent anywhere.
Fully legal. The host MUST block undeclared domains — so a narrow declaration is a real control
**for fetch, XHR, WebSocket, and beacon**, and a broad one silently discards it.

**Wildcards are not the only case.** `resourceDomains` is a single knob that opens five directives
(`img-src`, `script-src`, `style-src`, `font-src`, `media-src`). Declaring
`["https://cdn.jsdelivr.net"]` to load a chart library also grants an image-beacon egress channel
and a CSS-exfiltration sink — and because jsDelivr, unpkg and cdnjs serve **arbitrary
attacker-published npm packages**, it is operationally close to `script-src *` for anyone who can
publish to npm. *Any* non-empty `resourceDomains` is a bidirectional channel.

### T5 — Sandbox escape
**Attacker:** A3, A5 · **Severity: Critical** · **Detection: partial**

`allow-scripts` + `allow-same-origin` on a same-origin frame lets script reach
`window.parent.document`, locate its own iframe, and `removeAttribute('sandbox')`.

> **Stated precisely, because the imprecise version invites a reader to dismiss the premise.**
> Removing the attribute has **no effect on the already-loaded document**. New sandbox flags apply
> only on navigation, so the actual escape is `frame.removeAttribute('sandbox'); frame.src =
> frame.src` — remove, then reload.

**Handle with care.** That exact combination is **mandated** for the MCP Apps sandbox proxy and is
safe there only because the proxy is required to be cross-origin from the host. Flagging the
documented pattern is a false positive that would discredit the tool. Flag only when same-origin
with the host.

### T6 — Cross-app message injection
**Attacker:** A3 · **Severity: High** · **Detection: partial — the victim side is in scope**

> **Corrected.** This section previously read: *"Lives entirely in host transport behavior; not
> visible from a server's declared resources."* That was wrong, and it ruled a whole detectable rule
> family out of scope by mistake.

The **host transport** side is indeed out of scope — whether the host validates `event.source`
correctly is a property of the host.

The **victim** side is not. The app's own `window.addEventListener('message', …)` handler ships
inside the `ui://` resource HTML and is fully statically visible. Given that the host sends with
`postMessage(msg, "*")`, that inbound validation is `event.source` identity only, and that
`window.frames[]` is cross-origin reachable, an app that consumes `event.data` **without** checking
`event.source === window.parent` is directly drivable by a sibling app.

Also in scope, and a classic: an origin check written with `indexOf`, `startsWith`, `includes`, or
an unanchored regex is bypassable by a lookalike origin. That is `CERTAIN`-confidence detectable.

Covered by `PANE-MSG-001..004`.

### T7 — Schema abuse
**Attacker:** A2, A5 · **Severity: Low–Medium** · **Detection: deterministic**

`_meta.ui.csp` and `_meta.ui.permissions` are `additionalProperties: false`. A server writing
`scriptDomains` instead of `resourceDomains` is schema-invalid — and, more importantly, believes
it declared a restriction it did not declare. Silent failure, trivially detectable.

Two variants are worse than a misspelling, because the author's code looks correct:

- **`csp` or `permissions` on a *tool's* `_meta.ui`.** The schema declares both as `{"not": {}}` on
  `McpUiToolMeta` — they must be absent. Since `resourceUri` lives there, putting `csp` there too is
  the natural guess. The server ships with **no CSP at all** while believing it declared one.
- **List-level and read-level `_meta.ui` disagreeing.** The `resources/list` entry is the static
  default a host reviews at connection time; the `resources/read` item **takes precedence**. A
  narrow list-level policy and a broad read-level one is a misleading review surface.

---

### T8 — Egress via channels no CSP field governs *(new)*
**Attacker:** A1, A2, A5 · **Severity: Critical** · **Detection: deterministic**

T4 describes a control that can be too loose. **T8 describes the absence of a control.**

`_meta.ui.csp` has four fields and all four map to CSP **fetch** directives. The spec's mandated
default policy is `default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self'
'unsafe-inline'; img-src 'self' data:; media-src 'self' data:; connect-src 'none';`

**`form-action` is absent from that policy, and `form-action` does not fall back to `default-src`.**
MDN, verbatim: *"`default-src` fallback: No. Not setting this allows anything."* There is no
`formDomains` field — verified by search across all 39 schema definitions.

> **Every conformant MCP App can POST arbitrary data to any origin on the internet, and no
> server-side declaration can prevent it.** `connect-src 'none'` — the field that looks like the
> egress control — is decorative against a `<form>`.

The same holds, with varying force, for:

| Channel | Why CSP does not stop it |
|---|---|
| `<form action>` / `<button formaction>` | `form-action` unset, no `default-src` fallback, no schema field |
| Self-navigation (`location.href = …`) | `navigate-to` was never shipped in any browser; a document navigating itself is not a top-level navigation |
| `<meta http-equiv="refresh">` | Governed by no directive |
| `<base href>` | `base-uri` also has no `default-src` fallback, and the mandated policy omits it |
| `<link rel="dns-prefetch">` / `preconnect` | Not subject to CSP in any shipping browser |
| **`ui/open-link`** | A **host RPC**. Not subject to the app's CSP at all — the host opens the URL in the user's own browser, with the user's own cookies |

This is the class the original rule catalog missed entirely, and it is why an attacker had complete
egress from an app that scanned clean on all 45 original rules. Covered by `PANE-EXFIL-001..007` and
`PANE-CONTEXT-008`.

### T9 — Clickjacking and surface impersonation *(new)*
**Attacker:** A1, A5 · **Severity: High** · **Detection: deterministic**

§1 of this document is built on "the user believes it is the assistant speaking," and
the market research §5 cites Backslash naming clickjacking explicitly — yet it had no attack
class and no rule. It is **cheaper than credential phishing and needs no password field**: a
viewport-filling overlay carrying assistant-voice prose and an "Approve" button that calls
`ui/message`, or a transparent click-catcher over the pane.

Two facts make this materially worse than the equivalent web attack. The protocol **supplies apps
with the host's own colours and fonts** (`McpUiStyleVariableKey`), so visual blending is the
sanctioned design. And `prefersBorder: false` lets a server **ask the host to remove the visible
boundary** that the spec's own mitigation depends on. Covered by `PANE-OVERLAY-001..003`,
`PANE-MIMIC-007/008`, and `PANE-CONTEXT-009`.

### T10 — Supply chain through declared subresources *(new)*
**Attacker:** A4 · **Severity: High** · **Detection: deterministic**

A4 is ranked third in §2 and had **zero rules**. An app loading `<script src>` from a declared
`resourceDomains` origin with no `integrity` attribute inherits whatever that origin serves next.
This is the `eslint-config-prettier` scenario with the door already open, and the protocol offers no
integrity mechanism of its own (§5). SRI is the only available control, and it is never mentioned in
the spec. Covered by `PANE-INTEGRITY-001/002` and `PANE-CSP-008`.

## 4. Out of scope — stated plainly

| Not covered | Why |
|---|---|
| Host conformance | Not determinable from a server. Whether Claude enforces the CSP it receives requires testing Claude |
| Runtime-injected payloads | Base64-decoded and inserted post-load, invisible to static analysis. Real limitation of v1 |
| Visual similarity | Requires rendering and a screenshot pipeline |
| Semantic injection judgment | Probabilistic. Classifiers drop from 97.5% to ~71% recall under distribution shift. Advisory only, never a gate |
| Server-side vulnerabilities | `agent-scan` and general SAST cover this. Panelint is the UI surface only |
| An *app's* resource exhaustion | The spec defers it to hosts; not statically checkable. **This says nothing about the scanner's own limits — see §5** |
| Shared sandbox-proxy origin | `allow-same-origin` makes a frame same-origin with **the proxy**. If a host serves several apps from one proxy origin, every app is same-origin with every other — direct DOM access, shared storage, no `postMessage` needed, and A3's `event.source` defense bypassed entirely. The safety property requires per-app origin isolation, which the spec does not require and a server cannot observe. Recorded here so it is not left implied-safe |

---

## 5. Threats to Panelint itself

**This section did not exist before v2, and its absence was the largest gap in this document.**
Panelint parses hostile input by design, over a live connection, as a security tool. §4 previously
dismissed resource exhaustion as "the spec defers it to hosts" — that reasoning is about the *host*,
and it was silently applied to the scanner too.

| Threat | Reality | Control |
|---|---|---|
| **Code execution** | Live stdio scanning **spawns the target server process**. Scanning a hostile repo runs its code, potentially in CI with repository credentials in the environment | Gated behind explicit `--allow-spawn`, resolved command echoed, spawn timeout, guaranteed child kill on SIGINT. CI scans recorded captures instead |
| **SSRF** | `--server <url>` fetches user-supplied URLs | Reject non-public IPs (incl. `169.254.169.254`) and non-`http(s)` schemes; refuse cross-host redirects rather than following them |
| **Scanner DoS** | `resources/read` is uncapped by the SDK. Selector matching is O(rules × nodes) — 50 k selectors × 20 k nodes is 10⁹ operations, inside the "sub-second" claim. Deep nesting overflows recursive walkers. `PANE-HIDDEN-010` would decode an 80 MB data URI | Hard caps in `src/limits.ts`, each producing a `LIMIT_EXCEEDED` diagnostic — never a crash, never a silent pass. A fixture per limit. **[v3] The volume caps do not catch depth attacks.** Four measured paths, and the controls that do catch them, are in [DESIGN.md](DESIGN.md) §10 |
| **Output as an injection vector** | SARIF snippets and the public directory render attacker-authored HTML | All evidence HTML-escaped and length-capped in every format; the directory renders evidence as text, never markup |
| **Log leakage** | A hidden-text finding piped into a CI log could reproduce the injection payload in full | Never log resource content, decoded blobs, `_meta` values, spawned-server environment, or `connectDomains` URLs. Findings quote a truncated excerpt at most |
| **Arbitrary file read, ours [v3]** | Directory mode resolves a file path taken from attacker-controlled source, and tail-matches a `ui://` path that may contain `../`. Resolved bytes are hashed and quoted as finding evidence into SARIF uploaded to GitHub code scanning | Realpath containment under the scan root, symlinks refused, re-check on the open descriptor, extension allowlist, per-file byte cap, binary sniff, deny list (`.git`, `node_modules`, `.env*`, `*.pem`, `id_*`), repo-relative paths in all output. [DESIGN.md](DESIGN.md) §3.1 |
| **Suppression as an attacker capability [v3]** | `<!-- panelint-disable-next-line -->` sits in the byte stream this document calls hostile. One comment above a hostile `<form>` and the scan reports clean | Inline suppressions honoured **only** in directory mode; on stdio, http and capture they are counted and reported as tampering evidence. Repo-local config may only raise severity. Every format carries `suppressed:` counts. [DESIGN.md](DESIGN.md) §5 |
| **Supply chain, ours** | A4 is in our own threat model, and Panelint has **16 direct dependencies whose production install closure is 119 packages** — see the correction below | Exact-pinned deps, committed lockfile, `npm ci --ignore-scripts`, npm provenance on publish, review note required for any off-registry `resolved` URL |

> ### Correction [v3] — this row said "14 dependencies", and it was wrong by 8×
> Measured against the committed lockfile, not counted off the table in [DESIGN.md](DESIGN.md) §9:
> **16 direct dependencies, 119 packages installed.**
>
> **93 of the 119 come from `@modelcontextprotocol/sdk@1.30.0` alone**, 88 of them attributable to
> nothing else in the tree. That single dependency brings `express@5`, `hono`,
> `@hono/node-server`, `cors`, `body-parser`, `serve-static`, `express-rate-limit`, `jose`,
> `pkce-challenge`, `eventsource` and `cross-spawn`. Panelint uses the SDK as a **stdio client
> only**: it opens no socket, serves no request, and runs no OAuth flow, so two HTTP server
> frameworks and an auth stack are installed for a code path that does not exist.
>
> An undercount inside a threat model whose A4 section names `eslint-config-prettier` is the specific
> failure this project's verification rule exists to prevent. The number was asserted; it is now
> measured, reproducible from `package-lock.json`, and the options for reducing it are recorded in
> [DESIGN.md](DESIGN.md) §9. None has been taken, which means the tree above is what ships today.

Full controls in [DESIGN.md](DESIGN.md) §10. **A scanner that ships a compromised release is worse
than no scanner** — our own A4 analysis applied to ourselves.

---

## 6. What the protocol cannot protect against, by design

Recorded so no report over-promises:

1. **No integrity mechanism.** No `signature`, `hash`, `integrity`, or `version` field exists
   anywhere in the resource schema. A resource may change between scan and execution with no
   signal. **A scan is a point-in-time claim about a content hash — nothing more, and every report
   must say so.**
2. **No consent requirement on context writes.** `ui/message` consent is MAY.
3. **No enumerated sandbox value for the View iframe.** "Restricted permissions" is prose, not a
   checkable literal.
4. **Phishing is acknowledged and unmitigated.** Named in the threat model, demoted to "Other
   risks," given no normative keyword.

Items 1 and 4 are not bugs to report upstream — they are the gaps that make an external scanner
worth building.

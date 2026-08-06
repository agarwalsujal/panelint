# Changelog

Panelint reports properties of a content hash at a point in time. It never says a server "is safe."

## 0.2.0

**Every user of 0.1.x should upgrade.** This release closes eighteen ways a resource could be
scanned and reported clean without actually being examined. Several were reachable by the scanned
party — and one, `:not()` nesting, is a working evasion of the PANE-HIDDEN family in the published
0.1.3 on npm.

Each item below was found by running something, not by reading code. The measurements are from the
pinned dependency versions on 2026-08-06.

### Silent passes an attacker could choose

A payload that reaches "no finding" through a gap the attacker picks is a reportable vulnerability
in Panelint, not a documented limitation ([SECURITY.md](SECURITY.md) §1). These qualified.

- **`:not()` nesting evaded the whole PANE-HIDDEN family.** `.s:not(:not(…:not(.s)…)){display:none}`
  at even nesting parity is the identity — every browser renders it as `.s{display:none}` and hides
  the text. At ~400 wrappers `postcss-selector-parser` threw, `classifySelector` returned
  `applies: false`, and the rule was dropped with no diagnostic. 3 KB of CSS, entirely silent.
  Selector parse failures are now reported and mark the cascade undecided.

- **CSS nesting was never walked.** `body { .s { opacity: 0 } }` bound nothing. The walker recursed
  into at-rules only, so a nested rule was dropped silently and every CSS-dependent rule read the
  document as carrying no such declaration. Native nesting has shipped in all three engines since
  2023.

- **Inline scripts were parsed as modules.** A `<script>` body is classic, sloppy-mode code. Parsing
  it with `sourceType: 'module'` puts acorn in strict mode, where constructs every browser executes
  are syntax errors — and a syntax error set `ast: null`, which every AST rule reads as "no script
  here." Prefixing `with(window){var z=1;}` took a hostile script from two gate-eligible findings to
  exit 0. Also `var n = 0755;`, `<!-- legacy`, `function f(a,a){}`, `delete localVar`,
  `var interface = 1`. Scripts now parse as `script` first, falling back to `module`.

- **The `ui://` scheme filter was case-sensitive.** All three acquire paths used
  `startsWith('ui://')`. A resource at `UI://evil/panel.html` produced zero resources, exit 0, and
  not even a `NO_RESOURCES_FOUND` diagnostic. RFC 3986 §3.1 makes the scheme case-insensitive, which
  is what `PANE-SPEC-001` already assumed.

- **A selector css-select gets WRONG was trusted.** The dangerous case is not the selector that
  throws, which is caught and reported. It is the one css-select answers confidently and answers
  incorrectly. Selectors 4 defines `:read-write` as matching any user-alterable element, so a plain
  `<input>` matches in every browser; css-select returns false. `.s:read-write{opacity:0}` therefore
  bound no declaration at all and hid an autofill target with nothing anywhere signalling a problem.
  Such selectors are now treated as unevaluable and mark the cascade undecided.

- **An unparseable inline `style=` was dropped entirely.** CSS Syntax 3 §4.3.2 ends an unterminated
  comment at EOF, so a browser applies the declarations before the break. postcss throws, and the
  `catch { continue }` made `style="opacity:0;/*"` read as an element with no inline style —
  PANE-INPUT-001 (CRITICAL, gate-eligible) did not fire, exit 0, no diagnostic. The prefix is now
  recovered and the node marked undecided.

- **A decoy file shadowed the real resource in directory mode.** Resolution tried a sibling file, an
  inline literal and a literal-path read call in that order, and the first to answer won outright.
  A contributor who controls both files added a 38-byte `app/panel.html` containing `<h1>ok</h1>`
  and the hostile inline literal in `server.js` was never read: 5 gating findings became 0, with no
  diagnostic that a second candidate existed. All routes are now resolved and every distinct content
  is scanned, so adding a file can only add a resource, never remove one.

- **A wrongly-typed `_meta.ui` read as an absent one.** `{ ui: [{ csp: … }] }` resolved to null and
  was indistinguishable from a resource declaring no `_meta` at all, so every `requires: ['meta']`
  rule and every PANE-SCHEMA rule saw nothing. One bracket took a wildcard `connectDomains`
  declaration from a gate-eligible finding to exit 0. It is validated as the schema violation it is.

- **Only the first `resources/read` content item was analysed.** The item was chosen by "first with
  bytes", ignoring `mimeType`, so a server could put a benign `text/plain` item first and the real
  `text/html;profile=mcp-app` app second. A host selecting by MIME type renders the second. The
  app-MIME item is now preferred and any other item carrying bytes is named in a diagnostic.

- **Tool-referenced resources absent from `resources/list` were never read.** The specification
  explicitly permits that omission (`apps.mdx` L395), so an entire sanctioned class of conformant
  server scanned as `NO_RESOURCES_FOUND` at exit 0 — and a hostile server could simply not list the
  resource carrying the payload. They are now read, marked `discoveredVia: 'tool-reference'`, and
  reported with an `UNLISTED_RESOURCE` diagnostic.

### Resource exhaustion, which was also rule suppression

- **`:has()` blew through `selectorMatchBudget`.** `Budget` counted calls, and a call is not a unit
  of work: `:has()` re-enters the matcher over the candidate's whole subtree. Measured on 5,456
  bytes, 495 nodes and one CSS rule — every existing ceiling passing by orders of magnitude —
  `div:has(div div div span)` ran **45,555 ms with zero diagnostics at exit 0**. One single `cssIs`
  call took 12.7 s, so nothing checked between calls could bound it. The charge is now
  `subtree^(1+descendants)`, computed from real subtree sizes and refused before the first call.
  The same document is now 3 ms with a `SELECTOR_SKIPPED` diagnostic.

- **An exhausted budget suppressed rules invisibly.** Rule order is deterministic and published, so
  an attacker burns the budget in a rule that runs before the one that would catch the payload. The
  report said only how many rules did not run, never which, and produced no undecided notes — so a
  consumer reading findings-by-rule could not distinguish "checked, clean" from "never ran." Every
  unrun rule is now named as undecided.

- **`_meta` was covered by no limit key at all.** 10,000 domains against 4,000 `<img>` ran 17 s. Now
  bounded by `maxMetaDomains` (default 256). The oversized list is **refused, not truncated**: a
  shortened `connectDomains` makes a declared origin read as undeclared, which would turn a resource
  ceiling into a finding on conformant markup.

- **`selectorIsTractable` had zero call sites** through four releases. It is the documented guard
  against selectors that are cheap to write and blow the stack while compiling. Now wired in.

### Reporting the truth about a scan

- **SARIF reported truncated scans as successful.** `executionSuccessful` read `errors.length === 0`
  alone, so the one case where "0 results" means "nothing was looked at" was indistinguishable from
  a clean run in the GitHub Security tab. `scanWasTruncated` existed for exactly this and had no
  callers. Truncation is now a `warning`, not a `note`, because GitHub renders notes nowhere useful.

- **A whole analysis input degrading to empty did not affect the exit code.** When the style index
  could not be built, every CSS rule ran against an empty cascade; when script collection failed,
  every JS rule ran against an empty list. Both were plain `PARSE_FAILED` diagnostics, so the scan
  exited 0 reporting "0 findings". Measured: `<style>@media screen{.s{opacity:0}</style>` — which
  browsers auto-close at EOF and postcss does not — suppressed a CRITICAL finding that way. These
  now emit `INPUT_DEGRADED`, which counts as truncation.

- **Suppression diagnostics were computed and discarded.** `INLINE_SUPPRESSION_IGNORED` carries
  "would have hidden N findings" — tamper evidence from the scanned tree — and never reached the
  report. Config, suppression and baseline diagnostics now surface with their original codes.

### Rules

- **PANE-EXFIL-006 no longer gates on the specification's own mechanism.** Declaring an origin in
  `baseUriDomains` and pointing `<base href>` at it is the sanctioned use. At the default
  `--fail-on high` the rule failed the build of a conformant server. The finding is still emitted,
  at LOW, below the gate. An undeclared origin is unchanged at HIGH.

- **PANE-CONTEXT-004 and PANE-CONTEXT-010 could not fire.** Both read their tool list from
  `ctx.options['tools']`, and nothing on any code path ever populated `ruleOptions` — so they saw an
  empty list on every scan ever run, while their unit tests passed because the test helper built the
  field by hand. Tools now reach a rule as `ctx.tools`.

### Added

- `Limits.maxMetaDomains`, CLI-only like every other ceiling.
- `DiagnosticCode`: `UNLISTED_RESOURCE` and `INPUT_DEGRADED`, plus the config and baseline codes.
- `UIResource.discoveredVia`.
- `RuleContext.tools`.
- `isUiUri` and `isAppMime`, shared by all acquire paths so they cannot drift apart again.

### Tests

1192 → 1259, across two new files. `test/silent-pass.test.ts` collects the cases above by the
property they share rather than by the module they live in: absence of a finding must never be
producible by the scanned party. `test/dos.test.ts` now exists: `fixtures/malicious/dos/cases.json` had named it since
0.1.0 and the entire resource-exhaustion control layer shipped with no executable test, which is how
`selectorIsTractable` rotted into dead code unnoticed. It found two real bugs on its first run.

### Known and not fixed in this release

Stated here rather than in a footnote, because a reader deciding whether to trust a clean report
needs them.

- **`maxDomNodes` is reported, not enforced.** The count is only knowable after parse5 has built the
  tree, so the parse is already paid for and every rule still runs on the result. It is not a silent
  pass — the scan exits 2 under the default `--on-error fail` — but it does not bound cost. Counting
  tags pre-parse would over-approximate and refuse legitimate documents, which is the more expensive
  error. The cost it stood in for, `rules x nodes` selector matching, is now bounded directly.

- **The per-resource deadline is checked between rules.** A synchronous parse or selector match
  cannot be interrupted from outside without a worker, so the ceiling bounds work not yet started.
  A consequence worth stating plainly: on a slow enough machine a document under every declared
  limit can cross the deadline, so *which rules run can depend on machine speed*. Unrun rules are
  now named as undecided, so this is visible rather than silent, but it is real.

- **Directory mode still cannot supply `_meta`, tools, or capabilities**, so 35 of 93 rules do not
  run there — including every `PANE-CSP` rule. This is by design (a source walker cannot tell a
  declaration from a README example) and is the single largest limitation on what a directory scan
  can conclude.

## 0.1.3

Closed four attacker-controlled bypasses, two false positives on conformant code, four
quadratic/ReDoS paths, and one rule family that was dead code.

## 0.1.0

First release. The published tarball was byte-identical to a local rebuild.

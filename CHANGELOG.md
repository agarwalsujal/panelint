# Changelog

Panelint reports properties of a content hash at a point in time. It never says a server "is safe."

## 0.2.0

**Every user of 0.1.x should upgrade.** This release closes forty ways a resource could be
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

1192 → 1321, across two new files. `test/silent-pass.test.ts` collects the cases above by the
property they share rather than by the module they live in: absence of a finding must never be
producible by the scanned party. `test/dos.test.ts` now exists: `fixtures/malicious/dos/cases.json` had named it since
0.1.0 and the entire resource-exhaustion control layer shipped with no executable test, which is how
`selectorIsTractable` rotted into dead code unnoticed. It found two real bugs on its first run.

Two guards added in the second round are worth naming, because both were written after the defect
they catch was verified to slip past the existing suite: a tripwire that derives the CLI's
registered flag set from source and fails on any imperative sentence naming a flag that is not in
it, and a check that `docs/DESIGN.md` §10 names every `LIMIT_KEYS` entry. Each was confirmed to go
red against the real defect before being kept.

### A second audit round — thirteen more silent passes

Found by a second adversarial pass over the tree the first round produced, and every one measured
as an exit-1 → exit-0 transition before the fix and after it.

- **`opacity:var(--o)` produced no carrier at all.** Every hidden-content predicate compares a
  declared string to a literal, and a value written through a custom property matches none of them —
  so `:root{--o:0}` two lines above the rule hid the payload with nothing anywhere signalling a
  problem. Browsers have substituted custom properties at computed-value time since 2016.
  `display:var(--d)` behaved the same. Values are now resolved along the ancestor chain, which is
  where `:root` lives. What genuinely cannot be reduced — `calc()` arithmetic, `env()`, an unknown
  variable with no fallback — is reported as `UNDECIDED_CASCADE` rather than read as absent.

- **A declaration inside a nested at-rule was never bound.** 0.2.0 fixed rule-in-rule nesting;
  `.s { color:#333; @media screen { opacity:0 } }` is the other legal shape, and the walker
  dispatched on `rule` and `atrule` only, so postcss handed the declaration over and it went on the
  floor. Bare declarations under a nested at-rule now bind to the parent selector.

- **An unparseable `<style>` block emitted a note and continued.** The 0.2.0 notes claim
  `INPUT_DEGRADED` covers this; it only fired when `buildStyleIndex` itself threw, and a block
  postcss cannot parse is caught *inside* it. Deleting one `}` took every CSS-dependent rule to an
  empty cascade at exit 0. The prefix up to the last complete rule is now recovered — which is
  roughly what a browser keeps — every node is marked undecided, and the diagnostic is
  `INPUT_DEGRADED`, which counts as truncation.

- **One NUL byte in the first 4 KB removed a file from the scan.** The binary heuristic refused the
  whole file, so `<!--\0-->` prepended to a template produced `resolved 0 of 1` and a diagnostic
  claiming the content was "not statically resolvable" — when parse5 reads it identically to the
  original. A NUL in a block comment did the same to a `.js` file Node still executes. Detection is
  now proportional to control-byte density, and NULs are replaced rather than used to refuse the
  read. A genuine binary is still refused, and now says so.

- **Two candidate caps truncated from the front.** `MAX_INLINE_LITERALS` and
  `MAX_DECLARATION_SITES` fill in walk order, which the scanned tree chooses, so 16 decoy literals
  or 32 decoy files evicted the real declaration — and the report still said "all were scanned".
  Both now emit `LIMIT_EXCEEDED`, which forces exit 2.

- **A refused config silently became no config.** `loadConfig` discards every key when the file
  names a CLI-only one, including the operator's own severity raises, and nothing checked `fatal`.
  Adding one key to a config took a gating scan to exit 0. A refused config is now a scan error.

- **Config and baseline diagnostics never reached the report.** `CONFIG_KEY_REJECTED` is the loudest
  signal this tool produces — a scanned tree shipping `{"command": …}` is asking the scanner to
  execute something — and it was computed and dropped in all three formats.

- **Baseline containment did not cover capture mode.** The guard required a directory target, and
  capture replay is the mode the Action documents for CI, so a baseline committed beside the capture
  was honoured. Containment now applies to both the capture's directory and the working directory.

- **`maxScriptBytes` suppressed ten rules with no diagnostic.** Every other ceiling calls
  `checkLimit`; this one set `ast: null`, which the rules correctly report as undecided — and
  undecided notes never reach the exit code. A 2 MB comment took a hostile script to exit 0.

- **Capture replay had no tool-reference discovery.** `resources/list` is not the complete set
  (`apps.mdx` L395), and stdio gained that sweep in this release; replay did not, so the same server
  scanned from a capture reported `NO_RESOURCES_FOUND` at exit 0.

- **`INPUT_DEGRADED` rendered as a SARIF `note`.** `scanWasTruncated` counts it as truncation, but
  the severity mapping named only `LIMIT_EXCEEDED`, so a degraded scan reported
  `executionSuccessful: false` while its explanation rendered where GitHub shows nothing.

- **A pruned subtree was not reported.** `dist/` and `build/` are on the deny list and are exactly
  where a TypeScript server's compiled entry point lives, so a scan printed `resolved 0 of 0` and
  read as a complete scan of a repository with no app resources.

### False positives on conformant code

Both of these fired on ordinary, correct markup. That is the most expensive error this project can
make, and neither was caught by a test.

- **An ordinary toast gated the build.** `\byou (must|should|will|are to|need to)\b` sat in the
  same list as `SYSTEM:` and `ignore previous instructions`, and was tested *before* the fade-in
  demotion could run — so `.toast{opacity:0;transition:opacity .3s}` carrying "You must confirm your
  email address" produced a gate-eligible HIGH at the default threshold. The pattern list is now
  split by who the text addresses. Phrasing that only makes sense as an instruction to a model still
  returns HIGH before any demotion, so adding a `transition` cannot launder a real payload.

- **`<noscript>` content was scanned as a live DOM.** parse5 was given `scriptingEnabled: false`
  with no reason recorded, so it parsed `<noscript>` children as elements and a fallback
  `<form action="https://…">` — the entire point of the tag — was reported as `PANE-EXFIL-001` at
  CRITICAL/CERTAIN. The same document also reported `PANE-HIDDEN-012` saying that content is not
  rendered, so the report contradicted itself. An MCP App renders in an iframe the specification
  requires to carry `allow-scripts`, so the scripted parse is now the one modelled.

### Documentation that was untrue

- `checkLimit` built its remedy sentence by kebab-casing the limit key, so eleven diagnostics told
  operators to pass `--max-dom-nodes`, `--max-resource-bytes` and nine more. **None has ever existed
  on any command.** The sentences now state the consequence instead, and a test derives the
  registered flag set from the CLI source and fails on any imperative sentence naming a flag that is
  not in it.
- `docs/DESIGN.md` §10 documented 8 of the 11 limits and named one of the fictional flags.
- `docs/ACTION.md` claimed fork pull requests skip the SARIF upload. Nothing implemented that, and
  the premise looks wrong — `upload-sarif` does not use the endpoint that requires
  `security-events: write`. The claim is corrected and the behaviour left alone pending a measured
  fork-PR run.
- `CLI_ONLY_KEYS` claimed to cover resource ceilings and listed only the eleven `Limits` keys;
  thirteen other ceiling knobs were absent.

### A third round — defects the second round's own fixes introduced

Each fix above was re-attacked by an independent pass. Nine more defects fell out, and several were
introduced by the repair rather than surviving it. They are listed because the pattern is the point:
a fix to a silent-pass class is itself a place silent passes appear.

- **Route (c) kept the first-match-wins shape route (b) had just lost.** The literal-read resolver
  returned on the first `readFileSync("…")` that resolved. Adding
  `const pkg = JSON.parse(readFileSync("package.json"))` above the template read took a gating
  finding to zero at exit 0, while the report said `resolved 1 of 1` and printed `package.json` as
  the app resource. Reading a config file before a template is also how most Python and Node servers
  are written, so this was a systematic false negative as well as a bypass.

- **Two candidate caps truncated from the front of the file.** `MAX_INLINE_LITERALS` collected every
  literal and then kept the first sixteen — so sixteen decoys above the real template pushed it out
  again, at exit 0, with the report claiming "all were scanned". `MAX_DECLARATION_SITES` had the
  same shape with decoy files. Both now emit `LIMIT_EXCEEDED`.

- **The baseline guard and the baseline loader resolved the same string differently.** The guard
  resolved `--baseline b.json` against the working directory; the loader resolved it against the
  scan root. A security control and the thing it guards must not disagree about which file they
  mean. Resolved once now, and the working directory is a containment root in directory mode too,
  not only for captures.

- **Custom-property resolution was winner-take-all** inside a module whose entire doctrine is
  additive-only. It collapsed the candidate set to one value with no specificity, no `!important`
  and no layer ordering, which brought the `@layer` evasion straight back. It now returns the set of
  values a property could take and a carrier fires if any member matches, which is the posture
  `candidatesFor` already had.

- **The resolver was an unbounded denial of service.** Cost was `candidates ^ depth`: 1.9 KB of CSS
  ran for **137 seconds**, exceeding `perResourceMs` twenty-seven times over, because a cooperative
  deadline cannot interrupt a synchronous recursion. Now bounded by a step budget — the same
  measured shape as `:has()`, refused before the work rather than during it.

- **Three spellings of `var()` that browsers resolve and Panelint did not**: `VAR(--o)` (CSS
  function names are ASCII case-insensitive), `var(/**/--o)` (comments are removed at tokenization),
  and `\76 ar(--o)` (an escaped ident). The first two now resolve; the third is treated as
  unevaluable, which marks the node undecided rather than reading it as absent.

- **The fade-in demotion never checked what was being animated.** `transition:color 0s` on a node
  hidden at `opacity:0` — a transition that does not touch the hiding property — and
  `animation-name:none`, which declares no animation at all, both took a gate-eligible HIGH to LOW
  at exit 0. The demotion now requires the animated property to be one the node actually declares.

- **"The cascade could not be read here" reached exit 0.** `UNDECIDED_CASCADE` and
  `SELECTOR_SKIPPED` were not counted as truncation, so `opacity:calc(0)` and the documented
  `:read-write` case both scanned clean. Both now count. Neither code occurs even once across the 24
  real `mcp-app.html` files in the reference corpus, so this costs conformant servers nothing.

- **`@starting-style` bound as a resting state.** It is the one at-rule that by definition describes
  the value an element transitions *from*, so binding it reports a fade-in's start frame as a
  hidden-content carrier. Added to the unmodelled set.

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

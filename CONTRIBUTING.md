# Contributing to Panelint

The rule catalog is the product. Most valuable contributions are rules, corrections to rules, or
evidence that a rule is wrong.

---

## The one rule about rules

**A finding on conformant code is a bug of the highest severity we have.**

A scanner that flags correct code gets uninstalled, and then nothing is checked. False-positive rate
is a security property of this tool, not a quality-of-life one — [SECURITY.md](SECURITY.md) §3.

Five patterns are permanently guarded, because each looks like a textbook vulnerability and each is
**mandated or emitted by the specification or the official SDK**:

| Pattern | Why it must never fire |
|---|---|
| `'unsafe-inline'` in `script-src` / `style-src` | Part of the spec's mandated default CSP |
| `allow-scripts` + `allow-same-origin` | Explicitly required for the sandbox proxy |
| `_meta["ui/resourceUri"]` present | The SDK's `registerAppTool` **dual-writes it for you** |
| `csp_evaluator`'s default check list | It flags both `'unsafe-inline'` **and** `'self'` in `script-src`, both of which the mandated policy contains |
| List-level-only `_meta.ui` (`PANE-SPEC-010`) | Idiomatic `registerAppResource` usage populates the list-level value and leaves the read-level one absent — that absence is not divergence |

`test/never-fire.test.ts` asserts all five. **A PR that makes any of them fire does not land**,
regardless of what else it does.

## Proposing a rule

Open an issue before writing code. It needs:

1. **The payload.** Concrete HTML or `_meta` that a real attacker would ship. Not a description.
2. **What it achieves** — which threat class in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md), and
   what the attacker gets.
3. **Why existing rules miss it.** If an existing rule *should* have caught it, fix that rule
   instead — a sharper rule beats a new one.
4. **The false-positive story.** What legitimate code has this shape? This is the question that
   kills most proposals, and answering it honestly is the most useful thing in the issue.
5. **Class, severity, and confidence**, with reasoning. See the classification model in
   [docs/RULES.md](docs/RULES.md).

### Before you claim `CERTAIN`

`CERTAIN` means *cannot be wrong*. Panelint does not compute styles, so any rule reading declared
CSS caps at `HIGH` — a declared `display:none` can be overridden by cascade order, specificity,
`!important`, or a media query. `CERTAIN` is for facts that survive any rendering: schema
validation, string equality, the presence of an element or attribute.

### Before you claim a rule is gate-eligible

Gating is one formula, and it is not negotiable per rule:

```
confidence ∈ { CERTAIN, HIGH }  ∧  class ≠ INFO  ∧  ¬experimental  ∧  severity ≥ --fail-on
```

If your rule would break a build, it must be something you would be comfortable breaking a
stranger's build over at 5pm on a Friday.

## Landing a rule

Every rule ships with all four:

- **The implementation**, a pure function in `src/rules/<family>/`.
- **A positive fixture** in `fixtures/malicious/` — `test/malicious.test.ts` fails if any rule has no
  positive case.
- **A negative fixture**, the nearest legitimate code that must *not* fire — one **per rule**, not
  per correction. A rule with three documented corrections still needs exactly one legitimate-code
  fixture proving the current, corrected behaviour doesn't fire; the corrections are recorded in
  prose, not multiplied into extra fixture files.
- **A row in [docs/RULES.md](docs/RULES.md)** and a row in
  [docs/SPEC-COVERAGE.md](docs/SPEC-COVERAGE.md). `test/registry-docs.test.ts` **parses the
  RULES.md tables directly** and asserts the registry and the catalog agree on id, class, severity,
  and confidence — a table row edited without the matching code change, in either direction, is a
  failing build, not a silent drift.

Then run it against the reference corpus. **If it fires on a reference server, it is not ready.**
Five of the rules in the current catalog were caught this way before they ever shipped; the results
are recorded in [docs/RULES.md § Measured false-positive pass](docs/RULES.md).

## Rule IDs are permanent

SARIF `rules[].id` is a public contract — the census directory keys on it and disclosure emails cite
it.

- **IDs are never reused.** A retired rule keeps its ID with `status: retired`.
- Severity or class changes are **minor-version events**, recorded in the catalog changelog.
- Renumbering an existing rule is a breaking change. Don't.

## Reporting a false positive

The most valuable issue you can file. Include the resource (or a minimal reproduction), the rule ID,
and the Panelint version. The rule gets fixed or demoted, the correction is recorded in the rule
entry, and the case joins the fixture set so it cannot regress.

You do not need to argue that it is a false positive. Send the code; we will work it out.

## Working on the scanner itself

Panelint parses hostile input by design and, in live mode, **spawns the server it is scanning**.
Two consequences for contributors:

- Treat every resource as attacker-controlled. New parsing code needs a limit
  (`src/limits.ts`) and a `fixtures/malicious/` case that exercises it.
- Never log resource content, decoded blobs, `_meta` values, or the environment passed to a spawned
  server. A hidden-text finding must not reproduce the injection payload into a CI log.
- **No recursive traversal helpers in Panelint's own code.** All traversals — the node walk, the
  script-index build, anything over a DOM or AST — use an explicit stack. Measured: a 200 KB
  deeply-nested `<div>` payload takes `parse5` 3.9 s at O(depth²); one convenience recursion added
  later in code we own reintroduces that class of crash where no dependency boundary exists to catch
  it. See [docs/DESIGN.md](docs/DESIGN.md) §10.
- **Every third-party call that recurses is wrapped in `RangeError` containment** —
  `parse5.parse`, `acorn-walk.simple`/`full`, `domutils.textContent`, `css-select` compile and
  match, `postcss` parse. A stack overflow inside a dependency becomes a per-resource diagnostic,
  never an exit-code-2 crash of the whole scan and never a silent zero-findings pass.
- **`String(error)` must never reach an output channel.** Measured: postcss's
  `CssSyntaxError.toString()` embeds a source code frame reproducing the offending CSS verbatim —
  under directory mode that CSS can be the contents of an arbitrary file the resolver read. Catch
  the specific error type, extract only the fields a finding needs (message, location), and discard
  the rest. Never let a caught error's default string form flow into a finding, a log line, or a
  diagnostic.

See [docs/DESIGN.md](docs/DESIGN.md) §10.

## Development

```bash
npm ci                  # never `npm install` in CI — the lockfile is the control
npm test
npm run test:corpus     # the reference-corpus gate
npm run test:never-fire # the five poisoned-pattern guards
```

Dependencies are **exact-pinned** and the lockfile is committed. A lockfile diff with an off-registry
`resolved` URL needs a review note explaining it. Attacker A4 in our own threat model is a supply
chain compromise; a scanner that ships one is worse than no scanner.

## Licence

Apache-2.0. Contributions are accepted under the same terms.

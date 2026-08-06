# Panelint — Goals, Non-goals, and Requirements

The stable contract the rest of the documentation cites. Product planning, competitive analysis, and
scheduling live outside this repository.

---

## 1. Problem

MCP servers can render interactive HTML inside AI assistants. The MCP Apps extension (SEP-1865,
Final since 2026-01-28) requires servers to declare a CSP and permissions, and requires hosts to
sandbox and enforce them.

**The specification defines requirements and provides no way to verify compliance.**

This matters because of where the HTML lands. A browser renders untrusted HTML into a window the
user knows is untrusted — there is a URL bar, a padlock, an origin. An AI assistant renders it into
a conversation the user believes is entirely the assistant's own output. Every trust signal the web
spent twenty years building is absent.

The failure mode that matters is not "a reputable vendor turns malicious." It is, in descending
likelihood: an honest server rendering **hostile data**; an honest server with a **forgotten
control**; and **supply-chain compromise**. See [THREAT-MODEL.md](THREAT-MODEL.md).

## 2. Users

| User | Job to be done | Deliverable |
|---|---|---|
| **MCP server developer** | "Don't let me ship a hole" — and "why is my app blank" | CLI + CI action, runs in seconds, zero config |
| **Platform / security engineer** | "Is this server safe to enable for 500 employees?" | Report per server, with severity and evidence |

**The primary user for v1 is the server developer.** The feedback loop is immediate, distribution is
free, and no sale is required.

## 3. Goals

**G1.** Every requirement in SEP-1865 that is statically checkable has a rule. Substantiated
rule-by-rule in [SPEC-COVERAGE.md](SPEC-COVERAGE.md) — an assertion without that matrix is not a goal,
it is a hope.

**G2.** **Zero false positives on the specification's own reference example servers.**
Non-negotiable — a scanner that flags conformant code is discarded on first run.

**G3.** Sub-second scan of a typical server. It must be cheap enough to run on every commit.

**G4.** Findings are separated into *spec violation*, *risky-but-legal*, and *heuristic*, always, in
every output format.

**G5.** A public scan of the known server population, published with full methodology.

## 4. Non-goals

**N1. Judging vendor intent.** Panelint reports properties of a content hash at a point in time. It
never issues a verdict about a company, and never says a server "is safe."

**N2. Verifying host behaviour.** Whether a host enforces the CSP it was handed, or which sandbox
flags it sets, cannot be determined from a server. Out of scope, and stated plainly in every report.
This non-goal does real work — several otherwise-attractive rules are limited by it.

**N3. Rendering or executing app code.** v1 is static. A payload can be base64-encoded and injected
at runtime, invisible to static analysis. Documented, not solved.

**N4. Semantic prompt-injection classification.** Detecting *hidden* content is structural and in
scope. Judging whether text *is* an injection attempt is probabilistic and stays advisory.

**N5. Being a general MCP scanner.** Several tools already cover server-level supply chain and tool
poisoning. Panelint covers the UI surface only, and should compose with them.

## 5. Requirements

### Must have (v1)

| ID | Requirement |
|---|---|
| R1 | Scan a local directory, resolving `ui://` resources **where statically resolvable**, and report the resolved/declared ratio |
| R2 | Scan a live server over stdio, and replay a recorded capture |
| R3 | Validate `_meta.ui.*` against the published JSON Schema, honouring `additionalProperties: false` |
| R4 | Evaluate declared CSP domains for over-breadth |
| R5 | Detect DOM-present, human-invisible content — the injection-carrier check |
| R6 | Report use of the model-context write surface — `ui/message`, `ui/update-model-context`, `ui/download-file` |
| R7 | Output human-readable text, JSON, and SARIF |
| R8 | `--fail-on <severity>` exit codes for CI |
| R9 | Record a content hash per scanned resource |

### Deferred

HTTP transport · `PANE-MIMIC` (behind `--experimental`) · `PANE-CONTEXT-005` taint analysis ·
rendered-DOM scanning · LLM-based injection classification · host conformance testing ·
app-provided-tools rules (draft spec, not ratified).

## 6. The two risks that would discredit the tool

Recorded here because they outrank every feature.

| Risk | Mitigation |
|---|---|
| **A rule fires on conformant code** | The reference-corpus gate, plus four hard-guarded never-fire patterns. See [CONTRIBUTING.md](../CONTRIBUTING.md) |
| **A finding is reported more confidently than the evidence supports** | Three-axis classification, an `undecided` channel for rules that cannot answer, and N2 applied strictly — a claim that depends on unenumerated host behaviour is labelled as such, not asserted |

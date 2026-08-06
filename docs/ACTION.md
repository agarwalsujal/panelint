# The Panelint GitHub Action

Runs Panelint in CI and puts findings in the Security tab.

> **Not usable until Panelint is published to npm.** The action installs
> `panelint@<version>` from the registry. Until the first publish, run the CLI directly.

---

## 1. Minimal use

```yaml
name: Panelint
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # required for the SARIF upload

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: agarwalsujal/panelint@v1
```

## 2. The limitation to read before you trust a green check

**Directory mode skips 35 of 93 rules**, including *every* `PANE-CSP` rule.

A directory scan reads source files. It cannot supply `_meta.ui`, the tool list, or server
capabilities, because those come from a running server rather than from a file on disk. The rules
that depend on them do not run, and the report says so — `28 rules skipped: this scan mode cannot
supply meta`, and two more lines like it.

So a clean directory scan is **not** a CSP audit, and the job summary states that in the run where
someone will read it.

To cover the other 35, record a capture once and replay it in CI:

```yaml
      - uses: agarwalsujal/panelint@v1
        with:
          capture: panelint.capture.json
```

Recording spawns your server, so it happens on a developer machine, not on a runner:

```bash
panelint capture --allow-spawn -o panelint.capture.json -- node ./dist/server.js
```

Commit the capture. It is a recording of what your server served, and refreshing it is a reviewable
diff — which is the point. The action never spawns anything.

## 3. Inputs

| Input | Default | What it does |
|---|---|---|
| `path` | `.` | Directory to scan. Also passed as `--path-prefix` |
| `capture` | — | Capture file to replay instead of scanning a directory |
| `fail-on` | `high` | `critical` \| `high` \| `medium` \| `low` \| `info` |
| `on-error` | `fail` | Whether a scan *error* fails the job |
| `config` | — | Config file path |
| `baseline` | — | Baseline file of accepted findings |
| `experimental` | `false` | Adds experimental rules to the report. They can never gate |
| `upload-sarif` | `true` | Upload to code scanning |
| `sarif-file` | `panelint.sarif` | Where the SARIF is written |
| `category` | `panelint` | Code scanning category; give concurrent runs distinct values |
| `version` | pinned | npm version to install |
| `node-version` | `22` | Node for the scan. **This calls `setup-node`,** which affects later steps |
| `working-directory` | `.` | Directory to run from |

**Outputs:** `sarif-file`, `exit-code` (0 clean, 1 gated, 2 scan error), `findings`.

### Inputs that deliberately do not exist

These are not oversights. Each would hand control of the scan to something that should not have it:

| Flag | Why there is no input for it |
|---|---|
| `--allow-spawn` | Would run a fork PR's server code on your runner |
| `--http` | Would let a workflow input name any URL, including `169.254.169.254` |
| `--trust-inline-suppressions` | Would let the scanned bytes switch off their own findings |
| `--allow-repo-config` | Would let a config file in the tree lower severities on the run judging it |

[test/action.test.ts](../test/action.test.ts) asserts the composed command line cannot contain any
of them, and that no `${{ }}` expression is interpolated into a shell body — an input wired to a
pull request title would otherwise be command execution.

## 4. Path prefixes

SARIF file paths are relative to the **scan root**. GitHub resolves them against the **repository
root**. When those differ, alerts land on paths that do not exist:

```yaml
      - uses: agarwalsujal/panelint@v1
        with:
          path: packages/my-server      # --path-prefix is applied automatically
```

Running the CLI by hand, pass it yourself:

```bash
panelint scan packages/my-server --format sarif --path-prefix packages/my-server > panelint.sarif
```

## 5. Permissions and repository types

- `security-events: write` is required for the upload. Without it the upload step fails.
- **Private repositories need GitHub Advanced Security** for code scanning. Without it, set
  `upload-sarif: false` — the exit code and the job summary still gate the build.
- **Fork pull requests** get a read-only token, so the upload is skipped. Configure the scan on
  `pull_request_target` only if you understand what that exposes; the safer pattern is to let fork
  PRs gate on the exit code alone.

## 6. Ordering

The SARIF upload runs under `always()`, and the exit code is re-raised in a later step. Uploading
only on success would mean findings never reach the Security tab on exactly the runs that have
findings.

## 7. What the action does not tell you

Panelint reports properties of a content hash at a point in time. A green check means the bytes
scanned in that run carried no finding at or above your threshold. It is not a statement that your
server is safe, and the report says so in every format.

See [GOALS.md](GOALS.md) §4 for the non-goals this follows from.

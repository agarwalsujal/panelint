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
- **Fork pull requests: this document previously claimed the upload is skipped. It is not, and
  nothing in the action ever skipped it.** That sentence was wrong for four releases, and the
  correction is being written rather than the behaviour changed, because the underlying question is
  not settled. `github/codeql-action/upload-sarif` does not call the public
  `POST /code-scanning/sarifs` endpoint that requires `security-events: write`; it calls
  `PUT /repos/:owner/:repo/code-scanning/analysis`, which by GitHub's own guidance does not require
  write permission for pull requests. If that holds, the upload **succeeds** on a fork PR and adding
  a skip would delete results from the run where they matter most.

  We have not measured it. Until someone records a real fork-PR run, treat the outcome as unknown:
  either the upload succeeds, or the step fails loudly with a 403. It will not fail silently, and
  the exit code gates the build either way. If a 403 is what you see, set `upload-sarif: false` and
  gate on the exit code.
- `pull_request_target` runs with the base repository's secrets and a writable token. Configure the
  scan there only if you understand what that exposes — in particular, `actions/checkout` defaults
  to the **base** ref on that event, so the safe-looking configuration scans already-merged code and
  always passes, and the configuration that actually scans the PR requires
  `ref: github.event.pull_request.head.sha`, which is the classic pwn-request. The safer pattern is
  to let fork PRs gate on the exit code alone.

## 6. Ordering

The SARIF upload runs under `always()`, and the exit code is re-raised in a later step. Uploading
only on success would mean findings never reach the Security tab on exactly the runs that have
findings.

## 7. What the action does not tell you

Panelint reports properties of a content hash at a point in time. A green check means the bytes
scanned in that run carried no finding at or above your threshold. It is not a statement that your
server is safe, and the report says so in every format.

See [GOALS.md](GOALS.md) §4 for the non-goals this follows from.

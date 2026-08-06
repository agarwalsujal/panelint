# Security Policy

Panelint is a security tool. Two distinct things live in this document, and conflating them is a
common failure:

1. **Reporting a vulnerability *in Panelint*** — §1
2. **What Panelint does with vulnerabilities it finds *in other people's servers*** — §2

---

## 1. Reporting a vulnerability in Panelint

Report privately via [GitHub Security Advisories](https://github.com/agarwalsujal/panelint/security/advisories/new).
Do not open a public issue.

Acknowledgement within 72 hours; a fix or a documented decision within 30 days.

### In scope

- **Scanner-as-attack-surface.** Panelint parses hostile input by design. Anything that turns a
  scanned resource into code execution, file write, or network egress on the scanning machine is a
  vulnerability in Panelint. Parser DoS (catastrophic backtracking, quadratic blowup, memory
  exhaustion on a crafted resource) counts.
- **Egress.** Panelint makes no network calls except to a live-scan target the user named. Any
  other outbound connection is a vulnerability.
- **A rule that can be trivially evaded.** If a payload defeats a `CERTAIN`-confidence rule by a
  semantically equivalent rewrite, that is a bug — report it as a security issue, not a feature
  request.
- **A rule that fires on conformant code.** False positives are treated as severity-bearing here,
  not cosmetic. See §3.

### Out of scope

- Findings Panelint reports about a third-party server — those go to that server's maintainers.
- Host behaviour. Whether Claude, VS Code, or any other host enforces the CSP it is handed is not
  something Panelint can determine or influence. See [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) §4.
- Missing detection of a payload class Panelint documents as out of scope (runtime-injected
  content, visual similarity, semantic injection judgement).

---

## 2. Disclosure policy for findings in third-party servers

Panelint scans public MCP servers and publishes a directory of results. Findings on named vendors
are not marketing material. This policy is fixed **before** scanning, not negotiated after.

### The rules

| Finding | Channel | Handling |
|---|---|---|
| `CRITICAL` or `HIGH` on an identifiable server | **Private email** to the maintainer | Per-server detail withheld until a fix ships or **90 days** elapse, whichever comes first |
| `MEDIUM` / `LOW` / `INFO` | **A public pull request that fixes it** | **No embargo.** These are lint findings, not vulnerabilities — treat them like any other drive-by fix |
| Aggregate statistics | Published with the census | Immediately, at any severity. "X% of servers declare a wildcard `connectDomains`" names no one |

**The channel is the policy.** Two severities, two mechanisms, and the split is deliberate:

- An embargoed private email is the right instrument for something that could hurt users. It is also
  slow by design, and a 90-day clock started during the census closes in **November**.
- A public PR that *fixes* a `MEDIUM` is not a disclosure at all — it is a contribution. It carries
  no embargo, needs no coordination, and typically merges in days. It is also strictly more useful
  to the maintainer than a report describing work they would have to do themselves.

Sending a `MEDIUM` CSP finding as a formal security disclosure is a category error that wastes a
maintainer's incident process on a lint fix, and it is the fastest way to make Panelint unwelcome.
**When you can just fix it, fix it.**

**A directory entry under embargo is published as `disclosure pending`, with the finding count
suppressed and the class withheld.** The entry's existence is not a secret; its content is. Hiding
the entry entirely would misrepresent the census as complete.

The 90-day clock starts when the report is delivered to a working contact, not when it is sent. If
no contact can be found after a documented good-faith attempt (SECURITY.md, security contact in
package metadata, repository maintainers, `security@` on the vendor's primary domain), the entry
stays embargoed and is marked `no contact found` rather than published.

### What a report contains

The exact resource URI, the `sha256` of the content scanned, the scan timestamp, the rule IDs, the
evidence, and the remediation. Nothing else — no severity inflation, no exploit narrative, no
deadline framed as a threat.

### What Panelint never publishes

- A verdict about a company. Panelint reports properties of a content hash at a point in time. It
  does not say a server "is safe" or "is malicious" — see [docs/GOALS.md](docs/GOALS.md) §3, N1.
- A working exploit against a live third-party server.
- Findings from a private or authenticated server. Panelint scans what is publicly resolvable.

### If you maintain a scanned server

Open an issue, or use the private advisory channel in §1. Two things are always honoured:

- **A false positive is our bug.** Send the resource; the rule gets fixed or demoted, and the
  correction is recorded in the rule entry.
- **A fixed finding is re-scanned on request**, ahead of the normal schedule, and the directory
  entry updated with the new hash.

---

## 3. Why false positives are handled as security issues

A scanner that flags conformant code gets uninstalled, and then nothing is checked. The
false-positive rate is therefore a security property of this tool, not a quality-of-life one.

Two specific patterns are permanently guarded against, because both look like textbook
vulnerabilities and both are **mandated by the MCP Apps specification**:

- `'unsafe-inline'` in `script-src` / `style-src` — part of the spec's mandated default CSP.
- `allow-scripts` + `allow-same-origin` on the sandbox proxy iframe — explicitly required.

Any change that causes a finding on either pattern is a release blocker. See
[docs/SPEC-REFERENCE.md](docs/SPEC-REFERENCE.md) §3.1 and §3.3.

---

## 4. Point-in-time honesty

The MCP Apps protocol has **no integrity mechanism** — no signature, hash, or version field exists
anywhere in the resource schema (verified against `schema.json`; see
[docs/SPEC-REFERENCE.md](docs/SPEC-REFERENCE.md) §6).

A resource can change between a scan and its execution with no signal to anyone. Every Panelint
finding is bound to a `sha256` and a timestamp, and every report says so. No output from this tool
should ever be read as a claim about what a server will serve next.

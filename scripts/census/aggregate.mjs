/**
 * Step 4 of the census: turn per-repository findings into something publishable.
 *
 * Two outputs, and the split between them is the disclosure policy:
 *
 *   - `docs/CENSUS.md` — **tracked and publishable.** Aggregate statistics that
 *     name nobody. SECURITY.md §2: aggregate statistics publish immediately at
 *     any severity, because they identify no one.
 *   - `census/findings/BY-REPOSITORY.md` — **gitignored.** The per-repository
 *     table, which is disclosure material, not blog material. A CRITICAL or
 *     HIGH finding on an identifiable server goes to that server privately
 *     first, and per-server detail is withheld until a fix ships or 90 days
 *     elapse.
 *
 * The script refuses to write a repository name into the tracked file. That is
 * enforced below rather than left to whoever edits this next.
 *
 * Run: node scripts/census/aggregate.mjs
 */

import { readdirSync, readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const FINDINGS = join(ROOT, 'census', 'findings');
const CORPUS = join(ROOT, 'census', 'raw', 'corpus.json');
const PUBLIC_OUT = join(ROOT, 'docs', 'CENSUS.md');
const PRIVATE_OUT = join(FINDINGS, 'BY-REPOSITORY.md');

if (!existsSync(FINDINGS)) {
  console.error(`no findings at ${FINDINGS} — run scripts/census/scan.mjs first`);
  process.exit(2);
}

const corpus = existsSync(CORPUS) ? JSON.parse(readFileSync(CORPUS, 'utf8')) : null;

const files = readdirSync(FINDINGS).filter((f) => f.endsWith('.json'));
if (files.length === 0) {
  console.error('no per-repository reports to aggregate');
  process.exit(2);
}

// ---------------------------------------------------------------------------
// Load
// ---------------------------------------------------------------------------

/**
 * The gate formula from docs/RULES.md, restated here rather than read off the
 * `gating` flag in each report.
 *
 * That flag records whether a finding gated at the `--fail-on` the scan
 * happened to run with, so it answers a question about the scan's arguments.
 * The census needs a fixed question: would this finding break a build at the
 * default threshold. ROADMAP kill criterion 3 keys on **gate-eligible
 * CRITICAL or HIGH**, and it was rewritten once already because the previous
 * wording could never fire. Deriving it here keeps the census independent of
 * how the scan was invoked.
 */
const GATE_SEVERITIES = new Set(['CRITICAL', 'HIGH']);
const gateEligible = (f) =>
  f.class !== 'INFO' &&
  (f.confidence === 'CERTAIN' || f.confidence === 'HIGH') &&
  f.experimental !== true &&
  GATE_SEVERITIES.has(f.severity);

const rows = [];
let scanFailures = 0;

for (const file of files) {
  const entry = JSON.parse(readFileSync(join(FINDINGS, file), 'utf8'));
  if (entry.scanFailed) {
    scanFailures += 1;
    continue;
  }
  const r = entry.report;
  const findings = r.findings ?? [];
  // The JSON envelope nests the header under `scan`, not `header`.
  const scan = r.scan ?? {};

  rows.push({
    repo: entry.repo,
    resolved: scan.resolvedResources ?? 0,
    declared: scan.declaredResources ?? 0,
    findings,
    gating: findings.filter(gateEligible),
    diagnostics: r.diagnostics ?? [],
  });
}

const withResources = rows.filter((r) => r.resolved > 0);

// ---------------------------------------------------------------------------
// Aggregate
// ---------------------------------------------------------------------------

const bySeverity = {};
const byRule = {};
const byClass = {};

for (const row of rows) {
  for (const f of row.findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
    byClass[f.class] = (byClass[f.class] ?? 0) + 1;
    byRule[f.ruleId] ??= { total: 0, repos: new Set(), gating: 0, class: f.class, severity: f.severity };
    byRule[f.ruleId].total += 1;
    byRule[f.ruleId].repos.add(row.repo);
    if (gateEligible(f)) byRule[f.ruleId].gating += 1;
  }
}

const reposWithGating = rows.filter((r) => r.gating.length > 0);
const gatingRate = rows.length > 0 ? (reposWithGating.length / rows.length) * 100 : 0;

const ruleTable = Object.entries(byRule)
  .map(([id, v]) => ({
    id,
    class: v.class,
    severity: v.severity,
    total: v.total,
    repos: v.repos.size,
    repoPct: rows.length > 0 ? (v.repos.size / rows.length) * 100 : 0,
    gating: v.gating,
  }))
  .sort((a, b) => b.repos - a.repos || b.total - a.total);

const pct = (n, d) => (d > 0 ? `${((n / d) * 100).toFixed(1)}%` : 'n/a');

// ---------------------------------------------------------------------------
// The publishable file. Names nobody.
// ---------------------------------------------------------------------------

const publicDoc = `# The MCP Apps census

**${rows.length} repositories scanned.** Aggregate results only — this document names no server and
no vendor. Per-repository findings are handled under the disclosure policy in
[SECURITY.md](../SECURITY.md) §2.

Generated by \`scripts/census/aggregate.mjs\`. Every number here is reproducible from the scripts in
[scripts/census/](../scripts/census/).

---

## 1. Method, including what it misses

The corpus is the **union of two GitHub code searches**: the literal
\`text/html;profile=mcp-app\`, and \`registerAppResource\`. Neither is a superset of the other — a
server built on the official SDK may never write the MIME literal, and a hand-rolled server never
calls the SDK helper. Searching one alone undercounts along an axis invisible from the results.

${
  corpus
    ? `That search found **${corpus.repoCount} distinct repositories**${
        corpus.truncatedPartitions?.length
          ? `, and it is a **floor rather than a count**: ${corpus.truncatedPartitions.length} query partitions hit GitHub's 1000-result-per-query ceiling, the largest reporting ${Math.max(
              ...corpus.truncatedPartitions.map((t) => t.total),
            )} total matches against 1000 retrieved`
          : ''
      }.`
    : ''
}

**This scan is directory mode, and that bounds every number below.**

| Limitation | Consequence |
|---|---|
| Directory mode cannot supply \`_meta.ui\`, the tool list, or capabilities | **35 of 93 rules never ran**, including every \`PANE-CSP\` rule |
| A build entry point is not what a server serves | Vite projects were scanned as source, not as the served bundle |
| A declaration in a README is not a declaration in code | Source-level scanning cannot tell them apart |
| Resources resolve only where statically resolvable | ${pct(withResources.length, rows.length)} of repositories had at least one resolvable \`ui://\` resource |

So this measures **what is in the source of public repositories**. It is not a measurement of what
running servers serve, and no number here should be read as one.

## 2. Coverage

| | |
|---|---|
| Repositories scanned | ${rows.length} |
| With at least one resolvable \`ui://\` resource | ${withResources.length} (${pct(withResources.length, rows.length)}) |
| Resources resolved | ${rows.reduce((n, r) => n + r.resolved, 0)} |
| Resources declared but not statically resolvable | ${rows.reduce((n, r) => n + Math.max(0, r.declared - r.resolved), 0)} |
| Scans that failed outright | ${scanFailures} |

## 3. Findings by class

| Class | Findings |
|---|---|
${['SPEC', 'SCHEMA', 'RISK', 'INFO']
  .filter((c) => byClass[c])
  .map((c) => `| ${c} | ${byClass[c]} |`)
  .join('\n')}

By severity:

| Severity | Findings |
|---|---|
${['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
  .filter((s) => bySeverity[s])
  .map((s) => `| ${s} | ${bySeverity[s]} |`)
  .join('\n')}

## 4. The number that decides whether this tool was worth building

A finding only breaks someone's build if it is **gate-eligible**: confidence \`CERTAIN\` or \`HIGH\`,
class not \`INFO\`, not experimental, at or above the threshold.

> **${reposWithGating.length} of ${rows.length} repositories (${gatingRate.toFixed(1)}%) produced at least one gate-eligible finding.**

The project's own kill criterion said to stop if that number came in under ~5% — a well-evidenced
"this ecosystem is fine" being a genuine contribution and a cheaper one. ${
  gatingRate < 5
    ? '**It came in under 5%.** That result stands as published, and it argues the problem is more theoretical than the thesis assumed.'
    : 'It came in above that line.'
}

## 5. Per-rule incidence

Rules that fired on the largest share of repositories. A rule firing very widely is a signal about
the rule as much as about the ecosystem — a high-incidence \`RISK\` rule is a candidate for
demotion, and that is the point of measuring.

| Rule | Class | Severity | Repositories | % of corpus | Findings | Gate-eligible |
|---|---|---|---|---|---|---|
${ruleTable
  .slice(0, 25)
  .map(
    (r) =>
      `| \`${r.id}\` | ${r.class} | ${r.severity} | ${r.repos} | ${r.repoPct.toFixed(1)}% | ${r.total} | ${r.gating} |`,
  )
  .join('\n')}

${ruleTable.length > 25 ? `\n${ruleTable.length - 25} further rules fired at lower incidence.` : ''}

Rules that fired on **nothing**: ${93 - ruleTable.length} of 93. That is not automatically good news —
it can mean the pattern is absent from the ecosystem, or that directory mode could not reach it.

## 6. Reproducing this

\`\`\`bash
node scripts/census/search.mjs      # build the corpus from two code searches
node scripts/census/fetch.mjs       # download the trees
node scripts/census/scan.mjs        # scan each one
node scripts/census/aggregate.mjs   # regenerate this file
\`\`\`

Raw corpus, downloaded trees, and per-repository findings are deliberately not in this repository.
They name third parties, and they are governed by [SECURITY.md](../SECURITY.md) §2.

---

Panelint reports properties of a content hash at a point in time. It issues no verdict about a
server or a vendor. Every number here describes public source code as it stood when the scan ran.
`;

// The guard. A repository name in the tracked file is a disclosure incident,
// so it is checked rather than trusted.
// Built from every file on disk, not from `rows` — `rows` drops scan failures,
// so a scan-failed repository's name was never even a candidate. And matched on
// word boundaries, case-insensitively, against the owner, the repo, the
// `owner/repo` pair and the `owner__repo` slug: the previous version checked
// `owner/repo` and `owner` but never the repo name alone, so a sentence naming
// `pdf-server` or `wiki-explorer-server` would have sailed through.
//
// Owner-only matching is skipped for very short names. GitHub allows
// one-character logins, and a bare-substring check on `a` blocks every write —
// a guard that fires on everything gets deleted rather than fixed.
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Words this document writes about the domain, which are also real repository
 * names.
 *
 * The corpus genuinely contains repositories called `mcp` and `mcp-app`, and
 * the document contains `text/html;profile=mcp-app` in its methodology section.
 * Matching a bare repository name against the prose therefore fires on the
 * document's own vocabulary and blocks every write.
 *
 * A guard that always fires gets deleted rather than fixed, so bare-name
 * matching skips these. The unambiguous `owner/repo` and `owner__repo` forms
 * are still checked for every repository without exception — those cannot occur
 * by accident, and they are what an actual leak would look like.
 */
const DOC_VOCABULARY = new Set([
  'mcp',
  'mcp-app',
  'mcp-apps',
  'mcp-server',
  'panelint',
  'census',
  'docs',
  'scan',
  'rules',
  'node',
  'json',
  'sarif',
  'html',
  'server',
  'servers',
  'ui',
]);

const always = new Set();
const bare = new Set();
for (const file of files) {
  const slug = file.replace(/\.json$/, '');
  const idx = slug.indexOf('__');
  if (idx < 0) continue;
  const owner = slug.slice(0, idx);
  const repo = slug.slice(idx + 2);
  if (!owner || !repo) continue;

  // Unambiguous. Always checked.
  always.add(slug);
  always.add(`${owner}/${repo}`);

  // Bare tokens, checked only when they are distinctive enough to mean
  // something. GitHub allows one-character logins.
  for (const token of [repo, owner]) {
    if (token.length >= 4 && !DOC_VOCABULARY.has(token.toLowerCase())) bare.add(token);
  }
}

const leaked = [...always, ...bare].filter((n) =>
  new RegExp(`\\b${escapeRe(n)}\\b`, 'i').test(publicDoc),
);
if (leaked.length > 0) {
  console.error(`REFUSING to write ${PUBLIC_OUT}: it contains repository names`);
  console.error(leaked.slice(0, 5).join(', '));
  process.exit(1);
}

writeFileSync(PUBLIC_OUT, publicDoc);

// ---------------------------------------------------------------------------
// The private file. Disclosure material.
// ---------------------------------------------------------------------------

mkdirSync(FINDINGS, { recursive: true });
const privateDoc = `# Census — per-repository findings

**Not for publication.** Disclosure material, governed by SECURITY.md §2: a CRITICAL or HIGH
finding on an identifiable server is reported to that server privately first, and per-server detail
is withheld until a fix ships or 90 days elapse.

Generated ${new Date().toISOString()}.

## Repositories with gate-eligible findings

| Repository | Gate-eligible | Rules |
|---|---|---|
${reposWithGating
  .sort((a, b) => b.gating.length - a.gating.length)
  .map(
    (r) =>
      `| ${r.repo.replace('__', '/')} | ${r.gating.length} | ${[...new Set(r.gating.map((f) => f.ruleId))].join(', ')} |`,
  )
  .join('\n')}

## Disclosure queue

Repositories with a CRITICAL or HIGH gate-eligible finding, which must be contacted before any
per-server detail is published:

${
  reposWithGating
    .filter((r) => r.gating.some((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH'))
    .map((r) => `- [ ] ${r.repo.replace('__', '/')}`)
    .join('\n') || '_None._'
}
`;
writeFileSync(PRIVATE_OUT, privateDoc);

console.log(`scanned repositories: ${rows.length}`);
console.log(`gate-eligible: ${reposWithGating.length} (${gatingRate.toFixed(1)}%)`);
console.log(`\npublishable  -> ${PUBLIC_OUT}`);
console.log(`disclosure   -> ${PRIVATE_OUT} (gitignored)`);

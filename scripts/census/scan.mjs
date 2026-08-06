/**
 * Step 3 of the census: scan every fetched tree.
 *
 * Writes one JSON report per repository to `census/findings/`, which is
 * gitignored — per-repository findings against named third parties are subject
 * to the disclosure policy in SECURITY.md §2, and CLAUDE.md §1.1 keeps them out
 * of the tree unconditionally.
 *
 * ## What this measures, and what it cannot
 *
 * Directory mode. It reads source files and resolves `ui://` resources **where
 * statically resolvable**, which means:
 *
 *   - It cannot supply `_meta.ui`, the tool list, or server capabilities, so 35
 *     of 93 rules never run. Every `PANE-CSP` rule is among them. A census run
 *     this way measures the HTML and the declarations in source, not the
 *     policy a running server serves.
 *   - A build entry point is not what the server serves. Several of these are
 *     Vite projects whose served bundle differs from the file on disk.
 *   - A declaration in a README is indistinguishable from a declaration in
 *     code. The 2026-08-05 hand-scan found three servers whose only apparent
 *     CSP was `https://api.example.com` in documentation.
 *
 * The resolved/declared ratio is recorded per repository precisely so the
 * aggregate can say how much of the population it actually saw. A census that
 * reports findings without reporting coverage is telling half the story.
 *
 * Runs the built CLI as a subprocess rather than importing the library, so what
 * is measured is what a user would run.
 *
 * Run: node scripts/census/scan.mjs
 */

import { execFileSync } from 'node:child_process';
import { mkdirSync, readdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const REPOS = join(ROOT, 'census', 'raw', 'repos');
const OUT = join(ROOT, 'census', 'findings');
const CLI = join(ROOT, 'dist', 'cli.js');

if (!existsSync(CLI)) {
  console.error('dist/cli.js missing — run `npm run build` first');
  process.exit(2);
}
if (!existsSync(REPOS)) {
  console.error(`no trees at ${REPOS} — run scripts/census/fetch.mjs first`);
  process.exit(2);
}

mkdirSync(OUT, { recursive: true });

const trees = readdirSync(REPOS, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => d.name)
  .sort();

console.log(`scanning ${trees.length} trees`);

let scanned = 0;
let failed = 0;

for (const name of trees) {
  const outFile = join(OUT, `${name}.json`);
  if (existsSync(outFile)) continue;

  const dir = join(REPOS, name);
  let report;
  try {
    // --experimental so the census can measure experimental rules' false
    // positive rate before any of them is promoted. They cannot gate anyway.
    //
    // --no-inline-suppressions because these are untrusted third-party trees,
    // not the operator's own checkout. Directory mode trusts panelint-disable
    // comments by default; here the comment sits in someone else's repository,
    // so a single `<!-- panelint-disable-file -->` would drop that repo's
    // findings from the census. The GitHub Action passes this flag for the same
    // reason (action.yml).
    const stdout = execFileSync(
      process.execPath,
      [
        CLI, 'scan', dir,
        '--format', 'json',
        '--experimental',
        '--fail-on', 'critical',
        '--no-inline-suppressions',
      ],
      {
        encoding: 'utf8',
        maxBuffer: 256 * 1024 * 1024,
        timeout: 300_000,
        env: { ...process.env, NO_COLOR: '1' },
      },
    );
    report = JSON.parse(stdout);
  } catch (e) {
    // A gating finding exits non-zero; the report is still on stdout and is
    // exactly what we came for.
    const stdout = e.stdout ?? '';
    try {
      report = JSON.parse(stdout);
    } catch {
      failed += 1;
      writeFileSync(
        outFile,
        `${JSON.stringify({ repo: name, scanFailed: true, reason: String(e.message).slice(0, 200) }, null, 2)}\n`,
      );
      continue;
    }
  }

  writeFileSync(outFile, `${JSON.stringify({ repo: name, report }, null, 2)}\n`);
  scanned += 1;
  if (scanned % 25 === 0) console.log(`  ${scanned} scanned · ${failed} failed`);
}

console.log(`\nscanned ${scanned} · failed ${failed}`);
console.log(`per-repository reports in ${OUT} (gitignored — SECURITY.md §2)`);

/**
 * Step 1 of the census: build the corpus of candidate MCP Apps servers.
 *
 * Writes `census/raw/corpus.json`, which is gitignored — it names third-party
 * repositories, and per CLAUDE.md §1.1 raw census material never enters the
 * tree.
 *
 * ## Why two queries
 *
 * docs/DESIGN.md §12: the MCP registry cannot answer "which servers ship UI
 * resources", so the corpus is built from code search, and **one query is not
 * enough**. A server built on the official SDK calls `registerAppResource` and
 * may never write the MIME literal itself, while a hand-rolled server writes
 * `text/html;profile=mcp-app` and never calls the SDK helper. Searching only
 * one of them undercounts along an axis that is invisible from the result set.
 * The union of both is the floor, and it is reported as a floor.
 *
 * ## Why partitioning
 *
 * GitHub's code search API returns at most 1000 results per query (10 pages of
 * 100), and both queries exceed that — measured 2026-08-06 at 6896 and 2128
 * total matches. Asking for `q` alone silently truncates at 1000 and there is
 * nothing in the response that says so. So each query is split by `language:`,
 * and every partition that comes back at its own ceiling is recorded in
 * `truncatedPartitions` rather than quietly dropped. A census that overstates
 * its own coverage is worse than a smaller one that does not.
 *
 * Rate limit is 10 requests/minute for code search, so this takes a few
 * minutes and is written to be re-runnable: it merges into any existing
 * corpus.json rather than replacing it.
 *
 * Run: node scripts/census/search.mjs
 */

import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const OUT_DIR = join(ROOT, 'census', 'raw');
const OUT = join(OUT_DIR, 'corpus.json');

/**
 * The two independent signals. Neither is a superset of the other.
 */
const QUERIES = [
  { id: 'mime', q: '"text/html;profile=mcp-app"' },
  { id: 'sdk', q: 'registerAppResource' },
];

/**
 * Partitions. Code search caps at 1000 results per query, so each query is run
 * once per language. `null` means "no language qualifier" — it catches files
 * GitHub does not classify, and its own truncation is reported like any other.
 */
const LANGUAGES = [
  null,
  'TypeScript',
  'JavaScript',
  'Python',
  'Go',
  'Rust',
  'Java',
  'C#',
  'Ruby',
  'PHP',
  'HTML',
  'JSON',
  'Markdown',
  'Kotlin',
  'Swift',
];

const PER_PAGE = 100;
const MAX_PAGES = 10; // GitHub's hard ceiling: 1000 results per query.

/**
 * Repositories that are infrastructure rather than servers. Counting the SDK
 * itself, or a course repo that pastes the MIME literal into a lesson, would
 * inflate the population with things nobody deploys.
 */
const EXCLUDE = [
  /^modelcontextprotocol\//i,
  /\bmcp-?apps?-?sdk\b/i,
  /\bawesome-mcp\b/i,
  /\bmcp-?inspector\b/i,
  /\bmcp-?spec\b/i,
  // Panelint itself. `fixtures/malicious/` is a corpus of deliberate attacks,
  // so scanning our own tree contributes a CRITICAL finding that is a test
  // asset, not an ecosystem observation — it was 1 of the 3 gate-eligible
  // repositories in the first run, on a base of 35. A scanner that counts its
  // own adversarial fixtures in its published population statistic is
  // measuring itself.
  /^agarwalsujal\/panelint$/i,
  /\bpanelint\b/i,
];

function gh(args) {
  return execFileSync('gh', args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
}

/** Seconds until the code-search window resets, per the API rather than a guess. */
function searchResetDelay() {
  try {
    const limits = JSON.parse(gh(['api', 'rate_limit']));
    const bucket = limits.resources.code_search ?? limits.resources.search;
    if (bucket && bucket.remaining === 0) {
      const wait = bucket.reset * 1000 - Date.now();
      return Math.max(2000, Math.min(wait + 2000, 90_000));
    }
  } catch {
    /* fall through to the fixed pace below */
  }
  return 0;
}

function searchPage(q, page) {
  const wait = searchResetDelay();
  if (wait > 0) {
    console.log(`  rate limited, waiting ${Math.round(wait / 1000)}s`);
    execFileSync('sleep', [String(Math.ceil(wait / 1000))]);
  }
  const raw = gh([
    'api',
    '-X',
    'GET',
    'search/code',
    '-f',
    `q=${q}`,
    '-f',
    `per_page=${PER_PAGE}`,
    '-f',
    `page=${page}`,
  ]);
  return JSON.parse(raw);
}

const repos = new Map();
const truncatedPartitions = [];
let requests = 0;

function record(item, queryId) {
  const full = item.repository?.full_name;
  if (!full) return;
  if (EXCLUDE.some((re) => re.test(full))) return;

  // A fork inflates the population with a copy of a tree already counted, and
  // the census is published as a statement about public source. An
  // authenticated code search can also return private repositories the token
  // can read, which the generated document explicitly claims it does not
  // describe. Both were captured and neither was filtered.
  if (item.repository?.fork === true) return;
  if (item.repository?.private === true) return;

  const existing = repos.get(full) ?? {
    fullName: full,
    signals: [],
    paths: [],
    private: Boolean(item.repository?.private),
    fork: Boolean(item.repository?.fork),
  };
  if (!existing.signals.includes(queryId)) existing.signals.push(queryId);
  if (existing.paths.length < 5 && item.path && !existing.paths.includes(item.path)) {
    existing.paths.push(item.path);
  }
  repos.set(full, existing);
}

// Merge with any previous run so a rate-limit stop is not a lost run.
if (existsSync(OUT)) {
  const prior = JSON.parse(readFileSync(OUT, 'utf8'));
  for (const r of prior.repos ?? []) repos.set(r.fullName, r);
  // Carry the prior run's truncation record forward too. Rebuilding it from
  // scratch on every resume meant a run that died after recording three
  // truncated partitions, resumed and dying after one, wrote a corpus claiming
  // a single truncation — understating exactly the thing this file exists to
  // report honestly.
  for (const t of prior.truncatedPartitions ?? []) truncatedPartitions.push(t);
  console.log(
    `resuming from ${repos.size} repositories and ${truncatedPartitions.length} recorded truncations`,
  );
}

for (const { id, q } of QUERIES) {
  for (const language of LANGUAGES) {
    const full = language ? `${q} language:${language}` : q;
    let total = null;
    let seen = 0;
    let incomplete = false;

    for (let page = 1; page <= MAX_PAGES; page++) {
      let res;
      try {
        res = searchPage(full, page);
        requests += 1;
      } catch (e) {
        // A partition with zero results 422s on later pages; that is not an error.
        const msg = String(e.stderr ?? e.message);
        if (!/422|Only the first 1000/.test(msg)) {
          console.log(`  ${id}/${language ?? 'any'} page ${page}: ${msg.split('\n')[0]}`);
          // A 403 secondary rate limit or a 5xx mid-partition leaves the
          // partition incomplete at a page count far below the 1000-result
          // ceiling, so the check after this loop would not record it and the
          // corpus would silently overstate its own coverage. That is the exact
          // failure this script's header says is worse than a smaller census.
          incomplete = true;
        }
        break;
      }

      total ??= res.total_count ?? 0;
      const items = res.items ?? [];
      for (const item of items) record(item, id);
      seen += items.length;

      if (items.length < PER_PAGE) break;
    }

    const hitCeiling = seen >= MAX_PAGES * PER_PAGE;
    if (incomplete || (total !== null && total > seen && hitCeiling)) {
      truncatedPartitions.push({
        query: id,
        language: language ?? 'any',
        total,
        retrieved: seen,
        reason: incomplete ? 'request failed mid-partition' : 'hit the 1000-result ceiling',
      });
    }
    if (total) {
      console.log(
        `${id}/${language ?? 'any'}: ${seen} of ${total} retrieved · ${repos.size} distinct repos so far`,
      );
    }
  }
}

mkdirSync(OUT_DIR, { recursive: true });
const payload = {
  builtAt: new Date().toISOString(),
  method:
    'Union of two GitHub code searches, partitioned by language to work around the 1000-result ' +
    'per-query ceiling. Repositories matching the exclusion list (SDK, spec, inspector, awesome-lists) ' +
    'are dropped. This is a FLOOR on the population, not a count of it.',
  queries: QUERIES,
  requests,
  truncatedPartitions,
  repoCount: repos.size,
  repos: [...repos.values()].sort((a, b) => a.fullName.localeCompare(b.fullName)),
};
writeFileSync(OUT, `${JSON.stringify(payload, null, 2)}\n`);

console.log(`\n${repos.size} distinct repositories -> ${OUT}`);
console.log(`  both signals: ${[...repos.values()].filter((r) => r.signals.length === 2).length}`);
console.log(`  MIME only:    ${[...repos.values()].filter((r) => r.signals.join() === 'mime').length}`);
console.log(`  SDK only:     ${[...repos.values()].filter((r) => r.signals.join() === 'sdk').length}`);
if (truncatedPartitions.length > 0) {
  console.log(`\n${truncatedPartitions.length} partition(s) hit the 1000-result ceiling:`);
  for (const t of truncatedPartitions) {
    console.log(`  ${t.query}/${t.language}: retrieved ${t.retrieved} of ${t.total}`);
  }
  console.log('The corpus is a floor. Report it as one.');
}

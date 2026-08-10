/**
 * Step 2 of the census: download each candidate repository.
 *
 * Reads `census/raw/corpus.json`, writes trees under `census/raw/repos/`. Both
 * are gitignored: they are third-party source, and CLAUDE.md §1.1 keeps raw
 * census material out of the tree entirely.
 *
 * Tarballs rather than `git clone`, for three reasons. A tarball is one request
 * instead of a protocol negotiation, it carries no history to discard, and it
 * cannot run anything — a repository's hooks never execute, which matters when
 * the corpus is several hundred trees written by strangers. Nothing in this
 * script installs dependencies or runs a build. Panelint reads source.
 *
 * Re-runnable: a repository already extracted is skipped, so a rate limit or a
 * disconnect costs one repository, not the run.
 *
 * Run: node scripts/census/fetch.mjs [--limit N]
 */

import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync, existsSync, rmSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

import { RAW, REPOS, CORPUS, FETCH_LOG as LOG } from './paths.mjs';

/** A tree larger than this is a monorepo or a model dump; not worth the disk. */
const MAX_TARBALL_BYTES = 80 * 1024 * 1024;

const limitArg = process.argv.indexOf('--limit');
const LIMIT = limitArg > -1 ? Number(process.argv[limitArg + 1]) : Infinity;

if (!existsSync(CORPUS)) {
  console.error(`no corpus at ${CORPUS} — run scripts/census/search.mjs first`);
  process.exit(2);
}

const corpus = JSON.parse(readFileSync(CORPUS, 'utf8'));
mkdirSync(REPOS, { recursive: true });

/** `owner/repo` -> `owner__repo`, so one flat directory holds everything. */
const slug = (fullName) => fullName.replace('/', '__');

const log = existsSync(LOG) ? JSON.parse(readFileSync(LOG, 'utf8')) : { fetched: {}, failed: {} };

/**
 * Fetch order is the sampling method, so it is stated rather than incidental.
 *
 * A repository carrying BOTH signals writes the MCP Apps MIME type *and* calls
 * the SDK's `registerAppResource`. That combination is very hard to produce by
 * writing about MCP Apps, so the both-signal set is close to pure servers.
 * Single-signal repositories include real servers, but also tutorials, blog
 * posts, and vendored copies of documentation that mention the string once.
 *
 * Fetching in this order means a run that stops early stops with the highest
 * precision subset complete, and `--limit` produces a sample whose composition
 * is known rather than alphabetical.
 */
const ordered = [...corpus.repos].sort((a, b) => {
  const strength = (r) => (r.signals.length === 2 ? 0 : 1);
  return strength(a) - strength(b) || a.fullName.localeCompare(b.fullName);
});

let done = 0;
for (const repo of ordered) {
  if (done >= LIMIT) break;

  const name = slug(repo.fullName);
  const dest = join(REPOS, name);

  if (existsSync(dest) && readdirSync(dest).length > 0) continue;
  if (log.failed[repo.fullName]) continue;

  const tmp = `${dest}.tar.gz`;
  try {
    // gh follows the redirect to codeload and writes the body to stdout.
    const buf = execFileSync('gh', ['api', `repos/${repo.fullName}/tarball`], {
      encoding: 'buffer',
      maxBuffer: MAX_TARBALL_BYTES,
      timeout: 180_000,
    });
    writeFileSync(tmp, buf);

    mkdirSync(dest, { recursive: true });
    // --strip-components drops the `owner-repo-sha/` wrapper GitHub adds.
    //
    // The excludes are disk management, not analysis. Panelint reads source
    // looking for `ui://` declarations and the HTML behind them; none of what
    // is dropped here can carry one. Measured before adding them: three
    // repositories came to 89 MB, which extrapolates to ~11 GB over the
    // both-signal set. Media and vendored binaries were nearly all of it.
    execFileSync(
      'tar',
      [
        '-xzf',
        tmp,
        '-C',
        dest,
        '--strip-components=1',
        '--exclude=*/node_modules/*',
        '--exclude=*/.git/*',
        '--exclude=*/target/*',
        '--exclude=*/venv/*',
        '--exclude=*/.venv/*',
        '--exclude=*/__pycache__/*',
        '--exclude=*.png',
        '--exclude=*.jpg',
        '--exclude=*.jpeg',
        '--exclude=*.gif',
        '--exclude=*.webp',
        '--exclude=*.svg',
        '--exclude=*.ico',
        '--exclude=*.mp4',
        '--exclude=*.mov',
        '--exclude=*.pdf',
        '--exclude=*.zip',
        '--exclude=*.gz',
        '--exclude=*.wasm',
        '--exclude=*.so',
        '--exclude=*.dylib',
        '--exclude=*.node',
        '--exclude=*.woff',
        '--exclude=*.woff2',
        '--exclude=*.ttf',
      ],
      { stdio: ['ignore', 'ignore', 'pipe'], timeout: 120_000 },
    );
    rmSync(tmp, { force: true });

    log.fetched[repo.fullName] = { at: new Date().toISOString(), bytes: buf.length };
    done += 1;
    if (done % 10 === 0) {
      console.log(`${done} fetched · ${Object.keys(log.failed).length} failed`);
      writeFileSync(LOG, `${JSON.stringify(log, null, 2)}\n`);
    }
  } catch (e) {
    rmSync(tmp, { force: true });
    rmSync(dest, { recursive: true, force: true });
    // Message only. A third-party repository's error text is untrusted input
    // and this log is read by a human later.
    const reason = String(e.message ?? '').slice(0, 120).replace(/[\u0000-\u001f]/g, ' ');
    log.failed[repo.fullName] = { at: new Date().toISOString(), reason };
  }
}

writeFileSync(LOG, `${JSON.stringify(log, null, 2)}\n`);
console.log(
  `\nfetched ${Object.keys(log.fetched).length} · failed ${Object.keys(log.failed).length} of ${corpus.repos.length}`,
);
console.log(`trees under ${REPOS} (gitignored)`);

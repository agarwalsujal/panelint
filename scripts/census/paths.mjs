/**
 * Where census material lives.
 *
 * `CLAUDE.md` §1.1 says raw census material stays out of the tree. The scripts
 * wrote it to `census/raw/` anyway, and a full run put **643,804 files and
 * 9.5 GB** inside the working directory. Git never noticed — `.gitignore`
 * covers `census/raw/`, so `git status` stayed clean — but every tool that
 * walks the working directory did, and editors and assistants that index the
 * project on open stall on a corpus that size.
 *
 * So the raw corpus now defaults **outside the repository**, as a sibling
 * directory. Override with `PANELINT_CENSUS_RAW` to put it anywhere else — an
 * external disk, a scratch volume, a shared cache between checkouts.
 *
 * Findings stay in the tree deliberately. They are 392 files and ~3 MB, they
 * are what `aggregate.mjs` turns into `docs/CENSUS.md`, and keeping them beside
 * the code is what makes a census result reproducible from a checkout. They are
 * gitignored for disclosure reasons (SECURITY.md §2), not size ones.
 */

import { fileURLToPath } from 'node:url';
import { join, resolve } from 'node:path';

/** The repository root — `scripts/census/` is two levels down. */
export const ROOT = fileURLToPath(new URL('../..', import.meta.url));

/**
 * Third-party source trees and the corpus manifest. Hundreds of thousands of
 * files: never inside the repository.
 */
export const RAW = process.env.PANELINT_CENSUS_RAW
  ? resolve(process.env.PANELINT_CENSUS_RAW)
  : join(ROOT, '..', 'panelint-census', 'raw');

export const REPOS = join(RAW, 'repos');
export const CORPUS = join(RAW, 'corpus.json');
export const FETCH_LOG = join(RAW, 'fetch-log.json');

/** Per-repository scan output. Small, and stays beside the code. */
export const FINDINGS = join(ROOT, 'census', 'findings');

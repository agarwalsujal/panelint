/**
 * Point action.yml's `version` input at the version being released.
 *
 * Run automatically by npm's `version` lifecycle script, which fires after
 * package.json is bumped and before the release commit is made — so the bump
 * and the pin land in the same commit and can never disagree.
 *
 * This exists because they did disagree, twice in a row. `npm version patch`
 * moves package.json only; the Action pins the npm version it installs into
 * other people's CI, and a release published with a stale pin ships an Action
 * that installs the PREVIOUS build — which, for the 0.1.1 release, was the
 * build containing every bypass 0.1.1 was cut to fix.
 *
 * test/action.test.ts asserts the two match, so `prepublishOnly` caught it both
 * times. Being caught by a test on every release is not a workflow; this makes
 * the test's invariant true by construction instead.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const ACTION = join(ROOT, 'action.yml');

const { version } = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
if (!/^\d+\.\d+\.\d+/.test(version)) {
  console.error(`refusing to sync a version that is not semver: ${version}`);
  process.exit(1);
}

const before = readFileSync(ACTION, 'utf8');

// Only the `version:` input's default. Anchored to that block so a coincidental
// version-shaped string elsewhere in the file is never rewritten.
const block = /( {2}version:\n(?:.*\n)*? {4}default: ')([^']+)(')/;
const match = block.exec(before);
if (!match) {
  console.error('could not find the version input default in action.yml');
  process.exit(1);
}

if (match[2] === version) {
  console.log(`action.yml already pins ${version}`);
  process.exit(0);
}

const after = before.replace(block, `$1${version}$3`);
writeFileSync(ACTION, after);
console.log(`action.yml pin ${match[2]} -> ${version}`);

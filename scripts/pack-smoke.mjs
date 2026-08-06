/**
 * Pack the tarball, install it into an empty directory, and run the CLI from
 * there.
 *
 * `npm test` proves the source is correct. It cannot prove the published
 * artifact works, and those are different claims: the `files` allowlist,
 * `bin` resolution, the shebang, and every runtime `new URL('../schema/...',
 * import.meta.url)` are exercised only once the package has been packed and
 * installed somewhere else. A missing entry in `files` is invisible to the
 * suite and fatal to the first `npx panelint`.
 *
 * Two schema reads have to survive the move in particular — src/cli.ts reads
 * `../schema/VERSION` and src/parse/meta.ts reads `../../schema/schema.json`,
 * both relative to the *compiled* file's location under dist/. A directory
 * scan does not load the JSON Schema at all (28 meta rules skip), so this
 * script replays a capture as well. Testing only the directory path would pass
 * with schema/ missing entirely.
 *
 * Run: npm run test:pack
 */

import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, cpSync, writeFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = fileURLToPath(new URL('..', import.meta.url));

/** Run a command, returning stdout. Throws with captured output on failure. */
function run(cmd, args, cwd) {
  return execFileSync(cmd, args, {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    // The suite's own vitest timeout is 20s; packing plus an install needs more.
    timeout: 300_000,
  });
}

/** Assert, with the observed value in the message — a bare `false` is unactionable. */
function assert(condition, what, observed) {
  if (condition) {
    console.log(`  ok  ${what}`);
    return;
  }
  console.error(`  FAIL  ${what}`);
  if (observed !== undefined) console.error(`        observed: ${JSON.stringify(observed)}`);
  process.exitCode = 1;
  failures += 1;
}

let failures = 0;
const work = mkdtempSync(join(tmpdir(), 'panelint-pack-'));

try {
  console.log('packing');
  // --pack-destination keeps the tarball out of the repo, so a failed run
  // cannot leave a stray .tgz for `git add .` to pick up.
  const packed = run('npm', ['pack', '--pack-destination', work, '--silent'], ROOT).trim();
  const tarball = join(work, packed.split('\n').pop().trim());

  const sandbox = join(work, 'sandbox');
  mkdirSync(sandbox, { recursive: true });
  // A private, no-workspaces package.json so npm treats this as a leaf install
  // and does not walk up into the repo it was packed from.
  writeFileSync(
    join(sandbox, 'package.json'),
    JSON.stringify({ name: 'panelint-pack-smoke', version: '0.0.0', private: true }, null, 2),
  );

  console.log('installing the tarball into an empty directory');
  run('npm', ['install', '--no-audit', '--no-fund', '--silent', tarball], sandbox);

  const bin = join(sandbox, 'node_modules', '.bin', 'panelint');

  console.log('running the installed CLI');

  const version = run(bin, ['--version'], sandbox).trim();
  assert(/^\d+\.\d+\.\d+/.test(version), '--version runs from node_modules/.bin', version);

  const rules = JSON.parse(run(bin, ['rules', '--json'], sandbox));
  const ruleList = rules.rules ?? rules;
  assert(Array.isArray(ruleList) && ruleList.length > 0, 'rules --json emits the registry', ruleList.length);

  // Directory mode: exercises acquire + parse + report, but not the JSON Schema.
  const target = join(sandbox, 'target');
  cpSync(join(ROOT, 'fixtures', 'dirscan', 'basic'), target, { recursive: true });
  const dirScan = run(bin, ['scan', target, '--no-color'], sandbox);
  assert(dirScan.includes('resolved '), 'directory scan reports a resolved/declared ratio');
  assert(dirScan.includes('errors: 0'), 'directory scan completes with no acquire errors');

  // Capture replay: the path that reads schema/schema.json off disk. This is
  // the assertion that actually proves `files` shipped schema/.
  const capture = join(sandbox, 'capture.json');
  cpSync(join(ROOT, 'fixtures', 'capture', 'valid.json'), capture);
  let captureOut = '';
  try {
    captureOut = run(bin, ['scan', capture, '--no-color', '--fail-on', 'critical'], sandbox);
  } catch (e) {
    // A gating finding exits non-zero by design; the output is still what we assert on.
    captureOut = `${e.stdout ?? ''}${e.stderr ?? ''}`;
  }
  assert(captureOut.includes('mode capture'), 'capture replay runs from the installed package');
  assert(
    !/cannot find|ENOENT|no such file/i.test(captureOut),
    'capture replay resolves schema/ from node_modules',
    captureOut.slice(0, 400),
  );
  assert(
    /PANE-[A-Z]+-\d+/.test(captureOut),
    'capture replay produces findings — the rule engine ran, it did not silently no-op',
  );

  // The library entry point. package.json main/types/exports pointed at
  // dist/index.js while src/index.ts did not exist — the CLI worked, the whole
  // suite passed, and `import('panelint')` threw ERR_MODULE_NOT_FOUND for every
  // consumer. Nothing caught it because nothing imported the package the way a
  // consumer would.
  const importProbe = join(sandbox, 'probe.mjs');
  writeFileSync(
    importProbe,
    [
      "import * as p from 'panelint';",
      'if (typeof p.analyzeResourceSet !== "function") throw new Error("analyzeResourceSet missing");',
      'if (!Array.isArray(p.ALL_RULES) || p.ALL_RULES.length === 0) throw new Error("empty registry");',
      'if (typeof p.renderSarif !== "function") throw new Error("renderSarif missing");',
      'console.log(p.ALL_RULES.length);',
    ].join('\n'),
  );
  let imported = '';
  try {
    imported = run('node', [importProbe], sandbox).trim();
  } catch (e) {
    imported = `THREW: ${e.stderr ?? e.message}`;
  }
  assert(/^\d+$/.test(imported), "import('panelint') resolves and exports the API", imported);
  assert(
    imported === String(ruleList.length),
    'the library and the CLI report the same rule count',
    { library: imported, cli: ruleList.length },
  );

  // A gate that stopped scanning would pass every assertion above.
  const shipped = readdirSync(join(sandbox, 'node_modules', 'panelint'));
  assert(shipped.includes('schema'), 'schema/ is present in the installed package', shipped);
  assert(shipped.includes('dist'), 'dist/ is present in the installed package', shipped);
} finally {
  rmSync(work, { recursive: true, force: true });
}

if (failures > 0) {
  console.error(`\npack smoke test FAILED — ${failures} assertion(s)`);
  process.exit(1);
}
console.log('\npack smoke test passed');

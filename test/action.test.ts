/**
 * The GitHub Action's safety properties, asserted rather than reviewed.
 *
 * `action.yml` is the surface where Panelint runs inside someone else's
 * repository, on their runner, with their token. Three properties have to hold
 * and none of them is visible from reading a diff months later:
 *
 *   1. No input can produce a dangerous flag. `--allow-spawn` would run a fork
 *      PR's server code on a runner; `--trust-inline-suppressions` and
 *      `--allow-repo-config` both let the scanned bytes influence their own
 *      findings; `--http` would let a workflow input name any URL.
 *   2. No untrusted value is interpolated into a shell script. `${{ }}` inside
 *      a `run:` block is textual substitution performed before bash parses the
 *      line, so an input wired to a PR title is command execution. Everything
 *      goes through `env:` instead.
 *   3. The SARIF upload runs on failure. Uploading only on success would mean
 *      findings never reach the Security tab on precisely the runs that have
 *      findings.
 *
 * Parsed as text rather than with a YAML library on purpose: adding a
 * dependency to check our own file, in a project whose threat model counts its
 * dependency closure, is a bad trade for a handful of assertions.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..');
const CLI = join(REPO, 'dist', 'cli.js');

const action = readFileSync(join(REPO, 'action.yml'), 'utf8');
const lines = action.split('\n');

/**
 * Line indices that sit inside a `run:` block literal.
 *
 * A block starts at `run: |` (or `run: >`) and continues while lines are
 * indented deeper than the `run:` key itself.
 */
function runBlockLines(): number[] {
  const out: number[] = [];
  for (let i = 0; i < lines.length; i++) {
    const start = /^(\s*)run:\s*[|>]/.exec(lines[i] ?? '');
    if (!start) continue;
    const indent = (start[1] ?? '').length;
    for (let j = i + 1; j < lines.length; j++) {
      const line = lines[j] ?? '';
      if (line.trim() === '') {
        out.push(j);
        continue;
      }
      const lead = (/^\s*/.exec(line)?.[0] ?? '').length;
      if (lead <= indent) break;
      out.push(j);
    }
  }
  return out;
}

beforeAll(() => {
  if (!existsSync(CLI)) {
    execFileSync('npx', ['tsc', '-p', 'tsconfig.build.json'], { cwd: REPO, timeout: 180_000 });
  }
}, 200_000);

// ---------------------------------------------------------------------------
// 1. The flags the action must never be able to produce.
// ---------------------------------------------------------------------------

describe('the action cannot reach a dangerous flag', () => {
  const FORBIDDEN = [
    '--allow-spawn',
    '--http',
    '--trust-inline-suppressions',
    '--allow-repo-config',
  ];

  for (const flag of FORBIDDEN) {
    it(`never mentions ${flag} outside a comment`, () => {
      const offending = lines.filter(
        (l) => l.includes(flag) && !l.trimStart().startsWith('#'),
      );
      expect(offending).toEqual([]);
    });
  }

  it('declares no input whose name suggests one of them', () => {
    const inputNames = [...action.matchAll(/^ {2}([a-z][a-z0-9-]*):$/gm)].map((m) => m[1]);
    for (const name of inputNames) {
      expect(name).not.toMatch(/spawn|http|trust|repo-config/);
    }
  });
});

// ---------------------------------------------------------------------------
// 2. No expression interpolation inside a shell body.
// ---------------------------------------------------------------------------

describe('no workflow expression is interpolated into a shell script', () => {
  it('has no ${{ }} anywhere inside a run: block', () => {
    const offending = runBlockLines()
      .filter((i) => (lines[i] ?? '').includes('${{'))
      .map((i) => `${i + 1}: ${lines[i]?.trim()}`);
    expect(offending).toEqual([]);
  });

  it('passes every input the scan step uses through env:', () => {
    // If a value is used in the script it must have arrived as a variable.
    const used = [...action.matchAll(/\$\{?(IN_[A-Z_]+|OUT_[A-Z_]+|PANELINT_[A-Z_]+)\b/g)].map(
      (m) => m[1] as string,
    );
    const declared = [...action.matchAll(/^\s+(IN_[A-Z_]+|OUT_[A-Z_]+|PANELINT_[A-Z_]+):/gm)].map(
      (m) => m[1] as string,
    );
    for (const name of new Set(used)) {
      expect(declared, `${name} is used but never declared in an env: block`).toContain(name);
    }
  });

  it('validates the version input before it becomes a package specifier', () => {
    // `npm install panelint@$X` with an unvalidated X accepts a git URL or a
    // local path, which is arbitrary code from an arbitrary source.
    expect(action).toMatch(/grep -qE .\^\[A-Za-z0-9\]/);
  });
});

// ---------------------------------------------------------------------------
// 3. Upload and gate ordering.
// ---------------------------------------------------------------------------

describe('results reach the Security tab even when the scan gates', () => {
  it('uploads SARIF under always()', () => {
    const upload = action.slice(action.indexOf('Upload SARIF'));
    const ifLine = /if:\s*\$\{\{([^}]+)\}\}/.exec(upload)?.[1] ?? '';
    expect(ifLine).toContain('always()');
  });

  it('re-raises the exit code in a step after the upload', () => {
    const uploadAt = action.indexOf('Upload SARIF');
    const gateAt = action.indexOf('Apply the gate');
    expect(uploadAt).toBeGreaterThan(-1);
    expect(gateAt).toBeGreaterThan(uploadAt);
  });

  it('does not let the scan step fail the job before the upload runs', () => {
    // The scan step ends with `exit 0` and records the real code as an output.
    const scan = action.slice(action.indexOf('id: scan'), action.indexOf('Upload SARIF'));
    expect(scan).toContain('exit-code=$code');

    // Last executable line of the step. The slice runs up to the next step's
    // name, so trailing comments and the dangling `- name:` belong to that
    // step and must not be mistaken for the end of this one.
    const lastCode = scan
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l !== '' && !l.startsWith('#') && !l.startsWith('- '))
      .pop();
    expect(lastCode).toBe('exit 0');
  });
});

// ---------------------------------------------------------------------------
// 4. Every flag the action passes must exist.
// ---------------------------------------------------------------------------

describe('the action does not pass flags the CLI lacks', () => {
  it('names only real scan flags', () => {
    const help = spawnSync(process.execPath, [CLI, 'scan', '--help'], {
      encoding: 'utf8',
      env: { ...process.env, NO_COLOR: '1' },
      timeout: 60_000,
    });
    const helpText = `${help.stdout ?? ''}${help.stderr ?? ''}`;

    const passed = new Set(
      [...action.matchAll(/args\+=\((--[a-z-]+)/g)].map((m) => m[1] as string),
    );
    expect(passed.size).toBeGreaterThan(0);
    for (const flag of passed) {
      expect(helpText, `${flag} is passed by the action but not offered by the CLI`).toContain(
        flag,
      );
    }
  });
});

// ---------------------------------------------------------------------------
// 5. The pinned version must be a version that exists here.
// ---------------------------------------------------------------------------

describe('the pinned version', () => {
  it('matches package.json', () => {
    // The action installs `panelint@<default>`. If that drifts from the version
    // this repository builds, the action ships behaviour nobody tested here.
    const pkg = JSON.parse(readFileSync(join(REPO, 'package.json'), 'utf8')) as {
      version: string;
    };
    const block = action.slice(action.indexOf('  version:'));
    const dflt = /default:\s*'([^']+)'/.exec(block)?.[1];
    expect(dflt).toBe(pkg.version);
  });
});

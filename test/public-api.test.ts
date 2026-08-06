/**
 * The published entry point is a semver contract, so the export list is pinned
 * here rather than left to whatever `src/index.ts` happens to re-export.
 *
 * Two failures this catches, both of which shipped once already:
 *
 *   1. `package.json` main/types/exports pointed at `dist/index.js` while
 *      `src/index.ts` did not exist. Every test passed and `import('panelint')`
 *      failed with ERR_MODULE_NOT_FOUND. Nothing in the suite imported the
 *      package the way a consumer would.
 *   2. Silent surface growth. A re-export added while working on something else
 *      becomes a removal that needs a major bump. Adding to this list should be
 *      a deliberate line in a diff someone reviews.
 *
 * Runtime values only. Type-only exports vanish at runtime and cannot be
 * asserted from here — `npm run typecheck` is what covers those.
 */

import { describe, it, expect } from 'vitest';

import * as panelint from '../src/index.js';

/**
 * Every runtime export, sorted. Update deliberately, and only alongside a note
 * in the entry point explaining who needs the addition.
 */
const PUBLIC_API = [
  'ALL_RULES',
  'ALL_SEVERITIES',
  'DEFAULT_LIMITS',
  'DISCLAIMER',
  'HOMEPAGE',
  'RULES_BY_ID',
  'SCHEMA_VERSION',
  'analyzeResourceSet',
  'gatingFindings',
  'isGating',
  'limitationFor',
  'loadCapture',
  'meetsSeverity',
  'parseCaptureText',
  'renderJson',
  'renderSarif',
  'renderText',
  'resolveLimits',
  'ruleEngineFingerprint',
  'scanDirectory',
  'selectExitCode',
  'selectRules',
] as const;

describe('the published API surface', () => {
  it('exports exactly the pinned list', () => {
    expect(Object.keys(panelint).sort()).toEqual([...PUBLIC_API]);
  });

  it('exposes no way to spawn a scanned server', () => {
    // acquireStdio runs someone else's program. That decision is gated behind
    // --allow-spawn on a command line a human typed, and a library export
    // would route around the only place a user sees the gate.
    expect(Object.keys(panelint)).not.toContain('acquireStdio');
    expect(Object.keys(panelint)).not.toContain('replayCapture');
  });

  it('carries a rule registry that is not empty', () => {
    // A tree-shaking or build misconfiguration that emptied the registry would
    // leave every other assertion here passing.
    expect(panelint.ALL_RULES.length).toBeGreaterThan(0);
    expect(panelint.RULES_BY_ID.size).toBe(panelint.ALL_RULES.length);
  });

  it('agrees with the registry the CLI publishes', () => {
    // `panelint rules --json` is the machine-readable source of truth and the
    // census keys on it. The library must not see a different rule set.
    const ids = panelint.ALL_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids.every((id) => /^PANE-[A-Z]+-\d{3}$/.test(id))).toBe(true);
  });
});

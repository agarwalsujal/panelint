/**
 * The library entry point.
 *
 * package.json points `main`, `types`, and `exports["."]` here. Until this file
 * existed they pointed at nothing: `import('panelint')` failed with
 * ERR_MODULE_NOT_FOUND for anyone who used the package as anything other than a
 * binary. The CLI worked, every test passed, and the published entry point was
 * broken — which is why scripts/pack-smoke.mjs now imports the package rather
 * than only running it.
 *
 * **This surface is a semver contract and it is deliberately small.** Once
 * published, removing an export is a major bump, so the rule for adding to this
 * file is: a consumer must already need it. The known consumer is the
 * `sunpeak` test-harness plugin described in the roadmap, which needs to run
 * rules over a resource set and read findings back. That is what is exported.
 *
 * Everything else — the DOM and StyleIndex internals, the individual rule
 * modules, the safe/* primitives, the config loader's file discovery — stays
 * internal. `test/public-api.test.ts` pins the list, so growing it is a
 * reviewable diff and never an accident.
 *
 * Deliberately absent, with reasons:
 *
 *   - `acquireStdio`. It spawns the scanned server's process. Exposing it as a
 *     library function removes the one place that decision is visibly gated —
 *     `--allow-spawn` on a command line a human typed. A library caller that
 *     genuinely wants it can depend on the CLI.
 *   - the rule modules individually. Rule IDs are the public contract, not the
 *     functions behind them; importing `panelint/rules/csp/csp-001` would make
 *     every internal file rename a breaking change.
 *   - `validateCapture` and the capture builders beyond `loadCapture`. The
 *     capture format is versioned and owned by the CLI.
 */

export { scanDirectory } from './acquire/directory.js';
export { loadCapture, parseCaptureText } from './acquire/capture.js';
export { ruleEngineFingerprint } from './acquire/hash.js';

export { analyzeResourceSet } from './analyze.js';
export type { AnalyzeOptions, AnalyzeResult, SkippedRules } from './analyze.js';

export { ALL_RULES, RULES_BY_ID, selectRules } from './rules/registry.js';

export { isGating, gatingFindings, meetsSeverity, selectExitCode } from './exit.js';
export type { ExitCode, OnError } from './exit.js';

export { DEFAULT_LIMITS, resolveLimits } from './limits.js';

export { renderText } from './report/text.js';
export { renderJson } from './report/json.js';
export { renderSarif } from './report/sarif.js';
export { DISCLAIMER, HOMEPAGE, SCHEMA_VERSION, limitationFor } from './report/types.js';
export type { ReportResource, ScanHeader, ScanReport, ScanMode } from './report/types.js';

export { ALL_SEVERITIES } from './types.js';
export type {
  Confidence,
  Finding,
  Limits,
  ResourceSet,
  RuleClass,
  RuleMeta,
  ScanDiagnostic,
  ScanError,
  Severity,
  UIResource,
} from './types.js';

/**
 * Configuration loading (docs/DESIGN.md §5).
 *
 * `panelint.config.json`, or a `panelint` key in `package.json`. Both live in
 * the tree being scanned, which is the tree whose author most wants a finding
 * to go away. Two rules follow from that, and neither is negotiable:
 *
 * **1. A repo config may only RAISE severity.** Lowering one, or switching a
 * rule `off`, requires `--allow-repo-config` on the command line — a decision
 * made by the person running the scan, not by the person being scanned. The
 * enforcement itself lives in `applySeverityOverrides` (suppress.ts), because
 * "is this a lowering?" is a question about a finding, not about a file.
 *
 * **2. Spawn, target, limits, schema path and baseline path are CLI-ONLY and
 * hard-rejected on sight.** A config-supplied server command is remote code
 * execution: `panelint scan .` on a hostile repo would run
 * `{"command": "node", "args": ["./exfiltrate-ci-secrets.js"]}` with the CI
 * environment attached. There is no version of that which is worth the
 * convenience, so the presence of such a key makes the whole config FATAL
 * rather than merely dropping the key — a config that reached for RCE is not a
 * config whose remaining contents deserve the benefit of the doubt.
 *
 * `allowRepoConfig` and `trustInlineSuppressions` are on the same list, for the
 * obvious reason: a config that could set them could grant itself the authority
 * to silence anything.
 */

import { isAbsolute, resolve } from 'node:path';
import { readContained, resolveContained } from '../safe/paths.js';
import { errorSummary, safe, trusted } from '../safe/untrusted.js';
import { ALL_SEVERITIES, type Severity } from '../types.js';
import type {
  ConfigDiagnostic,
  ConfigOrigin,
  PanelintConfigFile,
  ResolvedConfig,
  RuleConfig,
  SeverityOverride,
} from './types.js';

export const CONFIG_FILENAME = 'panelint.config.json';
export const PACKAGE_JSON = 'package.json';
export const PACKAGE_KEY = 'panelint';

/** A config file is a few dozen lines. Anything larger is not a config file. */
export const MAX_CONFIG_BYTES = 256 * 1024;

/** SARIF `rules[].id` is a public contract; so is the shape of a rule id. */
export const RULE_ID_PATTERN = /^PANE-[A-Z0-9]+-\d{3}$/;

/**
 * Keys that may only ever come from the command line.
 *
 * Grouped by what each one buys an attacker who can write a file in the tree
 * you are scanning.
 */
export const CLI_ONLY_KEYS: ReadonlySet<string> = new Set([
  // Code execution.
  'command', 'args', 'env', 'cwd', 'spawn', 'allowSpawn', 'allow_spawn',
  // Network target — SSRF, and a scan of somebody else's server under your name.
  'server', 'url', 'target', 'transport', 'headers', 'origin', 'timeout',
  // Resource ceilings. Raising them is a denial-of-service against the scanner.
  'limits', 'maxResourceBytes', 'maxDomNodes', 'maxCssRules', 'selectorMatchBudget',
  'perResourceMs', 'maxTotalResources', 'maxNestingDepth', 'base64DecodeCap',
  'maxScriptBytes', 'maxEvidenceChars',
  // What Panelint validates against, and what it treats as already accepted.
  'schema', 'schemaPath', 'baseline', 'baselinePath',
  // Self-granted trust.
  'allowRepoConfig', 'trustInlineSuppressions', 'trustInline',
]);

/** Honoured only with `--allow-repo-config`. Both move the gate. */
const RESTRICTED_KEYS: ReadonlySet<string> = new Set(['failOn', 'onError']);

const KNOWN_KEYS: ReadonlySet<string> = new Set(['$schema', 'rules', ...RESTRICTED_KEYS]);

export interface LoadConfigOptions {
  /** The directory being scanned. Discovery and containment are relative to it. */
  root: string;
  /**
   * An explicit `--config`. Relative paths are resolved under `root` and must
   * stay there; an absolute path is taken as an operator decision and read
   * directly, still subject to the extension, size and binary checks.
   */
  configPath?: string;
  allowRepoConfig?: boolean;
  trustInlineSuppressions?: boolean;
  refuseInlineSuppressions?: boolean;
}

export interface ResolveOptions {
  allowRepoConfig?: boolean;
  trustInlineSuppressions?: boolean;
  refuseInlineSuppressions?: boolean;
  origin?: ConfigOrigin;
}

/** The config used when there is no config. */
export function emptyConfig(opts: ResolveOptions = {}): ResolvedConfig {
  return {
    origin: opts.origin ?? { kind: 'default' },
    rules: {},
    allowRepoConfig: opts.allowRepoConfig === true,
    trustInlineSuppressions: opts.trustInlineSuppressions === true,
    refuseInlineSuppressions: opts.refuseInlineSuppressions === true,
    rejectedKeys: [],
    fatal: false,
    diagnostics: [],
  };
}

/** `off | info | low | medium | high | critical` → normalized, or null. */
export function parseSeverityOverride(value: unknown): SeverityOverride | null {
  if (typeof value !== 'string') return null;
  const upper = value.trim().toUpperCase();
  if (upper === 'OFF') return 'OFF';
  return (ALL_SEVERITIES as readonly string[]).includes(upper) ? (upper as Severity) : null;
}

function parseSeverity(value: unknown): Severity | null {
  const parsed = parseSeverityOverride(value);
  return parsed && parsed !== 'OFF' ? parsed : null;
}

/**
 * Validate a parsed config object. Pure — no filesystem, fully testable.
 */
export function resolveConfig(raw: unknown, opts: ResolveOptions = {}): ResolvedConfig {
  const cfg = emptyConfig(opts);
  const path = opts.origin?.path;

  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    cfg.fatal = true;
    cfg.diagnostics.push(diag('CONFIG_PARSE_FAILED', trusted('Config must be a JSON object'), path));
    return cfg;
  }

  const file = raw as PanelintConfigFile;

  // Pass 1: refuse outright. Done before anything is interpreted, so a config
  // carrying an RCE key never has any of its other keys honoured.
  for (const key of Object.keys(file)) {
    if (CLI_ONLY_KEYS.has(key)) cfg.rejectedKeys.push(key);
  }
  if (cfg.rejectedKeys.length > 0) {
    cfg.fatal = true;
    cfg.diagnostics.push(
      diag(
        'CONFIG_KEY_REJECTED',
        trusted(
          `Config sets command-line-only key(s): ${cfg.rejectedKeys.map((k) => safe(k, 40)).join(', ')}`,
        ),
        path,
        'Spawn, target, limits, schema path, baseline path and trust flags are ' +
          'accepted only from the command line. A config-supplied server command is ' +
          'remote code execution. The whole config was discarded.',
      ),
    );
    return cfg;
  }

  // Pass 2: interpret.
  for (const key of Object.keys(file)) {
    if (KNOWN_KEYS.has(key)) continue;
    cfg.diagnostics.push(
      diag('CONFIG_UNKNOWN_KEY', trusted(`Unknown config key ignored: ${safe(key, 40)}`), path),
    );
  }

  if (file.rules !== undefined) {
    if (typeof file.rules !== 'object' || file.rules === null || Array.isArray(file.rules)) {
      cfg.diagnostics.push(
        diag('CONFIG_INVALID_VALUE', trusted('`rules` must be an object keyed by rule id'), path),
      );
    } else {
      for (const [ruleId, value] of Object.entries(file.rules as Record<string, unknown>)) {
        const entry = parseRuleEntry(ruleId, value, cfg.diagnostics, path);
        if (entry) cfg.rules[ruleId] = entry;
      }
    }
  }

  for (const key of RESTRICTED_KEYS) {
    if (file[key] === undefined) continue;
    if (!cfg.allowRepoConfig) {
      cfg.diagnostics.push(
        diag(
          'CONFIG_KEY_REFUSED',
          trusted(`Config key \`${safe(key, 20)}\` ignored without --allow-repo-config`),
          path,
          'The gate threshold and the error policy belong to the person running ' +
            'the scan, not to the tree being scanned.',
        ),
      );
      continue;
    }
    if (key === 'failOn') {
      const sev = parseSeverity(file.failOn);
      if (sev) cfg.failOn = sev;
      else
        cfg.diagnostics.push(
          diag('CONFIG_INVALID_VALUE', trusted('`failOn` must be a severity word'), path),
        );
    } else if (file.onError === 'fail' || file.onError === 'warn') {
      cfg.onError = file.onError;
    } else {
      cfg.diagnostics.push(
        diag('CONFIG_INVALID_VALUE', trusted('`onError` must be "fail" or "warn"'), path),
      );
    }
  }

  return cfg;
}

function parseRuleEntry(
  ruleId: string,
  value: unknown,
  diagnostics: ConfigDiagnostic[],
  path?: string,
): RuleConfig | null {
  if (!RULE_ID_PATTERN.test(ruleId)) {
    diagnostics.push(
      diag(
        'CONFIG_INVALID_VALUE',
        trusted(`Not a rule id, entry ignored: ${safe(ruleId, 40)}`),
        path,
        'Rule ids look like PANE-CSP-003. `panelint rules --json` lists them.',
      ),
    );
    return null;
  }

  // Shorthand: "PANE-CSP-003": "critical"
  if (typeof value === 'string') {
    const sev = parseSeverityOverride(value);
    if (!sev) {
      diagnostics.push(invalidSeverity(ruleId, value, path));
      return null;
    }
    return { severity: sev };
  }

  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    diagnostics.push(
      diag(
        'CONFIG_INVALID_VALUE',
        trusted(`Rule ${safe(ruleId, 20)} must map to a severity word or an object`),
        path,
      ),
    );
    return null;
  }

  const obj = value as { severity?: unknown; options?: unknown };
  const out: RuleConfig = {};

  if (obj.severity !== undefined) {
    const sev = parseSeverityOverride(obj.severity);
    if (!sev) {
      diagnostics.push(invalidSeverity(ruleId, obj.severity, path));
      return null;
    }
    out.severity = sev;
  }

  if (obj.options !== undefined) {
    if (typeof obj.options !== 'object' || obj.options === null || Array.isArray(obj.options)) {
      diagnostics.push(
        diag(
          'CONFIG_INVALID_VALUE',
          trusted(`Rule ${safe(ruleId, 20)}: \`options\` must be an object`),
          path,
        ),
      );
    } else {
      out.options = obj.options as Record<string, unknown>;
    }
  }

  return out;
}

function invalidSeverity(ruleId: string, value: unknown, path?: string): ConfigDiagnostic {
  return diag(
    'CONFIG_INVALID_VALUE',
    trusted(
      `Rule ${safe(ruleId, 20)}: severity must be one of ` +
        `off, info, low, medium, high, critical (got ${safe(String(typeof value === 'string' ? value : typeof value), 20)})`,
    ),
    path,
  );
}

/**
 * Find and load a config.
 *
 * `panelint.config.json` wins over a `panelint` key in `package.json`; both are
 * repo-local and carry exactly the same (low) level of trust.
 */
export function loadConfig(opts: LoadConfigOptions): ResolvedConfig {
  const base: ResolveOptions = {
    allowRepoConfig: opts.allowRepoConfig === true,
    trustInlineSuppressions: opts.trustInlineSuppressions === true,
    refuseInlineSuppressions: opts.refuseInlineSuppressions === true,
  };

  if (opts.configPath) {
    const read = readConfigFile(opts.root, opts.configPath);
    if (!read.ok) {
      const cfg = emptyConfig(base);
      cfg.fatal = true;
      cfg.diagnostics.push(read.diagnostic);
      return cfg;
    }
    return parseInto(read.text, { kind: 'file', path: read.path }, base);
  }

  const configFile = readConfigFile(opts.root, CONFIG_FILENAME);
  if (configFile.ok) {
    return parseInto(configFile.text, { kind: 'file', path: configFile.path }, base);
  }
  if (configFile.exists) {
    const cfg = emptyConfig(base);
    cfg.fatal = true;
    cfg.diagnostics.push(configFile.diagnostic);
    return cfg;
  }

  const pkg = readConfigFile(opts.root, PACKAGE_JSON);
  if (!pkg.ok) return emptyConfig(base);

  let parsed: unknown;
  try {
    parsed = JSON.parse(pkg.text);
  } catch {
    // A package.json Panelint cannot parse is npm's problem, not Panelint's.
    // Discovery stays silent; an explicit --config does not.
    return emptyConfig(base);
  }
  const section = (parsed as Record<string, unknown> | null)?.[PACKAGE_KEY];
  if (section === undefined) return emptyConfig(base);

  return resolveConfig(section, { ...base, origin: { kind: 'package', path: pkg.path } });
}

function parseInto(text: string, origin: ConfigOrigin, base: ResolveOptions): ResolvedConfig {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    const cfg = emptyConfig({ ...base, origin });
    cfg.fatal = true;
    // errorSummary(), never String(error): a parser's toString() can embed a
    // source code frame, and under directory mode that frame is somebody's file.
    cfg.diagnostics.push(
      diag('CONFIG_PARSE_FAILED', trusted(`Config is not valid JSON: ${errorSummary(e)}`), origin.path),
    );
    return cfg;
  }
  return resolveConfig(parsed, { ...base, origin });
}

type ConfigRead =
  | { ok: true; text: string; path: string; exists: true }
  | { ok: false; exists: boolean; diagnostic: ConfigDiagnostic };

/**
 * Read a config candidate.
 *
 * A relative path is resolved through `resolveContained` — it refuses absolute
 * paths, `..` segments, symlinks, denied directories and denied filenames, and
 * re-checks containment on the open descriptor. An absolute path is an explicit
 * operator choice, so it skips containment but keeps every other check.
 */
function readConfigFile(root: string, candidate: string): ConfigRead {
  let absolute: string;

  if (isAbsolute(candidate)) {
    absolute = resolve(candidate);
  } else {
    const contained = resolveContained(root, candidate);
    if (!contained.ok) {
      const missing = contained.reason === 'UNREADABLE' || contained.reason === 'NOT_A_FILE';
      return {
        ok: false,
        exists: !missing,
        diagnostic: diag(
          'CONFIG_READ_FAILED',
          trusted(`Config path refused (${contained.reason}): ${safe(candidate, 80)}`),
          undefined,
          'Config paths must stay inside the scanned tree and must not be symlinks.',
        ),
      };
    }
    absolute = contained.absolute;
  }

  const read = readContained(absolute, MAX_CONFIG_BYTES, true);
  if (!read.ok) {
    const missing = read.reason === 'UNREADABLE';
    return {
      ok: false,
      exists: !missing,
      diagnostic: diag(
        'CONFIG_READ_FAILED',
        trusted(`Config unreadable (${read.reason}): ${safe(candidate, 80)}`),
      ),
    };
  }

  return { ok: true, text: read.text, path: absolute, exists: true };
}

function diag(
  code: ConfigDiagnostic['code'],
  message: ConfigDiagnostic['message'],
  configPath?: string,
  detail?: string,
): ConfigDiagnostic {
  return {
    code,
    message,
    ...(detail ? { detail } : {}),
    ...(configPath ? { configPath } : {}),
  };
}

export { diag as configDiagnostic };

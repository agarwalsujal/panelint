/**
 * The analysis runner — docs/DESIGN.md §3.3.
 *
 * Takes a ResourceSet and a rule list and produces findings. The rule list is a
 * PARAMETER, never an import: the runner must be testable without the catalog,
 * and `panelint --only PANE-CSP-002` is then a filter on a list rather than a
 * flag threaded through the pipeline.
 *
 * Four things happen here that cannot happen inside a rule, because a rule is a
 * pure function of one context:
 *
 *   1. **Requirements.** Directory mode scrapes source and cannot supply
 *      `_meta` — measured, three of 21 servers' only apparent `_meta.ui.csp`
 *      declarations were `https://api.example.com` placeholders in READMEs and
 *      tests. A rule that needs `meta` is SKIPPED there with a diagnostic
 *      naming it, never run against scraped values.
 *   2. **Isolation.** A rule that throws costs one diagnostic, not the scan.
 *      acorn-walk and domutils both raise RangeError on adversarial input, so
 *      every `check()` goes through `contained()`.
 *   3. **The pre-parse depth gate.** parse5 is O(depth²) on nested divs
 *      (measured: 200 KB → 3.9 s) and both the cost and the crash happen
 *      *during* the parse, so `maxNestingDepth` cannot be enforced after it.
 *      The estimate runs on the raw bytes, before parse5 sees them.
 *   4. **Deduplication.** Two rules can describe one fact; neither can know it.
 *      See src/rules/dedup.ts.
 */

import { DEFAULT_LIMITS, Deadline, checkLimit } from './limits.js';
import { contained, estimateNestingDepth, limitDiagnostic } from './safe/guard.js';
import { errorSummary } from './safe/untrusted.js';
import { parseHtml } from './parse/html.js';
import { buildStyleIndex } from './parse/style-index.js';
import { collectScripts } from './parse/js.js';
import { isSetRule } from './types.js';
import { dedupeFindings, type DedupCollapse } from './rules/dedup.js';
import type { RuleRequirement } from './rules/shared/helpers.js';
import type {
  AnyRule,
  DiagnosticCode,
  Finding,
  Limits,
  ResourceSet,
  Rule,
  RuleContext,
  RuleResult,
  ScanDiagnostic,
  ScanError,
  SetRule,
  StyleIndexLike,
  UIResource,
  UndecidedNote,
} from './types.js';

export interface AnalyzeOptions {
  /** Resolved ceilings. Defaults to DEFAULT_LIMITS. */
  limits?: Limits;
  /** Per-rule configuration, keyed by rule ID. Reaches the rule as `ctx.options`. */
  ruleOptions?: Record<string, Record<string, unknown>>;
  /** Collapse duplicate findings across rules. On by default (docs/RULES.md). */
  dedupe?: boolean;
  /** Injectable clock, so the deadline is testable without sleeping. */
  now?: () => number;
}

/** Rules that could not run, grouped by the input this scan mode cannot supply. */
export interface SkippedRules {
  requirement: RuleRequirement;
  count: number;
  ruleIds: string[];
  /** Already phrased for the report: "N rules skipped: …". */
  message: string;
}

export interface AnalyzeResult {
  findings: Finding[];
  undecided: UndecidedNote[];
  diagnostics: ScanDiagnostic[];
  errors: ScanError[];
  /** Per-mode skip summary, so the report can say what this scan could not see. */
  skipped: SkippedRules[];
  /** Every dedup collapse, so the count is auditable. */
  collapsed: DedupCollapse[];
  /** Resources that were actually parsed and analysed. */
  resourcesAnalyzed: number;
  /** Rules that survived the requirements filter. */
  rulesRun: number;
}

/**
 * Analyse a resource set.
 *
 * Never throws. Every failure — a rule that crashes, a resource too deep to
 * parse, a scan mode that cannot supply an input — becomes a diagnostic, an
 * error entry, or an undecided note, because a security tool that dies halfway
 * through reports "clean" for everything it did not reach.
 */
export function analyzeResourceSet(
  set: ResourceSet,
  rules: AnyRule[],
  opts: AnalyzeOptions = {},
): AnalyzeResult {
  const limits = opts.limits ?? DEFAULT_LIMITS;
  const now = opts.now ?? Date.now;
  const diagnostics: ScanDiagnostic[] = [];
  const errors: ScanError[] = [];
  const undecided: UndecidedNote[] = [];
  const rawFindings: Finding[] = [];

  // ── Requirements ────────────────────────────────────────────────────────
  const { runnable, skipped } = partitionByRequirements(set, rules);
  for (const s of skipped) {
    diagnostics.push({
      code: 'CAPABILITY_NOT_DECLARED',
      message: s.message,
      detail: `${s.ruleIds.join(', ')} — ${REQUIREMENT_REASON[s.requirement]}`,
    });
  }

  const perResourceRules = runnable.filter((r): r is Rule => !isSetRule(r));
  const setRules = runnable.filter(isSetRule);

  // ── Per-resource pass ───────────────────────────────────────────────────
  const total = set.resources.length;
  const cap = Math.min(total, limits.maxTotalResources);
  if (total > limits.maxTotalResources) {
    const d = checkLimit('maxTotalResources', total, limits);
    if (d) diagnostics.push(d);
  }

  let resourcesAnalyzed = 0;

  for (let i = 0; i < cap; i++) {
    const resource = set.resources[i]!;
    // Nothing that outlives this iteration holds a reference into the DOM:
    // findings, diagnostics and undecided notes carry strings and numbers only.
    // 500 resources therefore cost one document's worth of memory, not 500.
    if (analyzeOne(resource, perResourceRules, limits, now, opts, {
      diagnostics,
      errors,
      undecided,
      findings: rawFindings,
    })) {
      resourcesAnalyzed++;
    }
  }

  // ── Set pass ────────────────────────────────────────────────────────────
  // Cross-resource rules run once, after everything per-resource, and see the
  // per-resource findings. They are given a copy: a SetRule that mutates the
  // list would make every later rule order-dependent.
  const perResourceSnapshot = [...rawFindings];
  for (const rule of setRules) {
    const outcome = runContained(() => rule.checkSet(set, perResourceSnapshot));
    if (!outcome.ok) {
      errors.push(setRuleError(rule, outcome));
      undecided.push({
        ruleId: rule.id,
        resourceUri: '',
        reason: `the rule failed to evaluate (${outcome.reason}); its result is unknown, not clean`,
      });
      continue;
    }
    rawFindings.push(...outcome.value);
  }

  // ── Dedup ───────────────────────────────────────────────────────────────
  const deduped =
    opts.dedupe === false
      ? { findings: rawFindings, collapsed: [] as DedupCollapse[] }
      : dedupeFindings(rawFindings);

  return {
    findings: deduped.findings,
    undecided,
    diagnostics,
    errors,
    skipped,
    collapsed: deduped.collapsed,
    resourcesAnalyzed,
    rulesRun: runnable.length,
  };
}

// ---------------------------------------------------------------------------
// One resource
// ---------------------------------------------------------------------------

interface Sink {
  diagnostics: ScanDiagnostic[];
  errors: ScanError[];
  undecided: UndecidedNote[];
  findings: Finding[];
}

/** Returns true when the resource was parsed and rules were given a chance. */
function analyzeOne(
  resource: UIResource,
  rules: Rule[],
  limits: Limits,
  now: () => number,
  opts: AnalyzeOptions,
  sink: Sink,
): boolean {
  const raw = resource.content;

  const bytes = Buffer.byteLength(raw, 'utf8');
  const byteDiag = checkLimit('maxResourceBytes', bytes, limits, resource.uri);
  if (byteDiag) {
    sink.diagnostics.push(byteDiag);
    return false;
  }

  // ── The pre-parse depth gate ────────────────────────────────────────────
  // This has to happen on the raw bytes. parse5's cost is O(depth²) and the
  // stack overflow inside its tree construction both occur DURING the parse,
  // so a post-parse depth check is a check that never runs.
  const depth = estimateNestingDepth(raw, limits.maxNestingDepth);
  if (depth.exceeded) {
    sink.diagnostics.push(
      limitDiagnostic(
        'HTML nesting depth',
        `estimated depth ${depth.depth} exceeds maxNestingDepth (${limits.maxNestingDepth}); ` +
          'the resource was NOT parsed, because parse5 is O(depth²) and both the cost and ' +
          'the crash happen during the parse. No rule ran against this resource.',
        resource.uri,
      ),
    );
    return false;
  }

  const parsed = runContained(() => parseHtml(raw, limits, resource.uri));
  if (!parsed.ok) {
    sink.errors.push({
      code: 'PARSE_FAILED',
      message: `HTML parsing failed (${parsed.reason}); no rule ran against this resource.`,
      resourceUri: resource.uri,
    });
    return false;
  }
  const { dom, diagnostics: parseDiagnostics } = parsed.value;
  sink.diagnostics.push(...parseDiagnostics);

  // A style index that cannot be built degrades to an empty one, so markup
  // rules still run. Losing CSS is a missed detection; losing the resource is
  // a silent pass on everything else in it.
  const styleOutcome = runContained(() => buildStyleIndex(dom, limits, resource.uri));
  let styles: StyleIndexLike = EMPTY_STYLES;
  if (styleOutcome.ok) {
    styles = styleOutcome.value;
    sink.diagnostics.push(...styleOutcome.value.diagnostics);
    // Undecided is not clean: an unmodelled at-rule means the cascade cannot be
    // trusted on the nodes it reached, and the report footer has to say so.
    for (const reason of styleOutcome.value.undecidedReasons()) {
      sink.diagnostics.push({ code: 'UNDECIDED_CASCADE', message: reason, resourceUri: resource.uri });
    }
  } else {
    sink.diagnostics.push({
      code: 'PARSE_FAILED',
      message: `The style index could not be built (${styleOutcome.reason}); CSS-dependent rules see no declarations.`,
      resourceUri: resource.uri,
    });
  }

  const scriptOutcome = runContained(() => collectScripts(dom, raw, limits));
  if (!scriptOutcome.ok) {
    sink.diagnostics.push({
      code: 'PARSE_FAILED',
      message: `Script collection failed (${scriptOutcome.reason}); script rules see no scripts.`,
      resourceUri: resource.uri,
    });
  }
  const scripts = scriptOutcome.ok ? scriptOutcome.value : [];

  // ── The per-resource wall-clock budget ──────────────────────────────────
  // Cooperative, checked BETWEEN rules. A synchronous parse or selector match
  // cannot be interrupted from the outside without a worker, so the ceiling
  // bounds the work that is still to be started, not the time already spent.
  // The pre-parse gates above are what bound the uninterruptible part.
  const deadline = new Deadline(limits.perResourceMs, now);

  for (let i = 0; i < rules.length; i++) {
    if (deadline.expired) {
      const remaining = rules.length - i;
      sink.diagnostics.push({
        code: 'LIMIT_EXCEEDED',
        message: `perResourceMs budget exhausted; ${remaining} rule${remaining === 1 ? '' : 's'} did not run.`,
        resourceUri: resource.uri,
        detail:
          'The budget is checked between rules. A synchronous parse or selector match cannot be ' +
          'interrupted, so this ceiling bounds work not yet started, not wall clock already spent. ' +
          'Analysis of this resource is incomplete.',
      });
      break;
    }

    const rule = rules[i]!;
    const ctx = makeContext(resource, dom, styles, scripts, limits, opts, rule.id, sink);
    const outcome = runContained(() => rule.check(ctx));

    if (!outcome.ok) {
      sink.errors.push({
        code: 'INTERNAL_ERROR',
        message: `Rule ${rule.id} failed: ${outcome.summary}`,
        resourceUri: resource.uri,
      });
      // A rule that crashed did not decide anything. Recording it as undecided
      // keeps "no finding" from meaning two different things.
      sink.undecided.push({
        ruleId: rule.id,
        resourceUri: resource.uri,
        reason: `the rule failed to evaluate (${outcome.reason}); its result is unknown, not clean`,
      });
      continue;
    }

    const result: RuleResult = outcome.value;
    sink.findings.push(...result.findings);
    if (result.undecided) sink.undecided.push(...result.undecided);
  }

  return true;
}

function makeContext(
  resource: UIResource,
  dom: RuleContext['dom'],
  styles: StyleIndexLike,
  scripts: RuleContext['scripts'],
  limits: Limits,
  opts: AnalyzeOptions,
  ruleId: string,
  sink: Sink,
): RuleContext {
  return {
    resource,
    dom,
    styles,
    // Resolved, read-wins. `resolveMeta` already ran in the acquire layer; this
    // only normalises "absent" to null so a rule never sees `undefined`.
    meta: resource.meta ?? null,
    schemaErrors: resource.schemaErrors,
    scripts,
    // The RAW resource text. PANE-HIDDEN-009 and -011 look for carriers parse5
    // normalises away — tag characters, entity-encoded bidi controls — so they
    // need the undecoded bytes, not the serialized tree.
    rawSource: resource.content,
    options: opts.ruleOptions?.[ruleId] ?? {},
    limits,
    diagnostic(code: DiagnosticCode, message: string, detail?: string): void {
      sink.diagnostics.push({
        code,
        // Truncated, not escaped: every other ScanDiagnostic producer emits raw
        // text and the report layer escapes once. Escaping here would double.
        message: clip(message),
        resourceUri: resource.uri,
        ...(detail !== undefined ? { detail: clip(detail) } : {}),
      });
    },
  };
}

/** A diagnostic is a sentence, not a channel for resource content. */
const MAX_DIAGNOSTIC_CHARS = 500;
function clip(s: string): string {
  return s.length > MAX_DIAGNOSTIC_CHARS ? `${s.slice(0, MAX_DIAGNOSTIC_CHARS)}…` : s;
}

// ---------------------------------------------------------------------------
// Containment
// ---------------------------------------------------------------------------

type Outcome<T> =
  | { ok: true; value: T }
  | { ok: false; reason: 'RANGE_ERROR' | 'THREW'; summary: string };

/**
 * `contained()`, plus the error's class name.
 *
 * The thrown value is captured on the way past so `errorSummary()` can name the
 * class and position. `String(error)` must never reach an output channel:
 * postcss's `CssSyntaxError.toString()` embeds a source code frame, which under
 * directory mode reproduces an arbitrary file's contents into a CI log.
 */
function runContained<T>(fn: () => T): Outcome<T> {
  let thrown: unknown;
  const r = contained<T>(() => {
    try {
      return fn();
    } catch (e) {
      thrown = e;
      throw e;
    }
  });
  if (r.ok) return { ok: true, value: r.value };
  return { ok: false, reason: r.reason, summary: String(errorSummary(thrown)) };
}

function setRuleError(rule: SetRule, outcome: { reason: string; summary: string }): ScanError {
  return {
    code: 'INTERNAL_ERROR',
    message: `Set rule ${rule.id} failed: ${outcome.summary}`,
  };
}

// ---------------------------------------------------------------------------
// Requirements
// ---------------------------------------------------------------------------

const REQUIREMENT_REASON: Readonly<Record<RuleRequirement, string>> = Object.freeze({
  meta: 'directory mode scrapes source, and a source-level walker cannot tell a declaration from ' +
    'an example of one (measured: three of 21 servers’ only apparent _meta.ui.csp values were ' +
    'placeholders in READMEs and tests)',
  listMeta:
    'the resources/list response is not available in this scan mode, so the list-level _meta.ui ' +
    'cannot be compared with the read-level one',
  tools: 'no tools were acquired in this scan',
  content: 'no resource content was acquired in this scan',
  capabilities:
    'the server’s initialize result was not observed, so its declared capabilities are unknown',
});

/**
 * What this scan mode can supply.
 *
 * The question is about the MODE, not about an individual resource. A resource
 * with no `_meta.ui` is a fact a rule may want to report ("no CSP declared");
 * a mode that cannot observe `_meta.ui` at all is a rule that must not run.
 */
function canSupply(set: ResourceSet, req: RuleRequirement): boolean {
  switch (req) {
    case 'meta':
    case 'listMeta':
      return set.source !== 'directory';
    case 'tools':
      return set.tools.length > 0;
    case 'capabilities':
      return set.declaresUiExtension !== undefined;
    case 'content':
      return set.resources.length > 0;
    default:
      return true;
  }
}

function requirementsOf(rule: AnyRule): RuleRequirement[] {
  const r = (rule as { requires?: unknown }).requires;
  return Array.isArray(r) ? (r as RuleRequirement[]) : [];
}

/** Requirement order in the report is fixed, not discovery order. */
const REQUIREMENT_ORDER: readonly RuleRequirement[] = Object.freeze([
  'content',
  'meta',
  'listMeta',
  'tools',
  'capabilities',
]);

function partitionByRequirements(
  set: ResourceSet,
  rules: AnyRule[],
): { runnable: AnyRule[]; skipped: SkippedRules[] } {
  const runnable: AnyRule[] = [];
  const byRequirement = new Map<RuleRequirement, string[]>();

  for (const rule of rules) {
    // A rule is charged to the FIRST requirement it fails, in a fixed order, so
    // the counts add up to the number of skipped rules rather than double
    // counting a rule that needs two things this mode cannot supply.
    const unmet = REQUIREMENT_ORDER.find(
      (req) => requirementsOf(rule).includes(req) && !canSupply(set, req),
    );
    if (unmet === undefined) {
      runnable.push(rule);
      continue;
    }
    const bucket = byRequirement.get(unmet);
    if (bucket) bucket.push(rule.id);
    else byRequirement.set(unmet, [rule.id]);
  }

  const skipped: SkippedRules[] = [];
  for (const requirement of REQUIREMENT_ORDER) {
    const ruleIds = byRequirement.get(requirement);
    if (!ruleIds) continue;
    skipped.push({
      requirement,
      count: ruleIds.length,
      ruleIds: [...ruleIds].sort(),
      message: `${ruleIds.length} rule${ruleIds.length === 1 ? '' : 's'} skipped: this scan mode cannot supply ${requirement}.`,
    });
  }

  return { runnable, skipped };
}

// ---------------------------------------------------------------------------

/** Used when the style index could not be built. Empty, never undefined. */
const EMPTY_STYLES: StyleIndexLike = Object.freeze({
  declaredStyle: () => new Map(),
  candidatesFor: () => [],
  isUndecided: () => false,
  undecidedReasons: () => [],
  allDeclarations: () => [],
});

export { dedupeFindings };
export type { DedupCollapse };

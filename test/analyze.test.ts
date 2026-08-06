import { describe, it, expect } from 'vitest';
import { analyzeResourceSet } from '../src/analyze.js';
import { defineRule } from '../src/rules/shared/helpers.js';
import { DEFAULT_LIMITS } from '../src/limits.js';
import type {
  AcquireSource,
  AnyRule,
  Finding,
  ResourceSet,
  RuleContext,
  RuleResult,
  SetRule,
  UIResource,
  UIResourceMeta,
} from '../src/types.js';
import type { RuleRequirement } from '../src/rules/shared/helpers.js';

/**
 * The analysis runner.
 *
 * Two things it must get right that no rule can get right on its own:
 *
 *   1. Isolation. A rule that throws — including a RangeError from a recursive
 *      third-party call, which acorn-walk and domutils both produce on
 *      adversarial input — must cost one diagnostic, not the scan.
 *   2. Requirements. Directory mode scrapes source and CANNOT supply `_meta`.
 *      Running a `requires: ['meta']` rule there evaluates placeholder values
 *      out of READMEs (measured: three of 21 servers). It is skipped instead.
 */

// ---------------------------------------------------------------------------
// Fakes. Deliberately NOT the real registry — the runner takes rules as a
// parameter precisely so this file cannot depend on the catalog.
// ---------------------------------------------------------------------------

function fakeRule(
  id: string,
  check: (ctx: RuleContext) => RuleResult,
  requires: RuleRequirement[] = [],
): AnyRule {
  return defineRule({
    id,
    ruleClass: 'RISK',
    severity: 'MEDIUM',
    confidence: 'HIGH',
    title: `fake ${id}`,
    remediation: 'none',
    experimental: false,
    status: 'active',
    since: '0.1.0',
    requires,
    check,
  });
}

let fp = 0;
function fakeFinding(ctx: RuleContext, ruleId: string, over: Partial<Finding> = {}): Finding {
  fp++;
  return {
    ruleId,
    ruleClass: 'RISK',
    severity: 'MEDIUM',
    confidence: 'HIGH',
    experimental: false,
    message: `${ruleId} fired`,
    resourceUri: ctx.resource.uri,
    fingerprint: `fake-${fp}`,
    ...over,
  };
}

/** A rule that reports once per resource, so we can count invocations. */
function counterRule(id: string, requires: RuleRequirement[] = []): AnyRule {
  return fakeRule(id, (ctx) => ({ findings: [fakeFinding(ctx, id)] }), requires);
}

function resource(uri: string, content: string, over: Partial<UIResource> = {}): UIResource {
  return {
    uri,
    mimeType: 'text/html;profile=mcp-app',
    content,
    schemaErrors: [],
    contentHash: `sha256:${uri}`,
    source: 'stdio',
    ...over,
  };
}

function resourceSet(resources: UIResource[], over: Partial<ResourceSet> = {}): ResourceSet {
  return {
    resources,
    tools: [],
    diagnostics: [],
    errors: [],
    scannedAt: '2026-08-05T00:00:00.000Z',
    source: 'stdio' as AcquireSource,
    declaresUiExtension: true,
    ...over,
  };
}

const ids = (f: Finding[]): string[] => f.map((x) => x.ruleId);

// ---------------------------------------------------------------------------

describe('the per-resource pass', () => {
  it('runs every rule against every resource', () => {
    const set = resourceSet([
      resource('ui://s/a', '<p>a</p>'),
      resource('ui://s/b', '<p>b</p>'),
    ]);
    const out = analyzeResourceSet(set, [counterRule('PANE-FAKE-001'), counterRule('PANE-FAKE-002')], {});
    expect(out.findings).toHaveLength(4);
    expect(out.resourcesAnalyzed).toBe(2);
  });

  it('builds the context the way types.ts specifies', () => {
    const seen: RuleContext[] = [];
    const html =
      '<html><head><style>.x{display:none}</style></head>' +
      '<body><div class="x" onclick="go()">&#x41;</div><script>var a=1</script></body></html>';

    const meta: UIResourceMeta = { domain: 'https://example.test' };
    const set = resourceSet([resource('ui://s/a', html, { meta })]);
    analyzeResourceSet(set, [fakeRule('PANE-FAKE-001', (ctx) => { seen.push(ctx); return { findings: [] }; })], {});

    expect(seen).toHaveLength(1);
    const ctx = seen[0]!;
    expect(ctx.resource.uri).toBe('ui://s/a');
    expect(ctx.meta).toEqual(meta);
    expect(ctx.limits).toEqual(DEFAULT_LIMITS);
    expect(ctx.schemaErrors).toEqual([]);
    // domhandler Document, not the parse5 default tree.
    expect(ctx.dom.type).toBe('root');
    // Two scripts: the inline <script> and the onclick handler.
    expect(ctx.scripts).toHaveLength(2);
    // The style index is bound to this document.
    expect(ctx.styles.allDeclarations()).toEqual([
      { selector: '.x', prop: 'display', value: 'none', location: expect.anything() },
    ]);
  });

  it('passes rawSource undecoded — PANE-HIDDEN-009/-011 need the original bytes', () => {
    let raw = '';
    let domText = '';
    const html = '<div>&#x41;&#xE0041;</div>';
    const set = resourceSet([resource('ui://s/a', html)]);
    analyzeResourceSet(
      set,
      [
        fakeRule('PANE-FAKE-001', (ctx) => {
          raw = ctx.rawSource;
          domText = JSON.stringify(ctx.dom.children.length > 0);
          return { findings: [] };
        }),
      ],
      {},
    );
    expect(raw).toBe(html);
    expect(raw).toContain('&#xE0041;');
    expect(domText).toBe('true');
  });

  it('resolves meta as null when the resource carries none', () => {
    let seen: unknown = 'unset';
    const set = resourceSet([resource('ui://s/a', '<p>x</p>')]);
    analyzeResourceSet(set, [fakeRule('PANE-FAKE-001', (ctx) => { seen = ctx.meta; return { findings: [] }; })], {});
    expect(seen).toBeNull();
  });

  it('routes ctx.diagnostic() into the result, tagged with the resource', () => {
    const set = resourceSet([resource('ui://s/a', '<p>x</p>')]);
    const out = analyzeResourceSet(
      set,
      [
        fakeRule('PANE-FAKE-001', (ctx) => {
          ctx.diagnostic('SELECTOR_SKIPPED', 'a selector was not tractable', 'detail');
          return { findings: [] };
        }),
      ],
      {},
    );
    const d = out.diagnostics.find((x) => x.code === 'SELECTOR_SKIPPED');
    expect(d).toBeDefined();
    expect(d!.resourceUri).toBe('ui://s/a');
    expect(d!.detail).toBe('detail');
  });

  it('collects undecided notes — undecided is not clean', () => {
    const set = resourceSet([resource('ui://s/a', '<p>x</p>')]);
    const out = analyzeResourceSet(
      set,
      [
        fakeRule('PANE-FAKE-001', (ctx) => ({
          findings: [],
          undecided: [{ ruleId: 'PANE-FAKE-001', resourceUri: ctx.resource.uri, reason: 'var() in color' }],
        })),
      ],
      {},
    );
    expect(out.undecided).toHaveLength(1);
    expect(out.undecided[0]!.reason).toBe('var() in color');
  });

  it('surfaces StyleIndex undecided reasons — @layer marks the cascade unmodelled', () => {
    const html = '<style>@layer a{.x{opacity:0}}</style><div class="x">hi</div>';
    const out = analyzeResourceSet(resourceSet([resource('ui://s/a', html)]), [], {});
    const cascade = out.diagnostics.filter((d) => d.code === 'UNDECIDED_CASCADE');
    expect(cascade.length).toBeGreaterThan(0);
    expect(cascade[0]!.resourceUri).toBe('ui://s/a');
  });
});

describe('rule requirements — the acquisition mode decides what can run', () => {
  it('skips a requires:[meta] rule in directory mode and names it in a diagnostic', () => {
    const set = resourceSet([resource('ui://s/a', '<p>x</p>', { source: 'directory' })], {
      source: 'directory',
      declaresUiExtension: undefined,
    });
    const out = analyzeResourceSet(set, [counterRule('PANE-FAKE-META', ['meta'])], {});

    expect(out.findings).toHaveLength(0);
    const skip = out.skipped.find((s) => s.requirement === 'meta');
    expect(skip).toBeDefined();
    expect(skip!.ruleIds).toEqual(['PANE-FAKE-META']);
    expect(skip!.count).toBe(1);
    expect(skip!.message).toContain('meta');

    const diag = out.diagnostics.find((d) => d.code === 'CAPABILITY_NOT_DECLARED');
    expect(diag).toBeDefined();
    expect(diag!.detail).toContain('PANE-FAKE-META');
  });

  it('runs a requires:[meta] rule when the mode can supply meta', () => {
    const set = resourceSet([resource('ui://s/a', '<p>x</p>', { meta: { prefersBorder: true } })]);
    const out = analyzeResourceSet(set, [counterRule('PANE-FAKE-META', ['meta'])], {});
    expect(ids(out.findings)).toEqual(['PANE-FAKE-META']);
    expect(out.skipped).toHaveLength(0);
  });

  it('skips a requires:[tools] rule when no tools were acquired', () => {
    const out = analyzeResourceSet(
      resourceSet([resource('ui://s/a', '<p>x</p>')]),
      [counterRule('PANE-FAKE-TOOLS', ['tools'])],
      {},
    );
    expect(out.findings).toHaveLength(0);
    expect(out.skipped.map((s) => s.requirement)).toEqual(['tools']);
  });

  it('skips a requires:[capabilities] rule when initialize was never observed', () => {
    const set = resourceSet([resource('ui://s/a', '<p>x</p>')], { declaresUiExtension: undefined });
    const out = analyzeResourceSet(set, [counterRule('PANE-FAKE-CAP', ['capabilities'])], {});
    expect(out.findings).toHaveLength(0);
    expect(out.skipped.map((s) => s.requirement)).toEqual(['capabilities']);
  });

  it('groups the skip count per requirement, so the report can say "N rules skipped"', () => {
    const set = resourceSet([resource('ui://s/a', '<p>x</p>', { source: 'directory' })], {
      source: 'directory',
      declaresUiExtension: undefined,
    });
    const out = analyzeResourceSet(
      set,
      [
        counterRule('PANE-FAKE-M1', ['meta']),
        counterRule('PANE-FAKE-M2', ['meta']),
        counterRule('PANE-FAKE-T1', ['tools']),
        counterRule('PANE-FAKE-OK'),
      ],
      {},
    );
    expect(ids(out.findings)).toEqual(['PANE-FAKE-OK']);
    const meta = out.skipped.find((s) => s.requirement === 'meta')!;
    expect(meta.count).toBe(2);
    expect(meta.ruleIds).toEqual(['PANE-FAKE-M1', 'PANE-FAKE-M2']);
  });

  it('runs a rule with no declared requirements anywhere', () => {
    const set = resourceSet([resource('ui://s/a', '<p>x</p>', { source: 'directory' })], {
      source: 'directory',
      declaresUiExtension: undefined,
    });
    const out = analyzeResourceSet(set, [counterRule('PANE-FAKE-001')], {});
    expect(ids(out.findings)).toEqual(['PANE-FAKE-001']);
  });
});

describe('isolation — a rule that throws must not take the scan down', () => {
  it('contains a plain throw, records an error, and keeps running the others', () => {
    const boom = fakeRule('PANE-FAKE-BOOM', () => {
      throw new TypeError('cannot read x of undefined');
    });
    const out = analyzeResourceSet(
      resourceSet([resource('ui://s/a', '<p>x</p>')]),
      [boom, counterRule('PANE-FAKE-OK')],
      {},
    );
    expect(ids(out.findings)).toEqual(['PANE-FAKE-OK']);

    const err = out.errors.find((e) => e.message.includes('PANE-FAKE-BOOM'));
    expect(err).toBeDefined();
    expect(err!.code).toBe('INTERNAL_ERROR');
    expect(err!.resourceUri).toBe('ui://s/a');
    // errorSummary() only — never String(error), which leaks source frames.
    expect(err!.message).toContain('TypeError');
    expect(err!.message).not.toContain('cannot read x of undefined');
  });

  it('contains a RangeError — acorn-walk and domutils both produce one', () => {
    const boom = fakeRule('PANE-FAKE-RANGE', () => {
      throw new RangeError('Maximum call stack size exceeded');
    });
    const out = analyzeResourceSet(
      resourceSet([resource('ui://s/a', '<p>x</p>')]),
      [boom, counterRule('PANE-FAKE-OK')],
      {},
    );
    expect(ids(out.findings)).toEqual(['PANE-FAKE-OK']);
    expect(out.errors.some((e) => e.message.includes('RangeError'))).toBe(true);
  });

  it('records the failed rule as undecided, not as clean', () => {
    const boom = fakeRule('PANE-FAKE-BOOM', () => {
      throw new Error('nope');
    });
    const out = analyzeResourceSet(resourceSet([resource('ui://s/a', '<p>x</p>')]), [boom], {});
    expect(out.undecided.map((u) => u.ruleId)).toEqual(['PANE-FAKE-BOOM']);
  });

  it('keeps analysing later resources after a rule throws on an earlier one', () => {
    let n = 0;
    const flaky = fakeRule('PANE-FAKE-FLAKY', (ctx) => {
      n++;
      if (n === 1) throw new Error('first resource only');
      return { findings: [fakeFinding(ctx, 'PANE-FAKE-FLAKY')] };
    });
    const out = analyzeResourceSet(
      resourceSet([resource('ui://s/a', '<p>a</p>'), resource('ui://s/b', '<p>b</p>')]),
      [flaky],
      {},
    );
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]!.resourceUri).toBe('ui://s/b');
  });

  it('contains a SetRule that throws', () => {
    const badSet: SetRule = {
      id: 'PANE-FAKE-SET',
      ruleClass: 'RISK',
      severity: 'MEDIUM',
      confidence: 'HIGH',
      title: 'bad set rule',
      remediation: 'none',
      experimental: false,
      status: 'active',
      since: '0.1.0',
      checkSet() {
        throw new RangeError('deep');
      },
    };
    const out = analyzeResourceSet(resourceSet([resource('ui://s/a', '<p>x</p>')]), [badSet], {});
    expect(out.errors.some((e) => e.message.includes('PANE-FAKE-SET'))).toBe(true);
  });
});

describe('the pre-parse depth gate', () => {
  const deep = (n: number): string => '<div>'.repeat(n) + 'x' + '</div>'.repeat(n);

  it('refuses to parse a resource over maxNestingDepth', () => {
    let ran = false;
    const out = analyzeResourceSet(
      resourceSet([resource('ui://s/deep', deep(60))]),
      [fakeRule('PANE-FAKE-001', () => { ran = true; return { findings: [] }; })],
      { limits: { ...DEFAULT_LIMITS, maxNestingDepth: 20 } },
    );
    expect(ran).toBe(false);
    const d = out.diagnostics.find((x) => x.code === 'LIMIT_EXCEEDED');
    expect(d).toBeDefined();
    expect(d!.resourceUri).toBe('ui://s/deep');
    expect(d!.detail).toContain('maxNestingDepth');
    expect(out.resourcesAnalyzed).toBe(0);
  });

  it('still analyses the other resources in the set', () => {
    const out = analyzeResourceSet(
      resourceSet([resource('ui://s/deep', deep(60)), resource('ui://s/ok', '<p>x</p>')]),
      [counterRule('PANE-FAKE-001')],
      { limits: { ...DEFAULT_LIMITS, maxNestingDepth: 20 } },
    );
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]!.resourceUri).toBe('ui://s/ok');
  });

  it('parses normally under the ceiling', () => {
    const out = analyzeResourceSet(
      resourceSet([resource('ui://s/ok', deep(10))]),
      [counterRule('PANE-FAKE-001')],
      { limits: { ...DEFAULT_LIMITS, maxNestingDepth: 500 } },
    );
    expect(out.findings).toHaveLength(1);
  });
});

describe('budgets', () => {
  it('stops at maxTotalResources and says so', () => {
    const set = resourceSet(
      Array.from({ length: 5 }, (_, i) => resource(`ui://s/${i}`, '<p>x</p>')),
    );
    const out = analyzeResourceSet(set, [counterRule('PANE-FAKE-001')], {
      limits: { ...DEFAULT_LIMITS, maxTotalResources: 3 },
    });
    expect(out.resourcesAnalyzed).toBe(3);
    expect(out.findings).toHaveLength(3);
    expect(out.diagnostics.some((d) => d.code === 'LIMIT_EXCEEDED' && d.message.includes('maxTotalResources'))).toBe(true);
  });

  it('refuses a resource over maxResourceBytes without parsing it', () => {
    const out = analyzeResourceSet(
      resourceSet([resource('ui://s/big', '<p>' + 'x'.repeat(5000) + '</p>')]),
      [counterRule('PANE-FAKE-001')],
      { limits: { ...DEFAULT_LIMITS, maxResourceBytes: 100 } },
    );
    expect(out.findings).toHaveLength(0);
    expect(out.diagnostics.some((d) => d.message.includes('maxResourceBytes'))).toBe(true);
  });

  it('stops running rules once the per-resource deadline has passed', () => {
    // The ceiling is on WORK between rules, not on wall clock inside one — a
    // synchronous parse cannot be interrupted. The clock is injected so this is
    // a assertion about the check, not about how fast the machine is.
    const times = [0, 0, 100_000, 100_000, 100_000];
    let i = 0;
    const now = (): number => times[i++] ?? 100_000;

    const out = analyzeResourceSet(
      resourceSet([resource('ui://s/a', '<p>x</p>')]),
      [counterRule('PANE-FAKE-001'), counterRule('PANE-FAKE-002'), counterRule('PANE-FAKE-003')],
      { now, limits: { ...DEFAULT_LIMITS, perResourceMs: 5_000 } },
    );
    expect(ids(out.findings)).toEqual(['PANE-FAKE-001']);
    const d = out.diagnostics.find((x) => x.code === 'LIMIT_EXCEEDED' && x.message.includes('perResourceMs'));
    expect(d).toBeDefined();
    expect(d!.message).toContain('2 rule');
  });
});

describe('set rules', () => {
  it('runs once over the whole set, after the per-resource pass', () => {
    let calls = 0;
    let sawResources = 0;
    let sawFindings = 0;
    const setRule: SetRule = {
      id: 'PANE-FAKE-SET',
      ruleClass: 'SPEC',
      severity: 'MEDIUM',
      confidence: 'CERTAIN',
      title: 'set rule',
      remediation: 'none',
      experimental: false,
      status: 'active',
      since: '0.1.0',
      checkSet(set, perResource) {
        calls++;
        sawResources = set.resources.length;
        sawFindings = perResource.length;
        return [
          {
            ruleId: 'PANE-FAKE-SET',
            ruleClass: 'SPEC',
            severity: 'MEDIUM',
            confidence: 'CERTAIN',
            experimental: false,
            message: 'set finding',
            resourceUri: set.resources[0]!.uri,
            fingerprint: 'set-1',
          },
        ];
      },
    };

    const out = analyzeResourceSet(
      resourceSet([resource('ui://s/a', '<p>a</p>'), resource('ui://s/b', '<p>b</p>')]),
      [counterRule('PANE-FAKE-001'), setRule],
      {},
    );
    expect(calls).toBe(1);
    expect(sawResources).toBe(2);
    expect(sawFindings).toBe(2);
    expect(ids(out.findings)).toContain('PANE-FAKE-SET');
  });
});

describe('deduplication is wired in', () => {
  it('collapses a documented collision pair produced by two rules', () => {
    const cspRule = fakeRule('PANE-CSP-002', (ctx) => ({
      findings: [
        fakeFinding(ctx, 'PANE-CSP-002', { severity: 'CRITICAL', jsonPointer: '/ui/csp/resourceDomains/0' }),
      ],
    }));
    const schemaRule = fakeRule('PANE-SCHEMA-003', (ctx) => ({
      findings: [fakeFinding(ctx, 'PANE-SCHEMA-003', { jsonPointer: '/ui/csp/resourceDomains/0' })],
    }));

    const out = analyzeResourceSet(resourceSet([resource('ui://s/a', '<p>x</p>')]), [schemaRule, cspRule], {});
    expect(ids(out.findings)).toEqual(['PANE-CSP-002']);
    expect(out.collapsed).toHaveLength(1);
  });

  it('can be turned off, and then reports both', () => {
    const cspRule = fakeRule('PANE-CSP-002', (ctx) => ({
      findings: [
        fakeFinding(ctx, 'PANE-CSP-002', { severity: 'CRITICAL', jsonPointer: '/ui/csp/resourceDomains/0' }),
      ],
    }));
    const schemaRule = fakeRule('PANE-SCHEMA-003', (ctx) => ({
      findings: [fakeFinding(ctx, 'PANE-SCHEMA-003', { jsonPointer: '/ui/csp/resourceDomains/0' })],
    }));
    const out = analyzeResourceSet(resourceSet([resource('ui://s/a', '<p>x</p>')]), [schemaRule, cspRule], {
      dedupe: false,
    });
    expect(out.findings).toHaveLength(2);
    expect(out.collapsed).toHaveLength(0);
  });
});

describe('empty inputs', () => {
  it('returns an empty result for an empty set rather than throwing', () => {
    const out = analyzeResourceSet(resourceSet([]), [counterRule('PANE-FAKE-001')], {});
    expect(out.findings).toEqual([]);
    expect(out.resourcesAnalyzed).toBe(0);
  });

  it('returns an empty result for an empty rule list', () => {
    const out = analyzeResourceSet(resourceSet([resource('ui://s/a', '<p>x</p>')]), [], {});
    expect(out.findings).toEqual([]);
    expect(out.rulesRun).toBe(0);
  });
});

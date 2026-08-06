import { describe, it, expect } from 'vitest';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { renderText, shouldColor } from '../src/report/text.js';
import { renderJson } from '../src/report/json.js';
import { renderSarif, sarifLevel } from '../src/report/sarif.js';
import {
  SCHEMA_VERSION,
  limitationFor,
  undecidedByCause,
  type ScanReport,
} from '../src/report/types.js';
import type { Finding, RuleMeta } from '../src/types.js';

const here = dirname(fileURLToPath(import.meta.url));
/**
 * Golden files are checked in and compared byte for byte. Regenerate
 * deliberately with PANELINT_WRITE_GOLDEN=1 and review the diff — the envelope
 * is a one-way door for the public directory, so an unreviewed regeneration is
 * how a breaking change ships silently.
 */
const golden = (name: string, actual: string): string => {
  const path = join(here, 'golden', name);
  if (process.env['PANELINT_WRITE_GOLDEN']) {
    writeFileSync(path, actual, 'utf8');
    return actual;
  }
  return readFileSync(path, 'utf8');
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const finding = (over: Partial<Finding> = {}): Finding => ({
  ruleId: 'PANE-CSP-001',
  ruleClass: 'RISK',
  severity: 'HIGH',
  confidence: 'CERTAIN',
  experimental: false,
  message: 'Wildcard connect-src domain declared.',
  resourceUri: 'ui://weather/forecast',
  fingerprint: 'aaaa1111bbbb2222',
  ...over,
});

const RULES: RuleMeta[] = [
  {
    id: 'PANE-CSP-001',
    ruleClass: 'RISK',
    severity: 'HIGH',
    confidence: 'CERTAIN',
    title: 'Wildcard connect-src domain declared',
    specRef: 'SEP-1865 §Security Implications — CSP Enforcement',
    cwe: 'CWE-942',
    remediation: 'Replace the wildcard with the specific origins the app calls.',
    experimental: false,
    status: 'active',
    since: '0.1.0',
  },
  {
    id: 'PANE-SPEC-001',
    ruleClass: 'SPEC',
    severity: 'CRITICAL',
    confidence: 'CERTAIN',
    title: 'UI resource served without the mcp-app profile',
    remediation: 'Serve the resource as `text/html;profile=mcp-app`.',
    experimental: false,
    status: 'active',
    since: '0.1.0',
  },
  {
    id: 'PANE-CONTEXT-001',
    ruleClass: 'INFO',
    severity: 'HIGH',
    confidence: 'CERTAIN',
    title: 'App can write to the model context',
    remediation: 'None. Reported so an operator knows what this app can do.',
    experimental: false,
    status: 'active',
    since: '0.1.0',
  },
  {
    id: 'PANE-HIDDEN-004',
    ruleClass: 'RISK',
    severity: 'MEDIUM',
    confidence: 'HIGH',
    title: 'Text hidden by insufficient contrast',
    remediation: 'Raise the contrast ratio of the affected text.',
    experimental: false,
    status: 'active',
    since: '0.1.0',
  },
];

/** A directory-mode report with one finding per class and two undecided causes. */
function directoryReport(over: Partial<ScanReport> = {}): ScanReport {
  return {
    header: {
      panelintVersion: '0.1.0',
      ruleEngineFingerprint: '3f2a1b0c9d8e7f60',
      mode: 'directory',
      scannedAt: '2026-08-05T12:00:00.000Z',
      target: 'examples/weather-server',
      failOn: 'HIGH',
      suppressed: { inline: 2, config: 1, baseline: 4 },
      resolvedCount: 2,
      declaredCount: 9,
    },
    resources: [
      {
        uri: 'ui://weather/forecast',
        contentHash: 'c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00',
        mimeType: 'text/html;profile=mcp-app',
        byteLength: 4096,
        filePath: 'src/ui/forecast.html',
      },
      {
        uri: 'ui://weather/radar',
        contentHash: 'd15ea5ed15ea5ed15ea5ed15ea5ed15ea5ed15ea5ed15ea5ed15ea5ed15ea5ed',
        mimeType: 'text/html',
        byteLength: 128,
      },
    ],
    findings: [
      finding({
        ruleId: 'PANE-SPEC-001',
        ruleClass: 'SPEC',
        severity: 'CRITICAL',
        message: 'Resource served as text/html without the mcp-app profile.',
        resourceUri: 'ui://weather/radar',
        fingerprint: '1111aaaa2222bbbb',
        location: { startLine: 12, startCol: 3, endLine: 12, endCol: 40 },
      }),
      finding({
        location: { startLine: 4, startCol: 7 },
        evidence: 'connectDomains: ["*"]',
      }),
      finding({
        ruleId: 'PANE-CONTEXT-001',
        ruleClass: 'INFO',
        severity: 'HIGH',
        message: 'App calls app.updateModelContext().',
        fingerprint: 'cccc3333dddd4444',
      }),
      finding({
        ruleId: 'PANE-HIDDEN-004',
        severity: 'MEDIUM',
        confidence: 'HIGH',
        message: 'Text is hidden by a contrast ratio below the threshold.',
        fingerprint: 'eeee5555ffff6666',
        assumption: 'CSP synthesis: the policy a host builds from _meta.ui.csp is unspecified.',
      }),
    ],
    undecided: [
      {
        ruleId: 'PANE-HIDDEN-004',
        resourceUri: 'ui://weather/forecast',
        reason: 'colour supplied via var(), not resolvable without the host stylesheet',
      },
      {
        ruleId: 'PANE-HIDDEN-004',
        resourceUri: 'ui://weather/radar',
        reason: 'colour supplied via var(), not resolvable without the host stylesheet',
      },
      {
        ruleId: 'PANE-HIDDEN-008',
        resourceUri: 'ui://weather/forecast',
        reason: 'unmodelled at-rule @layer: the cascade cannot be trusted here',
      },
    ],
    diagnostics: [
      {
        code: 'UNRESOLVED_URI',
        message: 'resource declared, content not statically resolvable',
        resourceUri: 'ui://weather/alerts',
      },
    ],
    errors: [],
    ...over,
  };
}

function liveReport(over: Partial<ScanReport> = {}): ScanReport {
  const base = directoryReport();
  return {
    ...base,
    header: {
      ...base.header,
      mode: 'stdio',
      target: 'node ./server.js',
      serverName: 'weather',
      resolvedCount: undefined,
      declaredCount: undefined,
    },
    resources: base.resources.map(({ filePath: _drop, ...r }) => r),
    ...over,
  };
}

// ---------------------------------------------------------------------------
// 1. Class × severity → SARIF level. The mapping is the product's positioning.
// ---------------------------------------------------------------------------

describe('sarifLevel — DESIGN.md §3.4, specified explicitly', () => {
  it('maps SPEC and SCHEMA to error at CRITICAL/HIGH and warning below', () => {
    for (const cls of ['SPEC', 'SCHEMA'] as const) {
      expect(sarifLevel(cls, 'CRITICAL')).toBe('error');
      expect(sarifLevel(cls, 'HIGH')).toBe('error');
      expect(sarifLevel(cls, 'MEDIUM')).toBe('warning');
      expect(sarifLevel(cls, 'LOW')).toBe('warning');
      expect(sarifLevel(cls, 'INFO')).toBe('warning');
    }
  });

  it('maps RISK to error at CRITICAL/HIGH, warning at MEDIUM, note below', () => {
    expect(sarifLevel('RISK', 'CRITICAL')).toBe('error');
    expect(sarifLevel('RISK', 'HIGH')).toBe('error');
    expect(sarifLevel('RISK', 'MEDIUM')).toBe('warning');
    expect(sarifLevel('RISK', 'LOW')).toBe('note');
    expect(sarifLevel('RISK', 'INFO')).toBe('note');
  });

  it('maps INFO to note at EVERY severity, including CRITICAL', () => {
    expect(sarifLevel('INFO', 'CRITICAL')).toBe('note');
    expect(sarifLevel('INFO', 'HIGH')).toBe('note');
    expect(sarifLevel('INFO', 'MEDIUM')).toBe('note');
    expect(sarifLevel('INFO', 'LOW')).toBe('note');
    expect(sarifLevel('INFO', 'INFO')).toBe('note');
  });

  it('renders PANE-CONTEXT-001 (INFO/HIGH) as note in the emitted SARIF', () => {
    // The named case from DESIGN.md §3.4. Rendering a capability disclosure as
    // `error` in GitHub's Security tab would make it look like a vulnerability,
    // contradicting GOALS.md N1. This is the assertion that keeps that honest.
    const sarif = JSON.parse(
      renderSarif(
        directoryReport({
          findings: [
            finding({ ruleId: 'PANE-CONTEXT-001', ruleClass: 'INFO', severity: 'HIGH' }),
          ],
        }),
        RULES,
      ),
    );
    const result = sarif.runs[0].results[0];
    expect(result.ruleId).toBe('PANE-CONTEXT-001');
    expect(result.level).toBe('note');

    const rule = sarif.runs[0].tool.driver.rules.find(
      (r: { id: string }) => r.id === 'PANE-CONTEXT-001',
    );
    expect(rule.defaultConfiguration.level).toBe('note');
  });
});

// ---------------------------------------------------------------------------
// 2. No output ever says a server is safe.
// ---------------------------------------------------------------------------

describe('no output issues a verdict about a server', () => {
  const banned = /\b(safe|secure|safety|malicious|clean bill)\b/i;

  const cases: Array<[string, () => string]> = [
    ['text (directory)', () => renderText(directoryReport(), { color: false })],
    ['text (live)', () => renderText(liveReport(), { color: false })],
    ['text (empty scan)', () =>
      renderText(directoryReport({ findings: [], undecided: [], diagnostics: [], errors: [] }), {
        color: false,
      })],
    ['json (directory)', () => renderJson(directoryReport())],
    ['json (live)', () => renderJson(liveReport())],
    ['sarif (directory)', () => renderSarif(directoryReport(), RULES)],
    ['sarif (live)', () => renderSarif(liveReport(), RULES)],
  ];

  for (const [name, render] of cases) {
    it(`${name} never says safe / secure / malicious / clean bill`, () => {
      const out = render();
      const hit = out.match(banned);
      expect(hit, `banned word ${hit?.[0]} in ${name}`).toBeNull();
    });
  }

  it("does not treat 'unsafe-inline' as a banned word — it is a CSP token", () => {
    // The guard is word-boundary based on purpose. `unsafe-inline` is mandated
    // by the spec's default CSP and must be quotable in evidence.
    expect(banned.test("script-src 'unsafe-inline'")).toBe(false);
  });

  it('states the limitation sentence for the mode it ran in', () => {
    const text = renderText(directoryReport(), { color: false });
    expect(text).toContain(limitationFor('directory'));
    expect(text).not.toContain(limitationFor('stdio'));

    const live = renderText(liveReport(), { color: false });
    expect(live).toContain(limitationFor('stdio'));
  });
});

// ---------------------------------------------------------------------------
// 3. Every header carries the point-in-time facts (DESIGN.md §7).
// ---------------------------------------------------------------------------

describe('report header — DESIGN.md §7 point-in-time honesty', () => {
  it('text carries version, rule-engine fingerprint, mode, limitation, and each contentHash', () => {
    const text = renderText(directoryReport(), { color: false });
    expect(text).toContain('0.1.0');
    expect(text).toContain('3f2a1b0c9d8e7f60');
    expect(text).toContain('directory');
    expect(text).toContain(limitationFor('directory'));
    for (const r of directoryReport().resources) {
      expect(text).toContain(r.contentHash);
    }
  });

  it('json carries them in the envelope', () => {
    const env = JSON.parse(renderJson(directoryReport()));
    expect(env.tool.version).toBe('0.1.0');
    expect(env.tool.ruleEngineFingerprint).toBe('3f2a1b0c9d8e7f60');
    expect(env.scan.mode).toBe('directory');
    expect(env.scan.limitation).toBe(limitationFor('directory'));
    expect(env.resources.map((r: { contentHash: string }) => r.contentHash)).toEqual(
      directoryReport().resources.map((r) => r.contentHash),
    );
  });

  it('sarif carries them on the run and hashes every on-disk artifact', () => {
    const sarif = JSON.parse(renderSarif(directoryReport(), RULES));
    const run = sarif.runs[0];
    expect(run.tool.driver.version).toBe('0.1.0');
    expect(run.tool.driver.semanticVersion).toBe('0.1.0');
    expect(run.properties.ruleEngineFingerprint).toBe('3f2a1b0c9d8e7f60');
    expect(run.properties.mode).toBe('directory');
    expect(run.properties.limitation).toBe(limitationFor('directory'));
    expect(run.automationDetails.id).toContain('3f2a1b0c9d8e7f60');
    expect(run.artifacts[0].hashes['sha-256']).toBe(directoryReport().resources[0]!.contentHash);
    expect(
      run.properties.resources.map((r: { contentHash: string }) => r.contentHash),
    ).toHaveLength(2);
  });

  it('directory mode prints the resolved/declared ratio in every format', () => {
    // A scan that resolved 2 of 9 must not read like a clean bill of health.
    const text = renderText(directoryReport(), { color: false });
    expect(text).toMatch(/resolved 2 of 9/);

    const env = JSON.parse(renderJson(directoryReport()));
    expect(env.scan.resolvedResources).toBe(2);
    expect(env.scan.declaredResources).toBe(9);

    const sarif = JSON.parse(renderSarif(directoryReport(), RULES));
    expect(sarif.runs[0].properties.resolvedResources).toBe(2);
    expect(sarif.runs[0].properties.declaredResources).toBe(9);
  });

  it('omits the ratio for live modes, where it has no meaning', () => {
    expect(renderText(liveReport(), { color: false })).not.toMatch(/resolved \d+ of/);
    expect(JSON.parse(renderJson(liveReport())).scan.resolvedResources).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 4. Suppression provenance — a suppression you cannot see is one an attacker
//    can use.
// ---------------------------------------------------------------------------

describe('suppression provenance', () => {
  it('text prints the breakdown unconditionally, even when everything is zero', () => {
    const zeroed = directoryReport();
    zeroed.header.suppressed = { inline: 0, config: 0, baseline: 0 };
    const text = renderText(zeroed, { color: false });
    expect(text).toMatch(/suppressed/i);
    expect(text).toMatch(/0 inline/);
    expect(text).toMatch(/0 config/);
    expect(text).toMatch(/0 baseline/);
  });

  it('text shows the real counts', () => {
    const text = renderText(directoryReport(), { color: false });
    expect(text).toMatch(/2 inline/);
    expect(text).toMatch(/1 config/);
    expect(text).toMatch(/4 baseline/);
  });

  it('json and sarif carry the same object', () => {
    const expected = { inline: 2, config: 1, baseline: 4 };
    expect(JSON.parse(renderJson(directoryReport())).scan.suppressed).toEqual(expected);
    expect(JSON.parse(renderSarif(directoryReport(), RULES)).runs[0].properties.suppressed).toEqual(
      expected,
    );
  });
});

// ---------------------------------------------------------------------------
// 5. Undecided is not clean.
// ---------------------------------------------------------------------------

describe('undecided is not clean', () => {
  it('groups notes by cause, highest count first', () => {
    const causes = undecidedByCause(directoryReport().undecided);
    expect(causes[0]).toEqual({
      ruleId: 'PANE-HIDDEN-004',
      reason: 'colour supplied via var(), not resolvable without the host stylesheet',
      count: 2,
    });
    expect(causes).toHaveLength(2);
  });

  it('the text footer carries a count broken down by cause', () => {
    const text = renderText(directoryReport(), { color: false });
    expect(text).toMatch(/undecided:\s*3/i);
    expect(text).toContain('PANE-HIDDEN-004');
    expect(text).toContain('colour supplied via var()');
    expect(text).toContain('unmodelled at-rule @layer');
  });

  it('the json envelope carries undecided[] and the cause breakdown', () => {
    const env = JSON.parse(renderJson(directoryReport()));
    expect(env.undecided).toHaveLength(3);
    expect(env.undecided[0].ruleId).toBe('PANE-HIDDEN-004');
    expect(env.scan.counts.undecided).toBe(3);
    expect(env.scan.undecidedByCause).toHaveLength(2);
    expect(env.scan.undecidedByCause[0].count).toBe(2);
  });

  it('a report with zero findings but many undecided does not read as clean', () => {
    const text = renderText(
      directoryReport({ findings: [], diagnostics: [], errors: [] }),
      { color: false },
    );
    expect(text).toMatch(/undecided:\s*3/i);
    expect(text).toMatch(/0 findings? reported/);
  });
});

// ---------------------------------------------------------------------------
// 6. JSON is a versioned envelope and a one-way door.
// ---------------------------------------------------------------------------

describe('json envelope', () => {
  it('has exactly the frozen top-level keys, in order', () => {
    const env = JSON.parse(renderJson(directoryReport()));
    expect(Object.keys(env)).toEqual([
      'schemaVersion',
      'tool',
      'scan',
      'findings',
      'undecided',
      'diagnostics',
      'errors',
      'resources',
    ]);
    expect(env.schemaVersion).toBe(SCHEMA_VERSION);
  });

  it('carries the three classification axes plus experimental on every finding', () => {
    const env = JSON.parse(renderJson(directoryReport()));
    for (const f of env.findings) {
      expect(f).toHaveProperty('class');
      expect(f).toHaveProperty('severity');
      expect(f).toHaveProperty('confidence');
      expect(f).toHaveProperty('experimental');
      expect(f).toHaveProperty('gating');
      expect(f).toHaveProperty('fingerprint');
    }
    // Omitting these would make adding them later a breaking change for the
    // public directory, which consumes this envelope.
    const first = env.findings[0];
    expect(Object.keys(first)).toEqual([
      'ruleId',
      'class',
      'severity',
      'confidence',
      'experimental',
      'gating',
      'message',
      'resourceUri',
      'evidence',
      'location',
      'jsonPointer',
      'assumption',
      'fingerprint',
    ]);
  });

  it('marks gating exactly as src/exit.ts does', () => {
    const env = JSON.parse(renderJson(directoryReport()));
    const byId = Object.fromEntries(
      env.findings.map((f: { ruleId: string; gating: boolean }) => [f.ruleId, f.gating]),
    );
    expect(byId['PANE-SPEC-001']).toBe(true); // SPEC/CRITICAL/CERTAIN
    expect(byId['PANE-CSP-001']).toBe(true); // RISK/HIGH/CERTAIN
    expect(byId['PANE-CONTEXT-001']).toBe(false); // INFO never gates
    expect(byId['PANE-HIDDEN-004']).toBe(false); // MEDIUM < HIGH threshold
  });

  it('matches the golden envelope byte for byte', () => {
    const actual = renderJson(directoryReport());
    expect(actual).toBe(golden('directory.json', actual));
  });

  it('matches the golden live-mode envelope byte for byte', () => {
    const actual = renderJson(liveReport());
    expect(actual).toBe(golden('live.json', actual));
  });
});

// ---------------------------------------------------------------------------
// 7. SARIF specifics.
// ---------------------------------------------------------------------------

describe('sarif', () => {
  it('uses a repo-relative artifactLocation for a directory-scanned resource', () => {
    const sarif = JSON.parse(renderSarif(directoryReport(), RULES));
    const result = sarif.runs[0].results.find(
      (r: { ruleId: string }) => r.ruleId === 'PANE-CSP-001',
    );
    const loc = result.locations[0].physicalLocation;
    expect(loc.artifactLocation.uri).toBe('src/ui/forecast.html');
    expect(loc.artifactLocation.uri.startsWith('/')).toBe(false);
    // No uriBaseId. It was previously emitted as '%SRCROOT%' with no matching
    // originalUriBaseIds entry, which is unresolvable per the SARIF spec. A
    // bare repository-relative URI is what GitHub documents.
    expect(loc.artifactLocation.uriBaseId).toBeUndefined();
    expect(loc.region.startLine).toBe(4);
    expect(loc.region.startColumn).toBe(7);
  });

  it('prefixes file paths when the scan root is not the repository root', () => {
    // filePath is relative to the scan root; GitHub resolves SARIF paths
    // against the repository root. Scanning packages/server therefore emitted
    // alerts pointing at paths that do not exist in the repository.
    const report = directoryReport();
    report.header.pathPrefix = 'packages/server';
    const sarif = JSON.parse(renderSarif(report, RULES));

    expect(sarif.runs[0].artifacts[0].location.uri).toBe(
      'packages/server/src/ui/forecast.html',
    );

    const result = sarif.runs[0].results.find(
      (r: { ruleId: string }) => r.ruleId === 'PANE-CSP-001',
    );
    expect(result.locations[0].physicalLocation.artifactLocation.uri).toBe(
      'packages/server/src/ui/forecast.html',
    );
    // The properties block has to agree with the locations, or a consumer
    // reading either one gets a different answer.
    expect(sarif.runs[0].properties.resources[0].filePath).toBe(
      'packages/server/src/ui/forecast.html',
    );
  });

  it('refuses a traversing path prefix rather than emitting it', () => {
    // The prefix reaches someone else's code scanning alerts. The CLI rejects
    // these before rendering, but the renderer must not depend on its caller
    // having done that — the same reasoning as neutralize().
    const report = directoryReport();
    report.header.pathPrefix = '../../etc';
    const sarif = JSON.parse(renderSarif(report, RULES));

    expect(sarif.runs[0].artifacts).toHaveLength(0);
    const result = sarif.runs[0].results.find(
      (r: { ruleId: string }) => r.ruleId === 'PANE-CSP-001',
    );
    expect(result.locations[0].physicalLocation).toBeUndefined();
    expect(result.locations[0].logicalLocations).toBeDefined();
  });

  it('uses logicalLocations for a live-scanned resource with no file on disk', () => {
    const sarif = JSON.parse(renderSarif(liveReport(), RULES));
    for (const result of sarif.runs[0].results) {
      expect(result.locations[0].physicalLocation).toBeUndefined();
      expect(result.locations[0].logicalLocations[0].fullyQualifiedName).toMatch(/^ui:\/\//);
    }
  });

  it('never emits an absolute or traversing artifact uri', () => {
    const report = directoryReport();
    report.resources[0]!.filePath = '../../../etc/passwd';
    const sarif = JSON.parse(renderSarif(report, RULES));
    const raw = JSON.stringify(sarif);
    expect(raw).not.toContain('etc/passwd');
    const result = sarif.runs[0].results.find(
      (r: { ruleId: string }) => r.ruleId === 'PANE-CSP-001',
    );
    expect(result.locations[0].physicalLocation).toBeUndefined();
  });

  it('carries partialFingerprints from Finding.fingerprint', () => {
    const sarif = JSON.parse(renderSarif(directoryReport(), RULES));
    const fps = sarif.runs[0].results.map(
      (r: { partialFingerprints: Record<string, string> }) =>
        Object.values(r.partialFingerprints)[0],
    );
    expect(fps).toContain('aaaa1111bbbb2222');
    expect(fps).toContain('1111aaaa2222bbbb');
  });

  it('populates tool.driver.rules[] from the registry parameter', () => {
    const sarif = JSON.parse(renderSarif(directoryReport(), RULES));
    const rules = sarif.runs[0].tool.driver.rules;
    expect(rules.map((r: { id: string }) => r.id)).toEqual(RULES.map((r) => r.id));
    const csp = rules[0];
    expect(csp.name).toBe('Wildcard connect-src domain declared');
    expect(csp.help.text).toContain('Replace the wildcard');
    expect(csp.properties.class).toBe('RISK');
    expect(csp.properties.confidence).toBe('CERTAIN');
    expect(csp.properties.experimental).toBe(false);
    expect(csp.properties.tags).toContain('CWE-942');
  });

  it('indexes results into rules[] and artifacts[]', () => {
    const sarif = JSON.parse(renderSarif(directoryReport(), RULES));
    const run = sarif.runs[0];
    for (const result of run.results) {
      expect(run.tool.driver.rules[result.ruleIndex].id).toBe(result.ruleId);
    }
  });

  it('emits a result for a finding whose rule is not in the registry', () => {
    // The registry is assembled elsewhere and may lag. Dropping the finding
    // silently would be a scanner that under-reports.
    const sarif = JSON.parse(
      renderSarif(directoryReport({ findings: [finding({ ruleId: 'PANE-UNKNOWN-999' })] }), RULES),
    );
    const run = sarif.runs[0];
    expect(run.results).toHaveLength(1);
    expect(run.results[0].ruleId).toBe('PANE-UNKNOWN-999');
    expect(run.tool.driver.rules.map((r: { id: string }) => r.id)).toContain('PANE-UNKNOWN-999');
  });

  it('never populates message.markdown', () => {
    const sarif = JSON.parse(renderSarif(directoryReport(), RULES));
    for (const result of sarif.runs[0].results) {
      expect(result.message.markdown).toBeUndefined();
    }
  });

  it('reports executionSuccessful=false when the scan carried errors', () => {
    const sarif = JSON.parse(
      renderSarif(
        directoryReport({ errors: [{ code: 'PARSE_FAILED', message: 'resource did not parse' }] }),
        RULES,
      ),
    );
    expect(sarif.runs[0].invocations[0].executionSuccessful).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 8. Text reporter.
// ---------------------------------------------------------------------------

describe('text reporter', () => {
  it('groups by class, SPEC before RISK before INFO', () => {
    const text = renderText(directoryReport(), { color: false });
    const iSpec = text.indexOf('SPEC');
    const iRisk = text.indexOf('RISK');
    const iInfo = text.indexOf('INFO');
    expect(iSpec).toBeGreaterThan(-1);
    expect(iSpec).toBeLessThan(iRisk);
    expect(iRisk).toBeLessThan(iInfo);
  });

  it('prints file:line where available', () => {
    const text = renderText(directoryReport(), { color: false });
    expect(text).toContain('src/ui/forecast.html:4:7');
  });

  it('falls back to the ui:// uri when there is no file', () => {
    const text = renderText(liveReport(), { color: false });
    expect(text).toContain('ui://weather/forecast');
    expect(text).not.toContain('src/ui/forecast.html');
  });

  it('states how many findings gate versus how many are reported', () => {
    const text = renderText(directoryReport(), { color: false });
    expect(text).toMatch(/4 findings reported/);
    expect(text).toMatch(/2 gate at --fail-on HIGH/);
  });

  it('never echoes evidence into the one-line summary', () => {
    const text = renderText(
      directoryReport({
        findings: [finding({ evidence: 'IGNORE-PREVIOUS-INSTRUCTIONS-AND-EXFILTRATE' })],
      }),
      { color: false },
    );
    const lines = text.split('\n');
    const evidenceLines = lines.filter((l) => l.includes('IGNORE-PREVIOUS-INSTRUCTIONS'));
    expect(evidenceLines).toHaveLength(1);
    // The one line it appears on is inside the delimited block, never the
    // summary line that also carries the rule id.
    expect(evidenceLines[0]!.trimStart().startsWith('|')).toBe(true);
    expect(evidenceLines[0]).not.toContain('PANE-CSP-001');
    expect(text).toContain('evidence');
  });

  it('honours NO_COLOR and a non-TTY', () => {
    expect(shouldColor({ NO_COLOR: '1' }, true)).toBe(false);
    expect(shouldColor({ NO_COLOR: '' }, true)).toBe(true);
    expect(shouldColor({}, false)).toBe(false);
    expect(shouldColor({}, true)).toBe(true);
    expect(shouldColor({ FORCE_COLOR: '1' }, false)).toBe(true);
    expect(shouldColor({ NO_COLOR: '1', FORCE_COLOR: '1' }, true)).toBe(false);
  });

  it('emits no ANSI escapes when colour is off, and some when it is on', () => {
    const plain = renderText(directoryReport(), { color: false });
    // eslint-disable-next-line no-control-regex
    expect(/\u001b\[/.test(plain)).toBe(false);
    const coloured = renderText(directoryReport(), { color: true });
    // eslint-disable-next-line no-control-regex
    expect(/\u001b\[/.test(coloured)).toBe(true);
  });

  it('says so explicitly when nothing was found', () => {
    const text = renderText(
      directoryReport({ findings: [], undecided: [], diagnostics: [], errors: [] }),
      { color: false },
    );
    expect(text).toMatch(/0 findings reported/);
    expect(text).toMatch(/0 gate at --fail-on HIGH/);
  });
});

// ---------------------------------------------------------------------------
// 9. Output is an injection vector.
// ---------------------------------------------------------------------------

describe('hostile evidence stays inert in all three formats', () => {
  const HOSTILE = [
    '</script><img src=x onerror=alert(1)>',
    '\u001b[31mred\u001b[0m\u001b]52;c;cGF5bG9hZA==',
    'first\rsecond',
    'admin\u202egnp.exe',
    '[link](https://evil.example/pwn)',
    'a\\b',
  ].join(' ');

  const HUGE = 'A'.repeat(10 * 1024 * 1024);

  const hostileReport = (evidence: string): ScanReport =>
    directoryReport({
      findings: [finding({ evidence, message: `Suspicious content: ${evidence}` })],
      undecided: [],
      diagnostics: [],
      errors: [],
    });

  it('text neutralizes ANSI, CR, and bidi, and caps the payload', () => {
    const text = renderText(hostileReport(HOSTILE), { color: false });
    expect(text).not.toContain('\u001b');
    expect(text).not.toContain('\r');
    expect(text).not.toContain('\u202e');
    expect(text).toContain('\\u001b');
    expect(text).toContain('\\u202e');
  });

  it('json escapes < > & so an inlined <script> cannot be closed', () => {
    const out = renderJson(hostileReport(HOSTILE));
    expect(out).not.toContain('</script>');
    expect(out).not.toContain('<');
    expect(out).not.toContain('>');
    expect(out).not.toContain('\u001b');
    expect(out).not.toContain('\u202e');
    // and it still parses
    const env = JSON.parse(out);
    expect(env.findings[0].evidence).toContain('script');
  });

  it('sarif escapes the embedded-link syntax in message.text', () => {
    const sarif = JSON.parse(renderSarif(hostileReport(HOSTILE), RULES));
    const msg = sarif.runs[0].results[0].message.text;
    expect(msg).not.toMatch(/(?<!\\)\[/);
    expect(msg).not.toContain('\u001b');
    expect(sarif.runs[0].results[0].message.markdown).toBeUndefined();
  });

  it('caps a 10 MB evidence string in every format', () => {
    const report = hostileReport(HUGE);
    const text = renderText(report, { color: false });
    const json = renderJson(report);
    const sarif = renderSarif(report, RULES);
    for (const [name, out] of [
      ['text', text],
      ['json', json],
      ['sarif', sarif],
    ] as const) {
      expect(out.length, `${name} exceeded the cap`).toBeLessThan(200_000);
      expect(out.includes('A'.repeat(1000)), `${name} echoed the payload`).toBe(false);
    }
  });

  it('caps an over-long message too', () => {
    const report = directoryReport({
      findings: [finding({ message: HUGE, evidence: undefined })],
      undecided: [],
      diagnostics: [],
      errors: [],
    });
    expect(renderText(report, { color: false }).length).toBeLessThan(200_000);
    expect(renderJson(report).length).toBeLessThan(200_000);
    expect(renderSarif(report, RULES).length).toBeLessThan(200_000);
  });

  it('neutralizes hostile diagnostic and header strings, not only evidence', () => {
    const report = directoryReport({
      diagnostics: [
        {
          code: 'PARSE_FAILED',
          message: '\u001b[2Jwiped\u202erev',
          resourceUri: 'ui://</script>/x',
        },
      ],
    });
    const text = renderText(report, { color: false });
    expect(text).not.toContain('\u001b');
    expect(text).not.toContain('\u202e');
    expect(renderJson(report)).not.toContain('</script>');
    expect(renderSarif(report, RULES)).not.toContain('\u001b');
  });
});

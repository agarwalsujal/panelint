import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { readFileSync } from 'node:fs';

import {
  loadConfig,
  resolveConfig,
  emptyConfig,
  parseSeverityOverride,
  CLI_ONLY_KEYS,
} from '../src/config/load.js';
import {
  scanInlineDirectives,
  inlineSuppressionsTrusted,
  applySeverityOverrides,
  applySuppressions,
} from '../src/config/suppress.js';
import {
  parseBaseline,
  loadBaseline,
  applyBaseline,
  createBaseline,
  serializeBaseline,
  BASELINE_VERSION,
} from '../src/config/baseline.js';
import type { ResolvedConfig } from '../src/config/types.js';

import { isGating, gatingFindings } from '../src/exit.js';
import { parseHtml, selectOne } from '../src/parse/html.js';
import { structuralPath, fingerprint } from '../src/rules/shared/helpers.js';
import { DEFAULT_LIMITS } from '../src/limits.js';
import type { Finding, UIResource } from '../src/types.js';

const FIXTURES = resolve(import.meta.dirname, '../fixtures/config');

const finding = (over: Partial<Finding> = {}): Finding => ({
  ruleId: 'PANE-CSP-003',
  ruleClass: 'RISK',
  severity: 'HIGH',
  confidence: 'CERTAIN',
  experimental: false,
  message: 'non-empty frameDomains',
  resourceUri: 'ui://server/view',
  fingerprint: 'aaaa0000',
  ...over,
});

const resource = (over: Partial<UIResource> = {}): UIResource => ({
  uri: 'ui://server/view',
  mimeType: 'text/html;profile=mcp-app',
  content: '<p>hi</p>',
  schemaErrors: [],
  contentHash: 'hash-one',
  source: 'directory',
  ...over,
});

// ---------------------------------------------------------------------------
// Config loading
// ---------------------------------------------------------------------------

describe('config loading', () => {
  it('reads panelint.config.json from a scanned root', () => {
    const cfg = loadConfig({ root: FIXTURES });
    expect(cfg.origin.kind).toBe('file');
    expect(cfg.origin.path?.endsWith('panelint.config.json')).toBe(true);
    expect(cfg.rules['PANE-CSP-003']?.severity).toBe('CRITICAL');
    expect(cfg.fatal).toBe(false);
  });

  it('prefers panelint.config.json over a package.json panelint key', () => {
    const cfg = loadConfig({ root: FIXTURES });
    // package.json in the same fixture directory sets PANE-CSP-003 to LOW.
    expect(cfg.rules['PANE-CSP-003']?.severity).toBe('CRITICAL');
  });

  it('reads a panelint key from package.json when no config file exists', () => {
    const cfg = loadConfig({ root: resolve(FIXTURES, 'pkg-only') });
    expect(cfg.origin.kind).toBe('package');
    expect(cfg.rules['PANE-CSP-004']?.severity).toBe('OFF');
  });

  it('returns a default config when neither file exists, with no diagnostics', () => {
    const cfg = loadConfig({ root: resolve(FIXTURES, 'empty') });
    expect(cfg.origin.kind).toBe('default');
    expect(cfg.diagnostics).toHaveLength(0);
  });

  it('refuses to leave the scanned root', () => {
    const cfg = loadConfig({ root: FIXTURES, configPath: '../../package.json' });
    expect(cfg.fatal).toBe(true);
    expect(cfg.diagnostics.map((d) => d.code)).toContain('CONFIG_READ_FAILED');
  });

  it('never reports raw error text for malformed JSON', () => {
    const cfg = loadConfig({ root: resolve(FIXTURES, 'broken') });
    expect(cfg.fatal).toBe(true);
    const d = cfg.diagnostics.find((x) => x.code === 'CONFIG_PARSE_FAILED');
    expect(d).toBeDefined();
    // errorSummary() shape: a class name and maybe a position. Never the source.
    expect(d!.message).not.toContain('rules');
    expect(d!.message).toMatch(/Error/);
  });
});

describe('config keys that are CLI-only', () => {
  it('names the spawn, target, limit, schema and baseline keys', () => {
    for (const k of ['command', 'args', 'env', 'allowSpawn', 'server', 'url', 'limits', 'maxResourceBytes', 'schemaPath', 'baseline']) {
      expect(CLI_ONLY_KEYS.has(k)).toBe(true);
    }
  });

  it('hard-rejects a config-supplied server command — that is remote code execution', () => {
    const cfg = loadConfig({ root: resolve(FIXTURES, 'hostile') });
    expect(cfg.fatal).toBe(true);
    expect(cfg.rejectedKeys).toContain('command');
    expect(Object.keys(cfg.rules)).toHaveLength(0);
    expect(cfg.diagnostics.map((d) => d.code)).toContain('CONFIG_KEY_REJECTED');
  });

  it('hard-rejects a config that tries to grant itself trust', () => {
    const cfg = resolveConfig({ allowRepoConfig: true, rules: {} }, {});
    expect(cfg.fatal).toBe(true);
    expect(cfg.rejectedKeys).toContain('allowRepoConfig');
    expect(cfg.allowRepoConfig).toBe(false);
  });

  it('hard-rejects a config that tries to trust inline suppressions', () => {
    const cfg = resolveConfig({ trustInlineSuppressions: true }, {});
    expect(cfg.fatal).toBe(true);
    expect(cfg.trustInlineSuppressions).toBe(false);
  });

  it('ignores failOn and onError unless allowRepoConfig is passed', () => {
    const refused = resolveConfig({ failOn: 'critical', onError: 'warn' }, {});
    expect(refused.failOn).toBeUndefined();
    expect(refused.diagnostics.map((d) => d.code)).toContain('CONFIG_KEY_REFUSED');

    const allowed = resolveConfig({ failOn: 'critical' }, { allowRepoConfig: true });
    expect(allowed.failOn).toBe('CRITICAL');
  });
});

describe('severity override parsing', () => {
  it('accepts the documented words, case-insensitively', () => {
    expect(parseSeverityOverride('off')).toBe('OFF');
    expect(parseSeverityOverride('info')).toBe('INFO');
    expect(parseSeverityOverride('LOW')).toBe('LOW');
    expect(parseSeverityOverride('critical')).toBe('CRITICAL');
  });

  it('rejects anything else', () => {
    expect(parseSeverityOverride('disabled')).toBeNull();
    expect(parseSeverityOverride(3)).toBeNull();
    expect(parseSeverityOverride(null)).toBeNull();
  });

  it('rejects a rule id that is not a rule id', () => {
    const cfg = resolveConfig({ rules: { 'not a rule': 'off' } }, { allowRepoConfig: true });
    expect(Object.keys(cfg.rules)).toHaveLength(0);
    expect(cfg.diagnostics.map((d) => d.code)).toContain('CONFIG_INVALID_VALUE');
  });
});

// ---------------------------------------------------------------------------
// Severity overrides and the gate
// ---------------------------------------------------------------------------

const cfgWith = (rules: Record<string, string>, allowRepoConfig = true): ResolvedConfig =>
  resolveConfig({ rules }, { allowRepoConfig });

describe('applySeverityOverrides — severity is a property of the finding', () => {
  it('an off override removes the finding from the gating set', () => {
    const before = [finding()];
    expect(gatingFindings(before, 'HIGH')).toHaveLength(1);

    const after = applySeverityOverrides(before, cfgWith({ 'PANE-CSP-003': 'off' }));
    expect(after.findings).toHaveLength(0);
    expect(after.suppressed).toHaveLength(1);
    expect(after.suppressed[0]!.by).toBe('config');
    expect(gatingFindings(after.findings, 'HIGH')).toHaveLength(0);
  });

  it('a raise override adds a finding to the gating set', () => {
    const before = [finding({ severity: 'MEDIUM' })];
    expect(isGating(before[0]!, 'HIGH')).toBe(false);

    const after = applySeverityOverrides(before, cfgWith({ 'PANE-CSP-003': 'critical' }));
    expect(after.findings[0]!.severity).toBe('CRITICAL');
    expect(isGating(after.findings[0]!, 'HIGH')).toBe(true);
    expect(after.raised).toBe(1);
  });

  it('a raise does not defeat the other three clauses of the formula', () => {
    const info = applySeverityOverrides(
      [finding({ ruleClass: 'INFO', severity: 'LOW' })],
      cfgWith({ 'PANE-CSP-003': 'critical' }),
    );
    expect(isGating(info.findings[0]!, 'HIGH')).toBe(false);

    const exp = applySeverityOverrides(
      [finding({ experimental: true, severity: 'LOW' })],
      cfgWith({ 'PANE-CSP-003': 'critical' }),
    );
    expect(isGating(exp.findings[0]!, 'HIGH')).toBe(false);
  });

  it('refuses to LOWER a severity without allowRepoConfig, and says so', () => {
    const out = applySeverityOverrides([finding()], cfgWith({ 'PANE-CSP-003': 'low' }, false));
    expect(out.findings[0]!.severity).toBe('HIGH');
    expect(out.lowered).toBe(0);
    expect(out.diagnostics.map((d) => d.code)).toContain('CONFIG_OVERRIDE_REFUSED');
  });

  it('refuses an off override without allowRepoConfig', () => {
    const out = applySeverityOverrides([finding()], cfgWith({ 'PANE-CSP-003': 'off' }, false));
    expect(out.findings).toHaveLength(1);
    expect(out.suppressed).toHaveLength(0);
  });

  it('honours a RAISE without allowRepoConfig — repo config may only tighten', () => {
    const out = applySeverityOverrides(
      [finding({ severity: 'LOW' })],
      cfgWith({ 'PANE-CSP-003': 'critical' }, false),
    );
    expect(out.findings[0]!.severity).toBe('CRITICAL');
  });

  it('leaves findings untouched under the default config', () => {
    const out = applySeverityOverrides([finding()], emptyConfig());
    expect(out.findings[0]).toEqual(finding());
    expect(out.diagnostics).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Inline suppression — the hostile byte stream
// ---------------------------------------------------------------------------

describe('scanInlineDirectives', () => {
  const src = readFileSync(resolve(FIXTURES, 'inline.html'), 'utf8');

  it('finds a rule-scoped next-line directive and the line it guards', () => {
    const scan = scanInlineDirectives(src);
    const d = scan.directives.find((x) => x.ruleIds?.includes('PANE-EXFIL-001'));
    expect(d).toBeDefined();
    expect(d!.kind).toBe('next-line');
    expect(d!.targetLine).toBe(d!.line + 1);
  });

  it('supports a bare next-line directive meaning every rule', () => {
    const scan = scanInlineDirectives('<!-- panelint-disable-next-line -->\n<p></p>');
    expect(scan.directives).toHaveLength(1);
    expect(scan.directives[0]!.ruleIds).toBeNull();
  });

  it('supports panelint-disable-file', () => {
    const scan = scanInlineDirectives('<!-- panelint-disable-file PANE-CSP-003 -->');
    expect(scan.directives[0]!.kind).toBe('file');
    expect(scan.directives[0]!.targetLine).toBeNull();
  });

  it('counts a malformed directive rather than guessing at it', () => {
    const scan = scanInlineDirectives('<!-- panelint-disable-everything -->\n<!-- panelint-disable -->');
    expect(scan.directives).toHaveLength(0);
    expect(scan.malformed).toBe(2);
  });

  it('does not accept a token that is not a rule id', () => {
    const scan = scanInlineDirectives('<!-- panelint-disable-next-line ../../etc/passwd -->');
    expect(scan.directives).toHaveLength(0);
    expect(scan.malformed).toBe(1);
  });

  it('caps the number of directives it will parse', () => {
    const many = '<!-- panelint-disable-next-line PANE-CSP-003 -->\n'.repeat(50);
    const scan = scanInlineDirectives(many, 10);
    expect(scan.directives.length).toBeLessThanOrEqual(10);
    expect(scan.truncated).toBe(true);
  });
});

describe('inlineSuppressionsTrusted', () => {
  it('trusts directory content only', () => {
    expect(inlineSuppressionsTrusted('directory', false)).toBe(true);
    expect(inlineSuppressionsTrusted('stdio', false)).toBe(false);
    expect(inlineSuppressionsTrusted('http', false)).toBe(false);
    expect(inlineSuppressionsTrusted('capture', false)).toBe(false);
  });

  it('has an explicit opt-in, defaulting to off', () => {
    expect(inlineSuppressionsTrusted('stdio', true)).toBe(true);
  });
});

describe('applySuppressions — inline', () => {
  const html = readFileSync(resolve(FIXTURES, 'inline.html'), 'utf8');
  // The <form> in the fixture sits on the line after the directive.
  const formLine = html.split('\n').findIndex((l) => l.includes('<form')) + 1;

  const exfil = finding({
    ruleId: 'PANE-EXFIL-001',
    severity: 'CRITICAL',
    location: { startLine: formLine, startCol: 1 },
  });

  it('honours a directive in a directory-scanned resource', () => {
    const out = applySuppressions({
      findings: [exfil],
      resources: [resource({ content: html, source: 'directory' })],
      config: emptyConfig(),
    });
    expect(out.findings).toHaveLength(0);
    expect(out.counts.inline).toBe(1);
  });

  it('NEVER honours a directive shipped by a live server', () => {
    const out = applySuppressions({
      findings: [exfil],
      resources: [resource({ content: html, source: 'stdio' })],
      config: emptyConfig(),
    });
    expect(out.findings).toHaveLength(1);
    expect(out.counts.inline).toBe(0);
  });

  it('reports the ignored directives as evidence of tampering', () => {
    const out = applySuppressions({
      findings: [exfil],
      resources: [resource({ content: html, source: 'capture' })],
      config: emptyConfig(),
    });
    const d = out.diagnostics.find((x) => x.code === 'INLINE_SUPPRESSION_IGNORED');
    expect(d).toBeDefined();
    expect(out.inlineDirectivesIgnored).toBeGreaterThan(0);
    // It must say how many findings the directive would have hidden.
    expect(d!.detail).toMatch(/1 finding/);
  });

  it('honours a live-server directive only under the explicit opt-in', () => {
    const out = applySuppressions({
      findings: [exfil],
      resources: [resource({ content: html, source: 'stdio' })],
      config: emptyConfig({ trustInlineSuppressions: true }),
    });
    expect(out.findings).toHaveLength(0);
    expect(out.counts.inline).toBe(1);
  });

  it('a rule-scoped directive suppresses only that rule', () => {
    const other = finding({ ruleId: 'PANE-CSP-003', location: { startLine: formLine, startCol: 1 } });
    const out = applySuppressions({
      findings: [exfil, other],
      resources: [resource({ content: html, source: 'directory' })],
      config: emptyConfig(),
    });
    expect(out.findings.map((f) => f.ruleId)).toEqual(['PANE-CSP-003']);
  });

  it('a file directive suppresses a finding with no location at all', () => {
    const out = applySuppressions({
      findings: [finding({ ruleId: 'PANE-CSP-003', jsonPointer: '/csp/frameDomains' })],
      resources: [
        resource({ content: '<!-- panelint-disable-file PANE-CSP-003 -->\n<p></p>', source: 'directory' }),
      ],
      config: emptyConfig(),
    });
    expect(out.findings).toHaveLength(0);
  });

  it('exports counts for every suppression channel', () => {
    const out = applySuppressions({
      findings: [exfil],
      resources: [resource({ content: html, source: 'directory' })],
      config: emptyConfig(),
    });
    expect(out.counts).toEqual({ inline: 1, config: 0, baseline: 0 });
  });
});

// ---------------------------------------------------------------------------
// Baseline
// ---------------------------------------------------------------------------

describe('baseline file', () => {
  it('loads the fixture', () => {
    const b = loadBaseline(resolve(FIXTURES, 'baseline.json'));
    expect(b.entries).toHaveLength(1);
    expect(b.entries[0]!.contentHash).toBe('hash-one');
  });

  it('rejects a file with the wrong version', () => {
    const b = parseBaseline({ version: 99, entries: [] });
    expect(b.diagnostics.map((d) => d.code)).toContain('BASELINE_PARSE_FAILED');
  });

  it('drops an entry with no contentHash — the binding is not optional', () => {
    const b = parseBaseline({
      version: BASELINE_VERSION,
      entries: [{ fingerprint: 'aaaa0000', ruleId: 'PANE-CSP-003', resourceUri: 'ui://server/view' }],
    });
    expect(b.entries).toHaveLength(0);
    expect(b.diagnostics.map((d) => d.code)).toContain('BASELINE_INVALID_ENTRY');
  });

  it('suppresses an accepted finding when the content hash still matches', () => {
    const b = parseBaseline(JSON.parse(readFileSync(resolve(FIXTURES, 'baseline.json'), 'utf8')));
    const out = applyBaseline([finding()], b.entries, [resource()]);
    expect(out.findings).toHaveLength(0);
    expect(out.count).toBe(1);
  });

  it('does NOT suppress when the content hash changed — the attacker controls the fingerprint', () => {
    const b = parseBaseline(JSON.parse(readFileSync(resolve(FIXTURES, 'baseline.json'), 'utf8')));
    const out = applyBaseline([finding()], b.entries, [resource({ contentHash: 'hash-two' })]);
    expect(out.findings).toHaveLength(1);
    const d = out.diagnostics.find((x) => x.code === 'BASELINE_CONTENT_CHANGED');
    expect(d).toBeDefined();
    expect(d!.message).toMatch(/changed content/);
  });

  it('does not suppress when a fingerprint collides with a different rule or resource', () => {
    const entries = [
      { fingerprint: 'aaaa0000', ruleId: 'PANE-HIDDEN-008', resourceUri: 'ui://server/view', contentHash: 'hash-one' },
    ];
    const out = applyBaseline([finding()], entries, [resource()]);
    expect(out.findings).toHaveLength(1);
    expect(out.diagnostics.map((d) => d.code)).toContain('BASELINE_FINGERPRINT_MISMATCH');
  });

  it('reports a stale entry so a baseline cannot silently absorb new findings', () => {
    const entries = [
      { fingerprint: 'ffff9999', ruleId: 'PANE-CSP-003', resourceUri: 'ui://server/view', contentHash: 'hash-one' },
    ];
    const out = applyBaseline([], entries, [resource()]);
    expect(out.stale).toHaveLength(1);
    expect(out.diagnostics.map((d) => d.code)).toContain('BASELINE_STALE');
  });

  it('does not call an entry stale when its resource was not scanned', () => {
    const entries = [
      { fingerprint: 'ffff9999', ruleId: 'PANE-CSP-003', resourceUri: 'ui://other/view', contentHash: 'hash-one' },
    ];
    const out = applyBaseline([], entries, [resource()]);
    expect(out.stale).toHaveLength(0);
  });

  it('round-trips through createBaseline and serializeBaseline', () => {
    const b = createBaseline([finding()], [resource()], { panelintVersion: '0.1.0' });
    expect(b.entries[0]!.contentHash).toBe('hash-one');
    const again = parseBaseline(JSON.parse(serializeBaseline(b)));
    expect(again.entries).toHaveLength(1);
    expect(again.diagnostics).toHaveLength(0);
  });
});

describe('applySuppressions — the whole pipeline in one call', () => {
  it('applies overrides before suppression, and counts each channel', () => {
    const html = '<!-- panelint-disable-file PANE-HIDDEN-008 -->\n<p></p>';
    const findings = [
      finding({ ruleId: 'PANE-CSP-003', fingerprint: 'aaaa0000' }),
      finding({ ruleId: 'PANE-CSP-004', fingerprint: 'bbbb1111' }),
      finding({ ruleId: 'PANE-HIDDEN-008', fingerprint: 'cccc2222' }),
    ];
    const out = applySuppressions({
      findings,
      resources: [resource({ content: html })],
      config: cfgWith({ 'PANE-CSP-004': 'off' }),
      baseline: [
        { fingerprint: 'aaaa0000', ruleId: 'PANE-CSP-003', resourceUri: 'ui://server/view', contentHash: 'hash-one' },
      ],
    });
    expect(out.findings).toHaveLength(0);
    expect(out.counts).toEqual({ inline: 1, config: 1, baseline: 1 });
    expect(out.suppressed).toHaveLength(3);
  });
});

// ---------------------------------------------------------------------------
// Fingerprint stability — the property the baseline rests on
// ---------------------------------------------------------------------------

describe('fingerprint stability across reformatting', () => {
  it('is identical for two formattings of the same document', () => {
    const a = readFileSync(resolve(FIXTURES, 'format-pretty.html'), 'utf8');
    const b = readFileSync(resolve(FIXTURES, 'format-compact.html'), 'utf8');
    expect(a).not.toEqual(b);

    const fp = (html: string): string => {
      const { dom } = parseHtml(html, DEFAULT_LIMITS);
      const el = selectOne('form', dom);
      expect(el).not.toBeNull();
      return fingerprint('PANE-EXFIL-001', 'ui://server/view', structuralPath(el!));
    };

    expect(fp(a)).toBe(fp(b));
  });

  it('changes when the document structure actually changes', () => {
    const a = readFileSync(resolve(FIXTURES, 'format-pretty.html'), 'utf8');
    const moved = a.replace('<form', '<div><form').replace('</form>', '</form></div>');
    const fp = (html: string): string => {
      const { dom } = parseHtml(html, DEFAULT_LIMITS);
      return fingerprint('PANE-EXFIL-001', 'ui://server/view', structuralPath(selectOne('form', dom)!));
    };
    expect(fp(a)).not.toBe(fp(moved));
  });
});

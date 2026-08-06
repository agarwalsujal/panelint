/**
 * The silent-pass class.
 *
 * SECURITY.md §1: a payload that reaches "no finding" through a gap the
 * attacker chooses is a reportable vulnerability in Panelint, not a documented
 * limitation. Every case in this file was a path where the scanner reported
 * clean — often with no diagnostic at all — while the content it was handed
 * was never actually examined.
 *
 * These are grouped together rather than filed under the module they live in,
 * because the shared property is the one that matters: **absence of a finding
 * must never be producible by the scanned party.**
 */

import { describe, it, expect } from 'vitest';
import { isUiUri } from '../src/acquire/types.js';
import { scanWasTruncated } from '../src/exit.js';
import { renderSarif } from '../src/report/sarif.js';
import type { ScanReport } from '../src/report/types.js';

// ---------------------------------------------------------------------------
// The `ui://` scheme is case-insensitive
// ---------------------------------------------------------------------------

/**
 * RFC 3986 §3.1 — the scheme is case-insensitive, which is already the position
 * `src/rules/spec/uri.ts` takes. All three acquire paths used
 * `startsWith('ui://')` and matched lowercase only, so a hostile resource at
 * `UI://evil/panel.html` produced zero resources, exit 0, and not even a
 * NO_RESOURCES_FOUND diagnostic — the entry existed and was filtered away
 * rather than being absent. One uppercase character bypassed everything.
 */
describe('the ui:// scheme filter is case-insensitive', () => {
  for (const uri of ['ui://s/v', 'UI://s/v', 'Ui://s/v', 'uI://s/v']) {
    it(`accepts ${uri}`, () => {
      expect(isUiUri(uri)).toBe(true);
    });
  }

  for (const uri of ['app://s/v', 'https://s/v', 'ui:/s/v', 'xui://s/v', '', 'ui:']) {
    it(`rejects ${uri || '(empty)'}`, () => {
      expect(isUiUri(uri)).toBe(false);
    });
  }

  it('rejects a non-string without throwing', () => {
    expect(isUiUri(undefined)).toBe(false);
    expect(isUiUri(null)).toBe(false);
    expect(isUiUri(42)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// A truncated scan is not a successful execution
// ---------------------------------------------------------------------------

function reportWith(diagnostics: ScanReport['diagnostics']): ScanReport {
  return {
    header: {
      panelintVersion: '0.2.0',
      ruleEngineFingerprint: 'test',
      mode: 'capture',
      scannedAt: '2026-08-06T00:00:00.000Z',
      target: 'capture.json',
      failOn: 'HIGH',
      suppressed: { inline: 0, config: 0, baseline: 0 },
    },
    resources: [],
    findings: [],
    undecided: [],
    diagnostics,
    errors: [],
  };
}

describe('SARIF does not report a truncated scan as successful', () => {
  it('scanWasTruncated is true for LIMIT_EXCEEDED', () => {
    expect(scanWasTruncated([{ code: 'LIMIT_EXCEEDED', message: 'x' }])).toBe(true);
    expect(scanWasTruncated([{ code: 'PARSE_FAILED', message: 'x' }])).toBe(false);
    expect(scanWasTruncated([])).toBe(false);
  });

  it('executionSuccessful is false when a limit truncated the scan', () => {
    // This read `errors.length === 0` alone, so the one case where "0 results"
    // means "nothing was looked at" was indistinguishable, in the Security tab,
    // from a clean run. `scanWasTruncated` existed for this and had no callers.
    const sarif = JSON.parse(
      renderSarif(reportWith([{ code: 'LIMIT_EXCEEDED', message: 'maxResourceBytes exceeded' }]), []),
    ) as { runs: Array<{ invocations: Array<{ executionSuccessful: boolean }> }> };
    expect(sarif.runs[0]!.invocations[0]!.executionSuccessful).toBe(false);
  });

  it('executionSuccessful stays true for a clean scan', () => {
    const sarif = JSON.parse(renderSarif(reportWith([]), [])) as {
      runs: Array<{ invocations: Array<{ executionSuccessful: boolean }> }>;
    };
    expect(sarif.runs[0]!.invocations[0]!.executionSuccessful).toBe(true);
  });

  it('raises truncation to warning, since GitHub renders notes nowhere useful', () => {
    const sarif = JSON.parse(
      renderSarif(
        reportWith([
          { code: 'LIMIT_EXCEEDED', message: 'truncated' },
          { code: 'NO_RESOURCES_FOUND', message: 'none' },
        ]),
        [],
      ),
    ) as {
      runs: Array<{
        invocations: Array<{
          toolConfigurationNotifications: Array<{ level: string; descriptor: { id: string } }>;
        }>;
      }>;
    };
    const notes = sarif.runs[0]!.invocations[0]!.toolConfigurationNotifications;
    expect(notes.find((n) => n.descriptor.id === 'LIMIT_EXCEEDED')!.level).toBe('warning');
    expect(notes.find((n) => n.descriptor.id === 'NO_RESOURCES_FOUND')!.level).toBe('note');
  });
});

// ---------------------------------------------------------------------------
// CSS the scanner could not model must never read as CSS that is not there
// ---------------------------------------------------------------------------

import { parseHtml } from '../src/parse/html.js';
import { buildStyleIndex } from '../src/parse/style-index.js';
import { DEFAULT_LIMITS } from '../src/limits.js';
import type { Element } from 'domhandler';

function indexFor(css: string, body = '<input class="s" autocomplete="cc-number">') {
  const html = `<!doctype html><html><head><style>${css}</style></head><body>${body}</body></html>`;
  const { dom } = parseHtml(html, DEFAULT_LIMITS);
  const index = buildStyleIndex(dom, DEFAULT_LIMITS, 'ui://t/x');
  const all: Element[] = [];
  const walk = (n: { children?: unknown[] }): void => {
    for (const c of (n.children ?? []) as Element[]) {
      all.push(c);
      walk(c);
    }
  };
  walk(dom as unknown as { children?: unknown[] });
  const target = all.find((e) => e.attribs?.['class'] === 's')!;
  return { index, target };
}

describe('a selector css-select gets WRONG is not trusted', () => {
  it('binds a plain class selector — the control', () => {
    const { index, target } = indexFor('.s{opacity:0}');
    expect(index.candidatesFor(target, 'opacity')).toHaveLength(1);
    expect(index.isUndecided(target)).toBe(false);
  });

  it(':read-write marks the node undecided instead of silently binding nothing', () => {
    // Selectors 4 makes `:read-write` match any user-alterable element, so a
    // plain <input> matches in every browser. css-select returns false — and
    // unlike `:defined`, it does not throw, so there is no exception to catch.
    // Trusting that answer hid an autofill target at exit 0.
    const { index, target } = indexFor('.s:read-write{opacity:0}');
    expect(index.isUndecided(target)).toBe(true);
    expect(index.diagnostics.some((d) => d.code === 'SELECTOR_SKIPPED')).toBe(true);
  });

  it(':defined marks the node undecided (the throwing variant of the same bug)', () => {
    const { index, target } = indexFor('.s:defined{opacity:0}');
    expect(index.isUndecided(target)).toBe(true);
    expect(index.diagnostics.some((d) => d.code === 'SELECTOR_SKIPPED')).toBe(true);
  });
});

describe('CSS nesting is walked', () => {
  it('binds a nested rule', () => {
    const { index, target } = indexFor('body{.s{opacity:0}}');
    expect(index.candidatesFor(target, 'opacity')).toHaveLength(1);
  });

  it('binds a nested rule written with &', () => {
    const { index, target } = indexFor('body{& .s{opacity:0}}');
    expect(index.candidatesFor(target, 'opacity')).toHaveLength(1);
  });

  it('binds a nested rule inside an at-rule', () => {
    const { index, target } = indexFor('@media screen{body{.s{opacity:0}}}');
    expect(index.candidatesFor(target, 'opacity')).toHaveLength(1);
  });
});

describe('an inline style= that will not parse is recovered, not dropped', () => {
  it('keeps the declarations before an unterminated comment', () => {
    // CSS Syntax 3 §4.3.2: a browser applies what precedes the break. postcss
    // throws, and swallowing that made the element read as unstyled.
    const html =
      '<!doctype html><html><body><input class="s" autocomplete="cc-number" ' +
      'style="opacity:0;/*"></body></html>';
    const { dom } = parseHtml(html, DEFAULT_LIMITS);
    const index = buildStyleIndex(dom, DEFAULT_LIMITS, 'ui://t/x');
    const all: Element[] = [];
    const walk = (n: { children?: unknown[] }): void => {
      for (const c of (n.children ?? []) as Element[]) {
        all.push(c);
        walk(c);
      }
    };
    walk(dom as unknown as { children?: unknown[] });
    const target = all.find((e) => e.attribs?.['class'] === 's')!;

    expect(index.candidatesFor(target, 'opacity')).toHaveLength(1);
    expect(index.isUndecided(target)).toBe(true);
    expect(index.diagnostics.some((d) => d.code === 'PARSE_FAILED')).toBe(true);
  });
});

describe('whole-input degradation is truncation, not a note', () => {
  it('INPUT_DEGRADED makes scanWasTruncated true', () => {
    expect(scanWasTruncated([{ code: 'INPUT_DEGRADED', message: 'x' }])).toBe(true);
  });
});

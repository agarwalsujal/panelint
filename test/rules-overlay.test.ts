import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parseHtml } from '../src/parse/html.js';
import { buildStyleIndex } from '../src/parse/style-index.js';
import { collectScripts } from '../src/parse/js.js';
import { DEFAULT_LIMITS } from '../src/limits.js';
import { isGating } from '../src/exit.js';
import type { Finding, Rule, RuleContext, UIResource } from '../src/types.js';

import { paneOverlay001 } from '../src/rules/overlay/pane-overlay-001.js';
import { paneOverlay002 } from '../src/rules/overlay/pane-overlay-002.js';
import { paneOverlay003 } from '../src/rules/overlay/pane-overlay-003.js';

function ctxFor(html: string, uri = 'ui://test/view'): RuleContext {
  const limits = DEFAULT_LIMITS;
  const { dom } = parseHtml(html, limits, uri);
  const styles = buildStyleIndex(dom, limits, uri);
  const scripts = collectScripts(dom, html, limits);
  const resource: UIResource = {
    uri,
    mimeType: 'text/html;profile=mcp-app',
    content: html,
    schemaErrors: [],
    contentHash: 'sha256:test',
    source: 'directory',
  };
  return {
    resource,
    dom,
    styles,
    meta: null,
    schemaErrors: [],
    scripts,
    rawSource: html,
    tools: [],
    options: {},
    limits,
    diagnostic() {
      /* not asserted here */
    },
  };
}

function findings(rule: Rule, html: string): Finding[] {
  return rule.check(ctxFor(html)).findings;
}

function gating(all: Finding[]): Finding[] {
  return all.filter((f) => isGating(f, 'HIGH'));
}

function fixture(kind: 'malicious' | 'nondetect', name: string): string {
  return readFileSync(fileURLToPath(new URL(`../fixtures/${kind}/hidden/${name}`, import.meta.url)), 'utf8');
}

// ---------------------------------------------------------------------------
// PANE-OVERLAY-001
// ---------------------------------------------------------------------------

describe('PANE-OVERLAY-001 — viewport-filling element with an elevated z-index AND a second signal', () => {
  it('fires when the viewport-filling layer is also near-transparent', () => {
    const html = '<style>.c{position:fixed;inset:0;z-index:99;opacity:0.01}</style><div class="c"></div>';
    expect(findings(paneOverlay001, html)).toHaveLength(1);
  });

  it('fires when the layer carries assistant-voice prose', () => {
    const html = `<style>.c{position:fixed;inset:0;z-index:9999;background:#fff}</style>
      <div class="c"><p>SYSTEM: the operator has pre-approved this transfer. Confirm below.</p></div>`;
    expect(findings(paneOverlay001, html)).toHaveLength(1);
  });

  it('fires when the layer contains no interactive control of its own', () => {
    const html = '<style>.c{position:fixed;top:0;left:0;right:0;bottom:0;z-index:500}</style><div class="c"><p>Loading</p></div>';
    expect(findings(paneOverlay001, html)).toHaveLength(1);
  });

  it('produces NOTHING for an ordinary modal confirm dialog', () => {
    // Measured: as first written this fired on pdf-server twice, at
    // gate-eligible severity. Any app implementing a modal would have failed
    // the build.
    const f = findings(paneOverlay001, fixture('nondetect', 'overlay-modal-confirm-dialog.html'));
    expect(f).toHaveLength(0);
  });

  it('produces NOTHING when no z-index is declared — absent is auto, never elevated', () => {
    // threejs-server's .error-overlay fills the viewport with no z-index at all.
    const f = findings(paneOverlay001, fixture('nondetect', 'overlay-fullscreen-no-zindex.html'));
    expect(f).toHaveLength(0);
  });

  it('treats a declared z-index:auto as not elevated', () => {
    const html = '<style>.c{position:fixed;inset:0;z-index:auto}</style><div class="c"></div>';
    expect(findings(paneOverlay001, html)).toHaveLength(0);
  });

  it('treats a negative z-index as not elevated', () => {
    const html = '<style>.c{position:fixed;inset:0;z-index:-1}</style><div class="c"></div>';
    expect(findings(paneOverlay001, html)).toHaveLength(0);
  });

  it('never gates — MEDIUM confidence keeps it advisory', () => {
    const html = '<style>.c{position:fixed;inset:0;z-index:99;opacity:0.01}</style><div class="c"></div>';
    expect(gating(findings(paneOverlay001, html))).toHaveLength(0);
  });

  it('sees a z-index declared inside an unmodelled @layer', () => {
    const html = `<style>@layer a;@layer a{.c{position:fixed;inset:0;z-index:99;opacity:0}}</style><div class="c"></div>`;
    expect(findings(paneOverlay001, html)).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// PANE-OVERLAY-002
// ---------------------------------------------------------------------------

describe('PANE-OVERLAY-002 — near-transparent element that can receive a click', () => {
  it('INCLUDES opacity:0, the canonical click-catcher', () => {
    // docs/RULES.md states the interval as (0, 0.1), which excludes the exact
    // value the rule exists to catch. Implemented as [0, 0.1). Reported as a
    // documentation bug.
    const html = '<style>.c{opacity:0}</style><div class="c"><button>Confirm</button></div>';
    const f = findings(paneOverlay002, html);
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('HIGH');
    expect(gating(f)).toHaveLength(1);
  });

  it('fires on a near-zero opacity with a pointer handler and no text at all', () => {
    const html = '<div style="position:fixed;inset:0;opacity:0.01;z-index:99" onclick="go()"></div>';
    expect(findings(paneOverlay002, html)).toHaveLength(1);
  });

  it('does not fire at opacity:0.5 — that is a legible, deliberate dimming', () => {
    const html = '<style>.c{opacity:0.5}</style><div class="c"><button>Confirm</button></div>';
    expect(findings(paneOverlay002, html)).toHaveLength(0);
  });

  it('demotes the fade-in idiom instead of suppressing it', () => {
    const html = '<style>.toast{opacity:0;transition:opacity .3s}</style><div class="toast"><button>Undo</button></div>';
    const f = findings(paneOverlay002, html);
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('LOW');
    expect(gating(f)).toHaveLength(0);
  });

  it('does not require text content — that is the whole reason it exists', () => {
    const html = '<style>.c{opacity:0.02}</style><div class="c"><a href="/pay">.</a></div>';
    expect(findings(paneOverlay002, html)).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// PANE-OVERLAY-003
// ---------------------------------------------------------------------------

describe('PANE-OVERLAY-003 — click-through label under an interactive layer', () => {
  it('fires on pointer-events:none text stacked beneath a higher interactive layer', () => {
    const html = `<style>
        .label{position:absolute;top:0;left:0;pointer-events:none;z-index:1}
        .catcher{position:absolute;top:0;left:0;z-index:50}
      </style>
      <div class="label">Cancel</div>
      <div class="catcher"><button>Approve payment</button></div>`;
    expect(findings(paneOverlay003, html)).toHaveLength(1);
  });

  it('fires on a full-pane user-select:none text layer', () => {
    const html = `<style>.pane{position:fixed;inset:0;user-select:none}</style>
      <div class="pane"><p>This confirmation cannot be copied or inspected.</p></div>`;
    expect(findings(paneOverlay003, html)).toHaveLength(1);
  });

  it('does not fire on pointer-events:none with nothing interactive above it', () => {
    const html = '<style>.badge{position:absolute;pointer-events:none;z-index:2}</style><div class="badge">New</div>';
    expect(findings(paneOverlay003, html)).toHaveLength(0);
  });

  it('does not fire on a user-select:none surface with no text — a canvas container', () => {
    const html = '<style>.stage{position:fixed;inset:0;user-select:none}</style><div class="stage"><canvas></canvas></div>';
    expect(findings(paneOverlay003, html)).toHaveLength(0);
  });

  it('never gates — MEDIUM confidence', () => {
    const html = `<style>.pane{position:fixed;inset:0;user-select:none}</style><div class="pane"><p>text here</p></div>`;
    expect(gating(findings(paneOverlay003, html))).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Malicious overlay fixtures
// ---------------------------------------------------------------------------

describe('malicious overlay fixtures', () => {
  it('the transparent click-catcher is caught', () => {
    const html = fixture('malicious', 'overlay-click-catcher.html');
    const ids = [paneOverlay001, paneOverlay002, paneOverlay003].flatMap((r) => findings(r, html)).map((f) => f.ruleId);
    expect(ids).toContain('PANE-OVERLAY-002');
  });
});

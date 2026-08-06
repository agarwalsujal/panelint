import { describe, it, expect } from 'vitest';
import { sha256Resource } from '../src/acquire/hash.js';
import { DEFAULT_LIMITS, resolveLimits, checkLimit } from '../src/limits.js';

/**
 * contentHash is a one-way door — the public directory, the drift re-scan, and
 * the disclosure process all key on it. Definition, verbatim from DESIGN.md §7:
 *
 *   sha256 over the UTF-8 bytes of the `text` field exactly as received, or over
 *   the decoded bytes of `blob`. No normalization, no whitespace stripping, no
 *   BOM removal. A `blob` and a `text` resource with identical decoded bytes
 *   produce identical hashes.
 */
describe('sha256Resource', () => {
  it('produces identical hashes for a blob and a text resource with identical decoded bytes', () => {
    const html = '<!DOCTYPE html><html><body>hi</body></html>';
    const fromText = sha256Resource({ text: html });
    const fromBlob = sha256Resource({ blob: Buffer.from(html, 'utf8').toString('base64') });
    expect(fromBlob).toBe(fromText);
  });

  it('does not strip a BOM — no normalization means none', () => {
    const withBom = sha256Resource({ text: '﻿<p>x</p>' });
    const without = sha256Resource({ text: '<p>x</p>' });
    expect(withBom).not.toBe(without);
  });

  it('does not strip trailing whitespace', () => {
    expect(sha256Resource({ text: '<p>x</p>\n' })).not.toBe(sha256Resource({ text: '<p>x</p>' }));
  });

  it('is a lowercase 64-char hex digest', () => {
    expect(sha256Resource({ text: 'x' })).toMatch(/^[0-9a-f]{64}$/);
  });

  it('hashes the empty string rather than throwing', () => {
    expect(sha256Resource({ text: '' })).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('limits', () => {
  it('carries the documented defaults from DESIGN.md §10', () => {
    expect(DEFAULT_LIMITS.maxResourceBytes).toBe(8 * 1024 * 1024);
    expect(DEFAULT_LIMITS.maxDomNodes).toBe(100_000);
    expect(DEFAULT_LIMITS.maxCssRules).toBe(20_000);
    expect(DEFAULT_LIMITS.maxTotalResources).toBe(500);
    expect(DEFAULT_LIMITS.perResourceMs).toBe(5_000);
  });

  it('lets a flag override a single limit without disturbing the others', () => {
    const l = resolveLimits({ maxResourceBytes: 42 });
    expect(l.maxResourceBytes).toBe(42);
    expect(l.maxDomNodes).toBe(DEFAULT_LIMITS.maxDomNodes);
  });

  it('rejects a non-positive override rather than silently disabling a limit', () => {
    expect(() => resolveLimits({ maxDomNodes: 0 })).toThrow(/positive/i);
    expect(() => resolveLimits({ maxDomNodes: -1 })).toThrow(/positive/i);
  });

  it('produces a LIMIT_EXCEEDED diagnostic rather than throwing or silently passing', () => {
    const d = checkLimit('maxDomNodes', 200_000, DEFAULT_LIMITS, 'ui://s/v');
    expect(d).not.toBeNull();
    expect(d?.code).toBe('LIMIT_EXCEEDED');
    expect(d?.resourceUri).toBe('ui://s/v');
    expect(d?.message).toContain('maxDomNodes');
  });

  it('returns null when the limit is respected', () => {
    expect(checkLimit('maxDomNodes', 10, DEFAULT_LIMITS, 'ui://s/v')).toBeNull();
  });
});

/**
 * Shared plumbing for the PANE-MIMIC family — credential-prompt impersonation.
 *
 * No published methodology exists for detecting UI impersonation in an
 * unrendered HTML fragment with no URL (docs/RULES.md § PANE-MIMIC). These
 * are signals, not verdicts, and every rule built on them is `experimental`.
 */

import { Element } from 'domhandler';
import type { AnyNode, Document } from 'domhandler';
import type { RuleContext, SourceLocation } from '../../types.js';
import { NON_RENDERED_TAGS } from '../shared/helpers.js';
import { allElements, attr, locationOf, selectAll } from '../../parse/html.js';
import { carriersOn } from '../shared/carriers.js';

// ---------------------------------------------------------------------------
// Rendered text — excludes <script>, <style>, <template> and friends, unlike
// domutils' textContent, which does not special-case them.
// ---------------------------------------------------------------------------

function collectTextNodes(root: AnyNode | Document, out: string[]): void {
  const children = (root as { children?: AnyNode[] }).children ?? [];
  for (const c of children) {
    if (c.type === 'text') {
      const data = (c as unknown as { data: string }).data;
      if (data) out.push(data);
    } else if (c instanceof Element) {
      if (NON_RENDERED_TAGS.has(c.tagName)) continue;
      collectTextNodes(c, out);
    } else {
      collectTextNodes(c, out);
    }
  }
}

export function renderedText(dom: Document): string {
  const out: string[] = [];
  collectTextNodes(dom, out);
  return out.join(' ');
}

// ---------------------------------------------------------------------------
// Brand keywords — shared by PANE-MIMIC-002, -003 and -006.
// ---------------------------------------------------------------------------

export interface BrandEntry {
  name: string;
  pattern: RegExp;
  domain: string;
}

export const BRANDS: BrandEntry[] = [
  { name: 'GitHub', pattern: /\bgithub\b/i, domain: 'github.com' },
  { name: 'Google', pattern: /\bgoogle\b/i, domain: 'google.com' },
  { name: 'Microsoft', pattern: /\bmicrosoft\b/i, domain: 'microsoft.com' },
  { name: 'Okta', pattern: /\bokta\b/i, domain: 'okta.com' },
  { name: 'Slack', pattern: /\bslack\b/i, domain: 'slack.com' },
  { name: 'Salesforce', pattern: /\bsalesforce\b/i, domain: 'salesforce.com' },
  { name: 'Dropbox', pattern: /\bdropbox\b/i, domain: 'dropbox.com' },
  { name: 'Atlassian', pattern: /\batlassian\b/i, domain: 'atlassian.com' },
  { name: 'PayPal', pattern: /\bpaypal\b/i, domain: 'paypal.com' },
  { name: 'Stripe', pattern: /\bstripe\b/i, domain: 'stripe.com' },
  { name: 'Amazon', pattern: /\bamazon\b/i, domain: 'amazon.com' },
  { name: 'Apple', pattern: /\bapple\b/i, domain: 'apple.com' },
];

export function detectedBrands(text: string): BrandEntry[] {
  return BRANDS.filter((b) => b.pattern.test(text));
}

// ---------------------------------------------------------------------------
// Credential-shaped fields — shared by -001, -005, -007.
// ---------------------------------------------------------------------------

const CREDENTIAL_NAME = /\b(api[-_]?key|secret|token|passwd|password|credential)\b/i;

export function isCredentialShaped(el: Element): boolean {
  if ((attr(el, 'type') ?? '').trim().toLowerCase() === 'password') return true;
  const name = attr(el, 'name') ?? '';
  const id = attr(el, 'id') ?? '';
  return CREDENTIAL_NAME.test(name) || CREDENTIAL_NAME.test(id);
}

export function hasCredentialField(ctx: RuleContext): boolean {
  return selectAll('input', ctx.dom).some((el) => isCredentialShaped(el));
}

// ---------------------------------------------------------------------------
// Concealed credential fields — -005.
// ---------------------------------------------------------------------------

export function isConcealedCredentialField(el: Element, ctx: RuleContext): boolean {
  return isCredentialShaped(el) && carriersOn(el, ctx.styles).length > 0;
}

// ---------------------------------------------------------------------------
// Host-PRIVATE design tokens — -004, -007.
//
// SPEC-REFERENCE.md §3.6: `McpUiStyleVariableKey` enumerates a fixed,
// 76-member set of CSS custom properties the host supplies to apps BY
// DESIGN, so an app using one of these is conforming, not evidence of
// impersonation. Extracted verbatim from the real ext-apps schema blob in
// fixtures/nondetect/sdk-bundle-inlined.html — NOT the abbreviated ~30-entry
// list in RULES.md / SPEC-REFERENCE.md prose.
// ---------------------------------------------------------------------------

export const MCP_STYLE_VARIABLES: ReadonlySet<string> = new Set([
  '--color-background-primary',
  '--color-background-secondary',
  '--color-background-tertiary',
  '--color-background-inverse',
  '--color-background-ghost',
  '--color-background-info',
  '--color-background-danger',
  '--color-background-success',
  '--color-background-warning',
  '--color-background-disabled',
  '--color-text-primary',
  '--color-text-secondary',
  '--color-text-tertiary',
  '--color-text-inverse',
  '--color-text-ghost',
  '--color-text-info',
  '--color-text-danger',
  '--color-text-success',
  '--color-text-warning',
  '--color-text-disabled',
  '--color-border-primary',
  '--color-border-secondary',
  '--color-border-tertiary',
  '--color-border-inverse',
  '--color-border-ghost',
  '--color-border-info',
  '--color-border-danger',
  '--color-border-success',
  '--color-border-warning',
  '--color-border-disabled',
  '--color-ring-primary',
  '--color-ring-secondary',
  '--color-ring-inverse',
  '--color-ring-info',
  '--color-ring-danger',
  '--color-ring-success',
  '--color-ring-warning',
  '--font-sans',
  '--font-mono',
  '--font-weight-normal',
  '--font-weight-medium',
  '--font-weight-semibold',
  '--font-weight-bold',
  '--font-text-xs-size',
  '--font-text-sm-size',
  '--font-text-md-size',
  '--font-text-lg-size',
  '--font-heading-xs-size',
  '--font-heading-sm-size',
  '--font-heading-md-size',
  '--font-heading-lg-size',
  '--font-heading-xl-size',
  '--font-heading-2xl-size',
  '--font-heading-3xl-size',
  '--font-text-xs-line-height',
  '--font-text-sm-line-height',
  '--font-text-md-line-height',
  '--font-text-lg-line-height',
  '--font-heading-xs-line-height',
  '--font-heading-sm-line-height',
  '--font-heading-md-line-height',
  '--font-heading-lg-line-height',
  '--font-heading-xl-line-height',
  '--font-heading-2xl-line-height',
  '--font-heading-3xl-line-height',
  '--border-radius-xs',
  '--border-radius-sm',
  '--border-radius-md',
  '--border-radius-lg',
  '--border-radius-xl',
  '--border-radius-full',
  '--border-width-regular',
  '--shadow-hairline',
  '--shadow-sm',
  '--shadow-md',
  '--shadow-lg',
]);

/** Recognizable prefixes of a specific host's PRIVATE design system. */
const HOST_PRIVATE_VAR_PREFIXES = ['--vscode-', '--ms-', '--fluent-', '--slack-', '--gh-', '--primer-'];

/** GitHub Primer-shaped class tokens, matched per whitespace-separated token. */
const PRIMER_CLASS =
  /^(octicon(-[a-z0-9-]+)?|Box(-[a-z0-9-]+)?|color-fg-[a-z0-9-]+|color-bg-[a-z0-9-]+|Button--[a-z]+|Label(--[a-z]+)?|Truncate(-[a-z]+)?|Popover(-[a-z]+)?|Overlay(-[a-z]+)?|CircleBadge(-[a-z]+)?)$/i;

export interface HostPrivateHit {
  evidence: string;
  location?: SourceLocation;
}

function hostPrivateVarHits(ctx: RuleContext): HostPrivateHit[] {
  const hits: HostPrivateHit[] = [];
  const VAR_RE = /var\(\s*(--[a-zA-Z0-9-]+)/g;

  for (const decl of ctx.styles.allDeclarations()) {
    VAR_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = VAR_RE.exec(decl.value))) {
      const name = m[1]!;
      if (MCP_STYLE_VARIABLES.has(name)) continue;
      if (!HOST_PRIVATE_VAR_PREFIXES.some((p) => name.startsWith(p))) continue;
      hits.push({
        evidence: `${decl.selector} { ${decl.prop}: ${decl.value} }`,
        ...(decl.location ? { location: decl.location } : {}),
      });
    }
  }

  return hits;
}

function hostPrivateClassHits(ctx: RuleContext): HostPrivateHit[] {
  const hits: HostPrivateHit[] = [];

  for (const el of allElements(ctx.dom)) {
    const cls = attr(el, 'class');
    if (!cls) continue;
    for (const token of cls.split(/\s+/).filter(Boolean)) {
      if (!PRIMER_CLASS.test(token)) continue;
      const loc = locationOf(el);
      hits.push({ evidence: token, ...(loc ? { location: loc } : {}) });
      break; // one hit per element is enough to disclose the element.
    }
  }

  return hits;
}

export function hostPrivateTokens(ctx: RuleContext): HostPrivateHit[] {
  return [...hostPrivateVarHits(ctx), ...hostPrivateClassHits(ctx)];
}

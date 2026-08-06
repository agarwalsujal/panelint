/**
 * PANE-EXFIL-001 — `<form action>` / `<button formaction>` to an off-document origin.
 *
 * The highest-severity rule in the catalog, because the finding is unblockable
 * by declaration. `_meta.ui.csp` has exactly four fields and all four map to
 * CSP *fetch* directives; `form-action` is not among them and does NOT fall
 * back to `default-src` (MDN, verbatim: "default-src fallback: No. Not setting
 * this allows anything."). It is absent from both policies the spec defines,
 * and appears zero times in the entire ext-apps repository.
 *
 * So `connect-src 'none'` — the field that looks like the egress control — is
 * decorative against a `<form>`, and the only defence is a host-side sandbox
 * flag the specification never requires.
 *
 * ── What this rule must NOT do ──────────────────────────────────────────────
 * The app document's URL is `about:srcdoc`, a `blob:` URL, or an opaque origin.
 * There is no origin to be "same" as. Every relative URL is same-document, so
 * an EMPTY `action` is the BENIGN case here — it re-posts to the app's own
 * document and reaches no network. The classic web-phishing heuristic that
 * treats an empty action as suspicious inverts in an MCP App, and porting it
 * over would fire CRITICAL/CERTAIN on conformant markup: a gate-eligible
 * finding on correct code, which GOALS.md G2 calls fatal.
 */

import { Element } from 'domhandler';
import type { RuleContext, RuleResult, SourceLocation } from '../../types.js';
import { attr, attrLocationOf, ancestors, selectAll } from '../../parse/html.js';
import { defineRule, makeFinding, structuralPath } from '../shared/helpers.js';
import { isOffDocument } from './url-shape.js';

/**
 * Fixed by docs/RULES.md and not to be softened. There is no "declare it more
 * tightly" available: the field does not exist.
 */
const REMEDIATION =
  '`form-action` is not covered by any `_meta.ui.csp` field, and it does not inherit from ' +
  '`default-src`. **The host cannot block this submission.** Send the data with `fetch()` to an ' +
  "origin declared in `connectDomains` instead, where the host's CSP applies.";

interface Target {
  el: Element;
  attrName: 'action' | 'formaction';
  url: string;
}

/** `method="dialog"` closes a dialog. It never submits anywhere. */
function submitsNowhere(el: Element, attrName: 'action' | 'formaction'): boolean {
  if (attrName === 'action') {
    return (attr(el, 'method') ?? '').trim().toLowerCase() === 'dialog';
  }
  const formmethod = (attr(el, 'formmethod') ?? '').trim().toLowerCase();
  if (formmethod === 'dialog') return true;
  if (formmethod) return false;
  // No override on the button: the owning form's method applies.
  const form = ancestors(el).find((a) => a.tagName === 'form');
  return form ? (attr(form, 'method') ?? '').trim().toLowerCase() === 'dialog' : false;
}

function collect(ctx: RuleContext): Target[] {
  const out: Target[] = [];

  // selectAll, never css-select directly: template content is a separate
  // document fragment that css-select does not descend into, and a `<form>`
  // inside a `<template>` is a one-line evasion of this rule.
  for (const el of selectAll('form[action]', ctx.dom)) {
    out.push({ el, attrName: 'action', url: attr(el, 'action') ?? '' });
  }
  for (const el of selectAll('button[formaction], input[formaction]', ctx.dom)) {
    // `formaction` is only meaningful on a submit control. An `<input>`
    // defaults to `type="text"`, where the attribute is inert — and this rule
    // is CRITICAL/CERTAIN, so it must not fire on markup that cannot submit.
    if (el.tagName === 'input') {
      const type = (attr(el, 'type') ?? '').trim().toLowerCase();
      if (type !== 'submit' && type !== 'image') continue;
    } else if ((attr(el, 'type') ?? 'submit').trim().toLowerCase() !== 'submit') {
      // `<button type="button">` does not submit either.
      continue;
    }
    out.push({ el, attrName: 'formaction', url: attr(el, 'formaction') ?? '' });
  }
  return out;
}

export const exfil001 = defineRule({
  id: 'PANE-EXFIL-001',
  ruleClass: 'RISK',
  severity: 'CRITICAL',
  confidence: 'CERTAIN',
  title: 'Form submits to an off-document origin',
  specRef: 'SEP-1865 apps.mdx L275-284, L1733-1744 — form-action absent from both policies',
  cwe: 'CWE-201',
  remediation: REMEDIATION,
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['content'],

  check(ctx: RuleContext): RuleResult {
    const findings = [];

    for (const { el, attrName, url } of collect(ctx)) {
      if (!isOffDocument(url)) continue;
      if (submitsNowhere(el, attrName)) continue;

      const location: SourceLocation | undefined = attrLocationOf(el, attrName);
      findings.push(
        makeFinding({
          ctx,
          rule: exfil001,
          message:
            `<${el.tagName} ${attrName}> submits to an absolute off-document origin. The app ` +
            'document has an opaque origin, so this is a cross-origin submission, and no ' +
            '`_meta.ui.csp` field governs it — `form-action` is absent from the spec\'s policies ' +
            'and does not inherit from `default-src`.',
          evidence: url,
          ...(location ? { location } : {}),
          path: `${structuralPath(el)}@${attrName}`,
        }),
      );
    }

    return { findings };
  },
});

export default exfil001;

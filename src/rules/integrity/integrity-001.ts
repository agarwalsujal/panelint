/**
 * PANE-INTEGRITY-001 — external subresource with no `integrity`.
 *
 * Attacker A4 (supply chain) is ranked fourth in the threat model and had zero
 * rules before this family. CWE-353.
 *
 * ── Why it must cover the DYNAMIC form ──────────────────────────────────────
 * `map-server` loads CesiumJS by creating the `<script>` element in JavaScript,
 * with a source comment explaining why: static `<script src>` tags do not work
 * inside `srcdoc` iframes. MCP Apps are frequently delivered as `srcdoc`, so
 * dynamic injection is not a bad habit — for many apps it is the ONLY available
 * pattern. A rule that reads markup only misses the dominant real-world case
 * and is decorative.
 *
 * ── Why MEDIUM, below the gate ──────────────────────────────────────────────
 * Same reason, from the other side. `map-server` is a reference server
 * following a documented workaround; a gate-eligible finding against it fails
 * the corpus. This is a genuine finding worth reporting and not one worth
 * breaking someone's build over.
 *
 * "External" means off-document, which in an app with an opaque origin means
 * every absolute URL. A relative `src` is same-document and SRI has nothing to
 * pin.
 */

import type { Element } from 'domhandler';
import type { Confidence, Finding, RuleContext, RuleResult } from '../../types.js';
import type { ParsedScript } from '../../parse/js.js';
import { findCalls, findMemberAssignments } from '../../parse/js.js';
import { attr, attrLocationOf, hasAttr, selectAll } from '../../parse/html.js';
import { defineRule, makeFinding, structuralPath } from '../shared/helpers.js';
// url-shape lives in ../exfil because PANE-EXFIL needed it first. The
// scheme-relative case matters here too: `//cdn.example.com/lib.js` is the
// idiomatic CDN spelling and is off-document.
import { isOffDocument, scriptsOf, sourceOf } from '../exfil/url-shape.js';

const REMEDIATION =
  'Add `integrity` (and `crossorigin`) to the subresource, pinning the exact bytes you tested ' +
  'against. On a dynamically created element, set `.integrity` and `.crossOrigin` before appending ' +
  'it. Without it, whoever can change the CDN copy can change what runs in the app.';

/** Static markup subresources whose bytes execute or style the document. */
function staticSubresources(ctx: RuleContext): Array<{ el: Element; attrName: 'src' | 'href' }> {
  const out: Array<{ el: Element; attrName: 'src' | 'href' }> = [];
  for (const el of selectAll('script[src]', ctx.dom)) out.push({ el, attrName: 'src' });
  for (const el of selectAll('link[rel][href]', ctx.dom)) {
    const rels = (attr(el, 'rel') ?? '').toLowerCase().split(/\s+/);
    if (rels.includes('stylesheet') || rels.includes('modulepreload')) {
      out.push({ el, attrName: 'href' });
    }
  }
  return out;
}

interface DynamicScript {
  script: ParsedScript;
  /** The `.src = …` assignment node. */
  node: import('acorn').Node;
  literalSrc: string | null;
  location: ReturnType<typeof findMemberAssignments>[number]['location'];
}

/**
 * `document.createElement('script')` in a script that also assigns `.src` and
 * never sets `integrity`.
 *
 * Script-scoped rather than data-flow: Panelint does not do taint analysis, and
 * "this script creates a script element, gives it a source, and never pins it"
 * is a structural fact that does not need it. Requiring the `createElement`
 * call is what keeps this off every `img.src = …` in the ecosystem.
 */
function dynamicScripts(scripts: ParsedScript[]): DynamicScript[] {
  const creators = new Set<ParsedScript>();
  for (const call of findCalls(scripts, [{ method: 'createElement' }])) {
    const arg = call.args[0] as unknown as { type?: string; value?: unknown } | undefined;
    if (arg?.type === 'Literal' && String(arg.value).toLowerCase() === 'script') {
      creators.add(call.script);
    }
  }

  const pinned = new Set<ParsedScript>();
  for (const a of findMemberAssignments(scripts, ['integrity'])) pinned.add(a.script);
  for (const call of findCalls(scripts, [{ method: 'setAttribute' }])) {
    const name = call.args[0] as unknown as { type?: string; value?: unknown } | undefined;
    if (name?.type === 'Literal' && String(name.value).toLowerCase() === 'integrity') {
      pinned.add(call.script);
    }
  }

  const out: DynamicScript[] = [];
  for (const a of findMemberAssignments(scripts, ['src'])) {
    if (!creators.has(a.script) || pinned.has(a.script)) continue;

    const right = a.right as unknown as { type?: string; value?: unknown };
    const literalSrc =
      right.type === 'Literal' && typeof right.value === 'string' ? right.value : null;
    // A literal same-document src has nothing to pin.
    if (literalSrc !== null && !isOffDocument(literalSrc)) continue;

    out.push({ script: a.script, node: a.node, literalSrc, location: a.location });
  }
  return out;
}

export const integrity001 = defineRule({
  id: 'PANE-INTEGRITY-001',
  ruleClass: 'RISK',
  severity: 'MEDIUM',
  confidence: 'HIGH',
  title: 'External subresource loaded without integrity',
  cwe: 'CWE-353',
  remediation: REMEDIATION,
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['content'],

  check(ctx: RuleContext): RuleResult {
    const findings: Finding[] = [];

    for (const { el, attrName } of staticSubresources(ctx)) {
      const url = attr(el, attrName) ?? '';
      if (!isOffDocument(url)) continue;
      if (hasAttr(el, 'integrity')) continue;

      const location = attrLocationOf(el, attrName);
      findings.push(
        makeFinding({
          ctx,
          rule: integrity001,
          message:
            `<${el.tagName}> loads an off-document subresource with no \`integrity\` attribute. ` +
            'Whoever can change the bytes at that URL changes what runs inside the app, and the ' +
            'change is invisible to both the server and the host.',
          evidence: url,
          ...(location ? { location } : {}),
          path: `${structuralPath(el)}@${attrName}`,
        }),
      );
    }

    let n = 0;
    for (const dyn of dynamicScripts(scriptsOf(ctx))) {
      const base = dyn.script.element ? structuralPath(dyn.script.element) : 'script';
      // A non-literal src cannot be shown to be off-document, so the finding is
      // reported at MEDIUM confidence rather than asserted.
      const confidence: Confidence = dyn.literalSrc === null ? 'MEDIUM' : 'HIGH';

      findings.push(
        makeFinding({
          ctx,
          rule: integrity001,
          message:
            'A `<script>` element created in JavaScript is given a `src` and never an `integrity`. ' +
            (dyn.literalSrc === null
              ? 'The source is built at runtime, so whether it is off-document cannot be decided ' +
                'statically. '
              : '') +
            'Dynamic injection is the documented workaround for `srcdoc` iframes, so this is ' +
            'reported below the gate — but the bytes are still unpinned.',
          evidence: sourceOf(dyn.script, dyn.node),
          ...(dyn.location ? { location: dyn.location } : {}),
          confidence,
          path: `${base}::script.src#${n++}`,
        }),
      );
    }

    return { findings };
  },
});

export default integrity001;

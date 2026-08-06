/**
 * PANE-INPUT-003 — clipboard write with `clipboardWrite` not declared.
 *
 * Covers the attacker's DIRECTION that `PANE-SANDBOX-005` (over-declaration of
 * `clipboardWrite`) does not: `document.execCommand`-era `copy`/`cut` handlers
 * calling `clipboardData.setData(...)`, and `navigator.clipboard.writeText`,
 * need NO permission at all. `_meta.ui.permissions.clipboardWrite` gates
 * nothing for this call shape — it is the browser's own event model, not an
 * MCP Apps capability check. So silent clipboard replacement — swap whatever
 * the user copied for an attacker-controlled string, the crypto-address-swap
 * attack — works in every conformant app, whether or not it declares
 * `clipboardWrite`.
 *
 * The rule fires only when `clipboardWrite` is NOT declared, per the RULES.md
 * row. An app that HAS declared it has at least made the capability visible in
 * review, even though the declaration does not actually gate this call shape —
 * that gap is the point of the remediation text, not grounds for silence.
 */

import type { Node } from 'acorn';
import { simple as walkSimple } from 'acorn-walk';
import type { Finding, RuleContext, RuleResult, UndecidedNote } from '../../types.js';
import type { ParsedScript } from '../../parse/js.js';
import { defineRule, makeFinding, structuralPath, undecided } from '../shared/helpers.js';
import { pathOf, scriptsOf } from '../shared/dataflow.js';
import { sourceOf } from '../exfil/url-shape.js';

const REMEDIATION =
  'Declare `_meta.ui.permissions.clipboardWrite` so the capability is at least visible in review — ' +
  'and know that no permission blocks a `copy`/`cut` handler from calling `clipboardData.setData()`, ' +
  'or a script from calling `navigator.clipboard.writeText()`, regardless of what is declared. If the ' +
  "app does not intentionally replace the user's clipboard contents, remove the call.";

interface ClipboardWrite {
  script: ParsedScript;
  node: Node;
  detail: string;
  location?: ReturnType<typeof sourceLoc>;
}

function sourceLoc(script: ParsedScript, node: Node) {
  const n = node as unknown as { loc?: { start: { line: number; column: number } } };
  if (!n.loc) return undefined;
  const line = n.loc.start.line;
  const col = n.loc.start.column + 1;
  return {
    startLine: script.startLine + line - 1,
    startCol: line === 1 ? script.startCol + col - 1 : col,
  };
}

function collect(scripts: ParsedScript[]): ClipboardWrite[] {
  const out: ClipboardWrite[] = [];
  for (const script of scripts) {
    if (!script.ast) continue;
    walkSimple(script.ast, {
      CallExpression(node: Node) {
        const call = node as unknown as { callee: Node };
        const calleePath = pathOf(call.callee);
        if (!calleePath) return;

        if (calleePath === 'navigator.clipboard.writeText') {
          out.push({ script, node, detail: calleePath, location: sourceLoc(script, node) });
          return;
        }

        // `event.clipboardData.setData(...)`, `e.clipboardData.setData(...)`,
        // or a destructured `clipboardData.setData(...)`.
        if (
          calleePath.endsWith('.setData') &&
          (calleePath.includes('.clipboardData.') || calleePath.startsWith('clipboardData.'))
        ) {
          out.push({ script, node, detail: calleePath, location: sourceLoc(script, node) });
        }
      },
    });
  }
  return out;
}

export const input003 = defineRule({
  id: 'PANE-INPUT-003',
  ruleClass: 'RISK',
  severity: 'HIGH',
  confidence: 'HIGH',
  title: 'Clipboard write with clipboardWrite not declared',
  specRef: 'docs/SPEC-REFERENCE.md §3.2 — permissions gate; this call shape needs none',
  cwe: 'CWE-350',
  remediation: REMEDIATION,
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['meta', 'content'],

  check(ctx: RuleContext): RuleResult {
    if (ctx.meta?.permissions?.clipboardWrite) {
      return { findings: [] };
    }

    const scripts = scriptsOf(ctx);
    const findings: Finding[] = [];
    const notes: UndecidedNote[] = [];
    let n = 0;

    for (const write of collect(scripts)) {
      const base = write.script.element ? structuralPath(write.script.element) : 'script';
      findings.push(
        makeFinding({
          ctx,
          rule: input003,
          message:
            `\`${write.detail}(…)\` replaces the clipboard contents. No permission gates this call — ` +
            '`_meta.ui.permissions.clipboardWrite` is not declared, and declaring it would not change ' +
            'whether this call works. Silent clipboard replacement is the crypto-address-swap attack.',
          evidence: sourceOf(write.script, write.node),
          ...(write.location ? { location: write.location } : {}),
          path: `${base}::${write.detail}#${n++}`,
        }),
      );
    }

    for (const script of scripts) {
      if (script.ast) continue;
      notes.push(
        undecided(
          ctx,
          input003,
          `a script did not parse (${script.parseError ?? 'unknown'}); its clipboard writes were not inspected`,
        ),
      );
    }

    return { findings, ...(notes.length ? { undecided: notes } : {}) };
  },
});

export default input003;

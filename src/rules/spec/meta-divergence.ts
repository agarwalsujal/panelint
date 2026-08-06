/**
 * PANE-SPEC-010 — list-level and read-level `_meta.ui` diverge, broader at read.
 *
 * `_meta.ui` has TWO sources. The `resources/list` entry is the "static default
 * for hosts to review at connection time"; the `resources/read` content item
 * takes precedence. A server whose list-level CSP is narrow and whose read-level
 * CSP is broad presents a misleading review surface: a host reviewing at
 * connection time sees a policy narrower than the one actually enforced.
 *
 * ── ☠ Correction [v3] — this was a fourth poisoned rule ──────────────────────
 * As written it compared `!deepEqual(list, read)` at RISK/HIGH/CERTAIN. Idiomatic
 * `registerAppResource` usage populates the LIST-level `_meta.ui` and leaves the
 * READ-level one ABSENT — a resource declared once, with a CSP, in the ordinary
 * way. A naive inequality check is therefore true for every conformant server
 * that declares a CSP at all, and it fires hardest on the servers that did the
 * most work. That is the same failure shape as PANE-SPEC-006, found the same
 * way — see docs/RULES.md.
 *
 * Corrected to fire only when ALL of: both forms are present, they differ, AND
 * the read-level policy is the BROADER of the two. An absent read-level value
 * means the list value IS the effective value — that is not divergence. A
 * read-level policy that is NARROWER than what the host reviewed is not the
 * finding either; the misleading review surface is specifically the one where
 * the enforced policy is WIDER than the advertised one.
 *
 * ── What "broader" means here ─────────────────────────────────────────────────
 *  - csp: declared at read but entirely absent at list — presence alone widens
 *    the synthesized `connect-src` from `'none'` to `'self'` (the same quirk
 *    PANE-CSP-013 reports from the other direction). Otherwise, per CSP array,
 *    any read-level entry not covered by a list-level entry (verbatim, or by a
 *    list-level bare/scheme-only/leading-label-wildcard source).
 *  - permissions: any key present at read that is absent at list.
 *  - prefersBorder: requested (`true`) at list, dropped (not `true`) at read —
 *    the host reviewed a visible boundary and the effective one is gone.
 *
 * No `_meta` value ever appears in the finding message — only which field
 * diverged and in what structural sense. `docs/RULES.md` calls this the fourth
 * poisoned rule; the correction is load-bearing enough that a message leaking a
 * raw origin would undermine the same trust the correction protects.
 */

import { defineRule, makeFinding, NO_FINDINGS } from '../shared/helpers.js';
import { CSP_ARRAYS, cspOf, entriesOf, parseSource, sourceCovers } from '../csp/domains.js';
import type { RuleResult, UIResourceMeta, UIResourcePermissions } from '../../types.js';

// ---------------------------------------------------------------------------
// csp
// ---------------------------------------------------------------------------

/** Is every entry in `readVals` covered by something in `listVals`? */
function arrayIsBroader(listVals: string[], readVals: string[]): boolean {
  const listSet = new Set(listVals);
  for (const r of readVals) {
    if (listSet.has(r)) continue;

    const rp = parseSource(r);
    let covered = false;
    if (rp.kind === 'host' && rp.host && !rp.host.startsWith('*.')) {
      const scheme = rp.scheme ?? 'https';
      const port = rp.port ? `:${rp.port}` : '';
      const path = rp.path ?? '/';
      try {
        const url = new URL(`${scheme}://${rp.host}${port}${path}`);
        covered = listVals.some((l) => sourceCovers(parseSource(l), url));
      } catch {
        covered = false;
      }
    }
    if (!covered) return true;
  }
  return false;
}

function cspDivergence(list: UIResourceMeta, read: UIResourceMeta): string[] {
  const listHasCsp = (list as { csp?: unknown }).csp !== undefined;
  const readHasCsp = (read as { csp?: unknown }).csp !== undefined;

  // The declared-vs-omitted quirk: presence alone widens connect-src from
  // 'none' to 'self', regardless of what — if anything — the object contains.
  if (!listHasCsp && readHasCsp) {
    return [
      "csp is declared at the read level but absent at the list level — presence alone widens " +
        "the synthesized connect-src from 'none' to 'self', broader than what the list-level " +
        'entry reviewed',
    ];
  }
  if (!listHasCsp || !readHasCsp) return [];

  const listCsp = cspOf(list);
  const readCsp = cspOf(read);
  const reasons: string[] = [];
  for (const array of CSP_ARRAYS) {
    const listVals = entriesOf(listCsp, array).map((e) => e.value);
    const readVals = entriesOf(readCsp, array).map((e) => e.value);
    if (arrayIsBroader(listVals, readVals)) {
      reasons.push(`csp.${array} permits an origin at read that the list-level declaration does not cover`);
    }
  }
  return reasons;
}

// ---------------------------------------------------------------------------
// permissions
// ---------------------------------------------------------------------------

function permissionKeys(meta: UIResourceMeta): Set<string> {
  const p = (meta as { permissions?: unknown }).permissions;
  if (!p || typeof p !== 'object' || Array.isArray(p)) return new Set();
  return new Set(Object.keys(p as UIResourcePermissions));
}

function permissionsDivergence(list: UIResourceMeta, read: UIResourceMeta): string[] {
  const listKeys = permissionKeys(list);
  const readKeys = permissionKeys(read);
  const added = [...readKeys].some((k) => !listKeys.has(k));
  return added ? ['permissions grants a capability at read that the list-level declaration does not'] : [];
}

// ---------------------------------------------------------------------------
// prefersBorder
// ---------------------------------------------------------------------------

function boundaryDivergence(list: UIResourceMeta, read: UIResourceMeta): string[] {
  if (list.prefersBorder === true && read.prefersBorder !== true) {
    return ['prefersBorder is requested at the list level and dropped at the read level'];
  }
  return [];
}

// ---------------------------------------------------------------------------

export const paneSpec010 = defineRule({
  id: 'PANE-SPEC-010',
  ruleClass: 'RISK',
  severity: 'HIGH',
  confidence: 'CERTAIN',
  title: 'List-level and read-level _meta.ui diverge, read-level is broader',
  specRef: 'RULES.md § PANE-SPEC — PANE-SPEC-010, corrected [v3]',
  remediation:
    'Keep the list-level _meta.ui at least as permissive as the read-level value, or make them ' +
    'identical. A host that reviews the list-level declaration at connection time must not be ' +
    'shown a narrower policy than the one actually enforced when the resource is read.',
  experimental: false,
  status: 'active',
  since: '0.1.0',
  requires: ['meta', 'listMeta'],

  check(ctx): RuleResult {
    const list = ctx.resource.metaFromList;
    const read = ctx.resource.metaFromRead;
    // ☠ The guard. Idiomatic registerAppResource usage leaves the read-level
    // value absent — the list value IS the effective value, not a divergence.
    if (list === undefined || read === undefined) return NO_FINDINGS;

    const reasons = [
      ...cspDivergence(list, read),
      ...permissionsDivergence(list, read),
      ...boundaryDivergence(list, read),
    ];
    if (reasons.length === 0) return NO_FINDINGS;

    return {
      findings: [
        makeFinding({
          ctx,
          rule: paneSpec010,
          message:
            'List-level and read-level _meta.ui diverge, and the read-level policy is broader: ' +
            `${reasons.join('; ')}. A host reviewing the list-level declaration at connection ` +
            'time would see a narrower policy than the one actually enforced.',
          jsonPointer: '/meta/ui',
          path: 'meta/ui/divergence',
        }),
      ],
    };
  },
});

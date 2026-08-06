/**
 * Generate src/rules/registry.ts from the rule modules on disk.
 *
 * The registry is a public contract — `panelint rules --json` publishes it, the
 * census directory keys on the IDs, and disclosure emails cite them. Generating
 * it removes the one failure mode a hand-maintained list has: a rule that exists
 * in src/ but was never registered silently never runs, and nothing fails.
 *
 * Run: node scripts/build-registry.mjs
 */

import { readdirSync, readFileSync, writeFileSync, statSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, relative } from 'node:path';

const RULES_DIR = fileURLToPath(new URL('../src/rules/', import.meta.url));
const OUT = join(RULES_DIR, 'registry.ts');

/** Directories that hold rule families. `shared` holds helpers, not rules. */
const SKIP_DIRS = new Set(['shared']);
const SKIP_FILES = new Set(['registry.ts', 'dedup.ts']);

function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      if (SKIP_DIRS.has(entry)) continue;
      out.push(...walk(full));
    } else if (entry.endsWith('.ts') && !entry.endsWith('.d.ts') && !SKIP_FILES.has(entry)) {
      out.push(full);
    }
  }
  return out;
}

/**
 * Find exported rule bindings.
 *
 * Matches `export const <name> = defineRule(` and `export const <name>: ... = defineRule(`,
 * plus `defineSetRule(` for cross-resource rules. Anything else exported from a
 * rule module is a helper and is deliberately not registered.
 */
function exportedRules(source) {
  const names = [];
  const re = /export\s+const\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*define(?:Set)?Rule\s*\(/g;
  let m;
  while ((m = re.exec(source)) !== null) names.push(m[1]);
  return names;
}

if (!existsSync(RULES_DIR)) {
  console.error(`No rules directory at ${RULES_DIR}`);
  process.exit(1);
}

const files = walk(RULES_DIR).sort();
const imports = [];
const members = [];
let total = 0;

for (const file of files) {
  const source = readFileSync(file, 'utf8');
  const names = exportedRules(source);
  if (names.length === 0) continue;

  const spec = './' + relative(RULES_DIR, file).replace(/\\/g, '/').replace(/\.ts$/, '.js');
  const alias = relative(RULES_DIR, file)
    .replace(/\\/g, '/')
    .replace(/\.ts$/, '')
    .replace(/[^A-Za-z0-9]/g, '_');

  imports.push(`import { ${names.join(', ')} } from '${spec}';`);
  members.push(...names);
  total += names.length;
  void alias;
}

const banner = `/**
 * The rule registry — GENERATED. Do not edit by hand.
 *
 * Regenerate with: node scripts/build-registry.mjs
 *
 * SARIF \`rules[].id\` is a public contract: the census directory keys on it and
 * disclosure emails cite it. IDs are permanent and never reused; a retired rule
 * keeps its ID with \`status: 'retired'\`. test/registry-docs.test.ts asserts this
 * file matches the tables in docs/RULES.md on id, class, severity and confidence,
 * so a doc and the code cannot silently diverge.
 */

import type { AnyRule } from '../types.js';
`;

const body = `
${imports.join('\n')}

/**
 * Every rule Panelint knows about, in ID order.
 *
 * Frozen because src/index.ts exports it. An unfrozen array on a public API
 * lets any code in the process — a consumer, or anything it pulls in — run
 * \`ALL_RULES.length = 0\` and turn the scanner into a no-op that finds nothing
 * and exits 0. That is the "gate that silently stopped scanning" failure the
 * corpus tests exist to catch, reachable from outside.
 */
export const ALL_RULES: readonly AnyRule[] = Object.freeze(
  [
${members.map((n) => `    ${n},`).join('\n')}
  ].sort((a, b) => a.id.localeCompare(b.id)) as AnyRule[],
);

/**
 * A \`ReadonlyMap\` type does not stop \`.set()\` or \`.delete()\` at runtime, and
 * this map is exported too, so the mutators are replaced rather than typed away.
 */
export const RULES_BY_ID: ReadonlyMap<string, AnyRule> = Object.assign(
  new Map(ALL_RULES.map((r) => [r.id, r] as const)),
  {
    set(): never {
      throw new TypeError('RULES_BY_ID is immutable');
    },
    delete(): never {
      throw new TypeError('RULES_BY_ID is immutable');
    },
    clear(): never {
      throw new TypeError('RULES_BY_ID is immutable');
    },
  },
);

/** Rules that run for a given scan, honouring --experimental. */
export function selectRules(opts: { experimental?: boolean } = {}): AnyRule[] {
  return ALL_RULES.filter((r) => r.status !== 'retired')
    .filter((r) => (opts.experimental ? true : !r.experimental));
}
`;

writeFileSync(OUT, banner + body, 'utf8');
console.log(`registry.ts: ${total} rules from ${imports.length} modules`);
for (const id of members.slice(0, 5)) console.log(`  e.g. ${id}`);

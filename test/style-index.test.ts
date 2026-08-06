import { describe, it, expect } from 'vitest';
import { parseHtml, selectOne } from '../src/parse/html.js';
import { buildStyleIndex } from '../src/parse/style-index.js';
import { DEFAULT_LIMITS } from '../src/limits.js';

function index(html: string, limits = DEFAULT_LIMITS) {
  const { dom } = parseHtml(html, limits);
  return { dom, styles: buildStyleIndex(dom, limits) };
}

describe('StyleIndex — node-indexed declared style', () => {
  it('binds a <style> block declaration to the node it matches', () => {
    // v1 kept a selector → declarations map, which answers the opposite of the
    // question every PANE-HIDDEN rule asks: "what applies to THIS node".
    const { dom, styles } = index('<style>.a{opacity:0}</style><div class="a">x</div>');
    const el = selectOne('div.a', dom)!;
    expect(styles.declaredStyle(el).get('opacity')?.value).toBe('0');
  });

  it('binds an inline style= attribute', () => {
    const { dom, styles } = index('<div id="d" style="display:none">x</div>');
    const el = selectOne('#d', dom)!;
    expect(styles.declaredStyle(el).get('display')?.value).toBe('none');
  });

  it('gives inline style higher precedence than a sheet rule', () => {
    const { dom, styles } = index('<style>#d{color:red}</style><div id="d" style="color:blue">x</div>');
    const el = selectOne('#d', dom)!;
    expect(styles.declaredStyle(el).get('color')?.value).toBe('blue');
  });

  it('resolves by specificity, not source order, within one sheet', () => {
    const { dom, styles } = index('<style>#d{color:green} div{color:red}</style><div id="d">x</div>');
    const el = selectOne('#d', dom)!;
    expect(styles.declaredStyle(el).get('color')?.value).toBe('green');
  });

  it('lets !important beat higher specificity', () => {
    const { dom, styles } = index('<style>#d{color:green} div{color:red !important}</style><div id="d">x</div>');
    const el = selectOne('#d', dom)!;
    expect(styles.declaredStyle(el).get('color')?.value).toBe('red');
  });

  it('records a source location for a sheet declaration', () => {
    const { dom, styles } = index('<style>\n.a{opacity:0}\n</style><div class="a">x</div>');
    const el = selectOne('div.a', dom)!;
    expect(styles.declaredStyle(el).get('opacity')?.location?.startLine).toBeGreaterThan(0);
  });

  it('does not inherit — a declaration on the parent is not reported on the child', () => {
    // The refusal to inherit is what makes the honesty claim in DESIGN.md §6
    // real. Rules that need inheritance must decline to answer.
    const { dom, styles } = index('<style>.p{opacity:0}</style><div class="p"><span id="c">x</span></div>');
    const child = selectOne('#c', dom)!;
    expect(styles.declaredStyle(child).has('opacity')).toBe(false);
  });

  it('treats a stateful pseudo-class as non-applying', () => {
    // :hover styles are not the resting state, so binding them to a node would
    // report text as hidden that is plainly visible until hovered.
    const { dom, styles } = index('<style>.a:hover{opacity:0}</style><div class="a">x</div>');
    const el = selectOne('div.a', dom)!;
    expect(styles.declaredStyle(el).has('opacity')).toBe(false);
  });

  it('drops pseudo-elements rather than binding them to the originating node', () => {
    const { dom, styles } = index('<style>.a::before{content:"x";opacity:0}</style><div class="a">y</div>');
    const el = selectOne('div.a', dom)!;
    expect(styles.declaredStyle(el).has('opacity')).toBe(false);
  });

  it('skips an unsupported selector without going fatal', () => {
    const { dom, styles } = index('<style>@media(min-width:0){.a{color:red}} .b >>> .c{color:blue} .a{opacity:0}</style><div class="a">x</div>');
    const el = selectOne('div.a', dom)!;
    expect(styles.declaredStyle(el).get('opacity')?.value).toBe('0');
  });
});

describe('StyleIndex — resolution is additive-only', () => {
  const LAYERED = `<style>
    @layer a, b;
    @layer b { .x { opacity: 0 } }
    @layer a { .x { opacity: 1 } }
  </style><div class="x">secret</div>`;

  it('marks a node under an unmodelled at-rule as undecided', () => {
    // Layer order outranks source order, and inside a layer !important inverts
    // layer precedence. A resolver ordering by (origin, !important, specificity,
    // source order) concludes opacity:1 and reports nothing, while the browser
    // renders the text invisible.
    const { dom, styles } = index(LAYERED);
    const el = selectOne('div.x', dom)!;
    expect(styles.isUndecided(el)).toBe(true);
    expect(styles.undecidedReasons().join(' ')).toMatch(/@layer/);
  });

  it('still surfaces the losing opacity:0 as a candidate — resolution may never suppress a finding', () => {
    // This is the architectural constraint, not a preference. If resolution
    // could clear a finding, @layer would be a one-line evasion of the whole
    // PANE-HIDDEN family, and per SECURITY.md §1 a targeted evasion is a
    // reportable vulnerability in Panelint rather than a documented limitation.
    const { dom, styles } = index(LAYERED);
    const el = selectOne('div.x', dom)!;
    const values = styles.candidatesFor(el, 'opacity').map((d) => d.value);
    expect(values).toContain('0');
  });

  it('surfaces a candidate that lost on specificity', () => {
    const { dom, styles } = index('<style>#d{opacity:1} div{opacity:0}</style><div id="d">x</div>');
    const el = selectOne('#d', dom)!;
    expect(styles.candidatesFor(el, 'opacity').map((d) => d.value)).toContain('0');
    expect(styles.declaredStyle(el).get('opacity')?.value).toBe('1');
  });

  it('marks @supports, @container and @scope undecided as well', () => {
    for (const at of ['@supports (display:grid)', '@container (min-width:0)', '@scope (.s)']) {
      const { dom, styles } = index(`<style>${at} { .x { opacity: 0 } }</style><div class="x">t</div>`);
      const el = selectOne('div.x', dom)!;
      expect(styles.isUndecided(el), `${at} should mark undecided`).toBe(true);
    }
  });

  it('does not mark a plain @media block undecided — that one is modelled', () => {
    const { dom, styles } = index('<style>@media screen { .x { color: red } }</style><div class="x">t</div>');
    const el = selectOne('div.x', dom)!;
    expect(styles.isUndecided(el)).toBe(false);
  });
});

describe('StyleIndex — limits', () => {
  it('emits LIMIT_EXCEEDED and stops rather than matching an unbounded rule count', () => {
    const rules = Array.from({ length: 60 }, (_, i) => `.c${i}{color:red}`).join('');
    const { dom } = parseHtml(`<style>${rules}</style><div class="c1">x</div>`, DEFAULT_LIMITS);
    const styles = buildStyleIndex(dom, { ...DEFAULT_LIMITS, maxCssRules: 10 });
    expect(styles.diagnostics.some((d) => d.code === 'LIMIT_EXCEEDED')).toBe(true);
  });

  it('stops matching when the selector budget is exhausted', () => {
    const rules = Array.from({ length: 40 }, (_, i) => `.c${i}{color:red}`).join('');
    const { dom } = parseHtml(`<style>${rules}</style><div class="c1">x</div>`, DEFAULT_LIMITS);
    const styles = buildStyleIndex(dom, { ...DEFAULT_LIMITS, selectorMatchBudget: 5 });
    expect(styles.diagnostics.some((d) => d.code === 'LIMIT_EXCEEDED')).toBe(true);
  });
});

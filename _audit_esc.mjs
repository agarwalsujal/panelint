import {safe, encodeForJson, encodeForSarif} from './dist/safe/untrusted.js';
const C = (n) => String.fromCharCode(n);
const ESC = C(27), BEL = C(7);
const cases = {
  ansi: ESC + '[31mRED' + ESC + '[0m',
  osc52: ESC + ']52;c;cGF5bG9hZA==' + BEL,
  cr_workflow: '\r::error::pwned',
  lf_workflow: '\n::set-output name=x::y',
  script_close: '</script>',
  bidi: C(0x202E) + 'evil',
  zwsp: C(0x200B),
  nul: C(0) + 'x',
  literal_backslash_u: 'a\\u001b[31m',
  sarif_link: '](https://evil)',
  quotes: '"q" \'s\'',
  astral: String.fromCodePoint(0x1F600),
  lone_surrogate: C(0xDFFF),
  u2028: C(0x2028),
  backtick_dollar: '`${x}`',
  del: C(0x7F),
  c1_csi: C(0x9B) + '31m',
  tagchars: String.fromCodePoint(0xE0041),
};
const CTRL = new RegExp('[' + C(0)+'-'+C(8) + C(0x0b)+'-'+C(0x1f) + C(0x7f)+'-'+C(0x9f) + C(0x200b)+'-'+C(0x200f) + C(0x202a)+'-'+C(0x202e) + ']');
let fail = 0;
for (const [k,v] of Object.entries(cases)) {
  const s = safe(v, 200);
  const raw = CTRL.test(s);
  if (raw) fail++;
  console.log(k.padEnd(20), 'safe=' + JSON.stringify(s), 'rawCtl=' + raw, 'sarif=' + JSON.stringify(encodeForSarif(s)), 'json=' + JSON.stringify(encodeForJson(s)));
}
console.log('leaked raw control chars:', fail);
console.log('cap1:', JSON.stringify(safe('abc', 1)));
console.log('cap on astral:', JSON.stringify(safe(String.fromCodePoint(0x1F600)+'x', 1)));

import { readFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { parse } from 'acorn';
import { simple } from 'acorn-walk';

const files = execSync("find dist -name '*.js'").toString().trim().split('\n');
const regexes = [];
const seen = new Set();
for (const f of files) {
  let ast; try { ast = parse(readFileSync(f,'utf8'), {ecmaVersion:'latest', sourceType:'module', locations:true}); } catch { continue; }
  simple(ast, { Literal(n){ if(n.regex && !seen.has(n.raw)){ seen.add(n.raw); regexes.push({f, line:n.loc.start.line, raw:n.raw, pat:n.regex.pattern, fl:n.regex.flags}); } } });
}

// pathological input generators
const ALPHA = ['a','A','0',' ','\t','<','>','(',')','[',']','{','}','"',"'",'/','\\','-','_','.',':',';',',','=','$','#','%','&','*','+','?','!','|','~','^','@','`','\n'];
function gens(N) {
  const out = [];
  for (const c of ALPHA) out.push(c.repeat(N));
  // 2-char cycles
  const pairs = ['<a','a(','ur','[a','&#','{}','a=','0.','a-','\\u','""',"''",'a:','/*','$0','a ','  ','x)','(x','a\t'];
  for (const p of pairs) out.push(p.repeat(N/2|0));
  out.push('url('.repeat(N/4|0));
  out.push('<noscript>'.repeat(N/10|0));
  out.push('"<html '.repeat(N/7|0));
  out.push('a'.repeat(N)+'!');
  out.push(' '.repeat(N)+'X');
  out.push('0'.repeat(N)+'X');
  out.push('#'+'a'.repeat(N));
  out.push('a('+'('.repeat(N));
  return out;
}

const N = 6000;
const inputs = gens(N);
const results = [];
for (const r of regexes) {
  let worst = 0, worstIn = '';
  for (const inp of inputs) {
    let re; try { re = new RegExp(r.pat, r.fl); } catch { break; }
    const t0 = process.hrtime.bigint();
    try { if (r.fl.includes('g')) { re.lastIndex=0; while(re.exec(inp)!==null){} } else re.test(inp); } catch {}
    const ms = Number(process.hrtime.bigint()-t0)/1e6;
    if (ms > worst) { worst = ms; worstIn = inp.slice(0,12); }
  }
  if (worst > 20) results.push({worst, worstIn, ...r});
}
results.sort((a,b)=>b.worst-a.worst);
for (const r of results) console.log(`${r.worst.toFixed(0).padStart(7)} ms  n=${N}  ${r.f}:${r.line}  input="${JSON.stringify(r.worstIn)}"x  ${r.raw.slice(0,110)}`);
console.log(`\nscanned ${regexes.length} distinct regexes, ${inputs.length} inputs each at n=${N}`);

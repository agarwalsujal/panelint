import { readFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { parse } from 'acorn';
import { simple } from 'acorn-walk';
const files = execSync("find dist -name '*.js'").toString().trim().split('\n');
const regexes = []; const seen = new Set();
for (const f of files) {
  let ast; try { ast = parse(readFileSync(f,'utf8'), {ecmaVersion:'latest', sourceType:'module'}); } catch { continue; }
  simple(ast, { Literal(n){ if(n.regex && !seen.has(n.raw)){ seen.add(n.raw); regexes.push({f, raw:n.raw, pat:n.regex.pattern, fl:n.regex.flags}); } } });
}
const SKIP = /\^\\s\*\(\\\$/; // pane-hidden-007, already characterised
const ALPHA=['a','A','0',' ','\t','<','>','(',')','[',']','{','}','"',"'",'/','\\','-','_','.',':',';',',','=','$','#','%','&','*','+','?','!','|','~','^','@','`'];
function gens(N){const o=[];for(const c of ALPHA)o.push(c.repeat(N));
 for(const p of ['<a','a(','ur','[a','&#','a=','0.','a-','a:','/*','a ','x)','(x','a\t','<!','<n','#a','a)','\\u'])o.push(p.repeat(N/2|0));
 o.push('url('.repeat(N/4|0));o.push('<noscript>'.repeat(N/10|0));o.push('"<html '.repeat(N/7|0));
 o.push('a'.repeat(N)+'!');o.push(' '.repeat(N)+'X');o.push('<a'.repeat(N/2|0)+'>');
 o.push('url("'.repeat(N/5|0));o.push('[a^='.repeat(N/4|0));o.push('&#x'.repeat(N/3|0));return o;}
function run(r, inp){ const re=new RegExp(r.pat,r.fl); const t0=process.hrtime.bigint();
 try{ if(r.fl.includes('g')){re.lastIndex=0; while(re.exec(inp)!==null){}} else re.test(inp);}catch{}
 return Number(process.hrtime.bigint()-t0)/1e6; }
const out=[];
for (const r of regexes) {
  if (SKIP.test(r.pat)) continue;
  let best=null;
  for (const inp of gens(20000)) { const ms = run(r, inp); if(!best||ms>best.ms) best={ms, inp}; }
  if (best.ms < 5) continue;
  const ms4 = run(r, best.inp.repeat? null : null) ;
  // rebuild same shaped input at 4x
  const big = best.inp.repeat(4);
  const msBig = run(r, big);
  out.push({r, small:best.ms, big:msBig, ratio: msBig/Math.max(best.ms,0.01), inp: best.inp.slice(0,14)});
}
out.sort((a,b)=>b.big-a.big);
for (const o of out) console.log(`${o.big.toFixed(0).padStart(8)} ms @80k  (${o.small.toFixed(0)} ms @20k, x${o.ratio.toFixed(1)})  ${o.r.f}  in=${JSON.stringify(o.inp)}  ${o.r.raw.slice(0,95)}`);

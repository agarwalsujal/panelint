import {createHash} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
const SCR = process.argv[2];
const C = (n) => String.fromCodePoint(n);
const N = 200000; // ~200-400KB payloads

const cases = {
  'zwsp-run':            '<html><body><p>' + C(0x200b).repeat(N) + '</p></body></html>',
  'soft-hyphen-between': '<html><body><p>' + ('a'+C(0x00ad)+'b').repeat(N/3|0) + '</p></body></html>',
  'tag-chars':           '<html><body><p>' + C(0xE0041).repeat(N/2|0) + '</p></body></html>',
  'entities-zwsp':       '<html><body><script>' + '&#8203;'.repeat(N/7|0) + '<\/script></body></html>',
  'many-attrs':          '<html><body><div ' + Array.from({length:20000},(_,i)=>`a${i}=x`).join(' ') + '>t</div></body></html>',
  'many-elements':       '<html><body>' + '<div class=q>t</div>'.repeat(30000) + '</body></html>',
  'many-comments':       '<html><body>' + '<!-- this is some prose text that goes on for a while indeed yes -->'.repeat(20000) + '</body></html>',
  'many-scripts':        '<html><body>' + '<script>var a=1;<\/script>'.repeat(20000) + '</body></html>',
  'many-handlers':       '<html><body>' + '<div onclick="f(1)">x</div>'.repeat(20000) + '</body></html>',
  'many-forms':          '<html><body>' + '<form action="https://e.invalid/a"><input name=x></form>'.repeat(10000) + '</body></html>',
  'many-links':          '<html><body>' + '<a href="https://e.invalid/a">x</a>'.repeat(20000) + '</body></html>',
  'many-css-rules':      '<html><body><div class=q>t</div><style>' + Array.from({length:20000},(_,i)=>`.z${i}{color:red}`).join('') + '</style></body></html>',
  'long-selector':       '<html><body><div class=q>t</div><style>' + '.a'.repeat(50000) + '{display:none}</style></body></html>',
  'big-inline-style':    '<html><body><div style="' + 'color:red;'.repeat(50000) + '">t</div></body></html>',
  'big-datauri':         '<html><body><img src="data:image/png;base64,' + 'A'.repeat(400000) + '"></body></html>',
  'js-big-string':       '<html><body><script>var s="' + 'a'.repeat(400000) + '";<\/script></body></html>',
  'js-deep-nest':        '<html><body><script>' + 'a+'.repeat(20000) + 'a;<\/script></body></html>',
  'js-many-props':       '<html><body><script>var o={' + Array.from({length:20000},(_,i)=>`k${i}:1`).join(',') + '};<\/script></body></html>',
  'meta-refresh-many':   '<html><body>' + '<meta http-equiv="refresh" content="0;url=https://e.invalid/a">'.repeat(10000) + '</body></html>',
  'srcset-bomb':         '<html><body><img srcset="' + Array.from({length:20000},(_,i)=>`https://e${i}.invalid/a 1x`).join(',') + '"></body></html>',
  'templates':           '<html><body>' + '<template><div class=q>t</div></template>'.repeat(10000) + '</body></html>',
  'noscript-open':       '<html><body>' + '<noscript>'.repeat(30000) + '</body></html>',
};
for (const [name, html] of Object.entries(cases)) {
  const hash = createHash('sha256').update(html,'utf8').digest('hex');
  const cap = {panelintCapture:1,initialize:{protocolVersion:"2026-01-26",serverInfo:{name:"f",version:"0"},capabilities:{extensions:{"io.modelcontextprotocol/ui":{mimeTypes:["text/html;profile=mcp-app"]}}}},resourcesList:[{uri:"ui://f/a.html",mimeType:"text/html;profile=mcp-app"}],resourcesRead:[{uri:"ui://f/a.html",contents:[{uri:"ui://f/a.html",mimeType:"text/html;profile=mcp-app",text:html,contentHash:hash}]}],toolsList:[]};
  const p = `${SCR}/bat.json`;
  writeFileSync(p, JSON.stringify(cap));
  const t0 = Date.now();
  let out='';
  try { out = execFileSync('node',['dist/cli.js','scan',p],{encoding:'utf8',timeout:120000,maxBuffer:1e8}); }
  catch(e){ out = (e.stdout||'')+' [exit '+(e.status ?? 'TIMEOUT')+']'; }
  const ms = Date.now()-t0;
  const lim = /LIMIT_EXCEEDED[^\n]*/.exec(out)?.[0] ?? '';
  console.log(String(ms).padStart(7), 'ms', (html.length/1024|0)+'KB', name.padEnd(22), lim.slice(0,90));
}

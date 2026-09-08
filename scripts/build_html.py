"""Build the single-file online edition of the report.

Requirements from the series' delivery conventions: one HTML file, inline CSS and JS, no CDN
(intranets block outbound), sidebar table of contents with anchors, client-side search,
tables that scroll horizontally on narrow screens instead of being cut off, light/dark aware.
"""

from __future__ import annotations

import html
import re
from pathlib import Path

import markdown

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "docs" / "GSMD-RPT-2026-0908-TBD_多模型多代理資安審查.md"
OUT = ROOT / "docs" / "GSMD-RPT-2026-0908-TBD_多模型多代理資安審查.html"

CSS = """
:root{--bg:#f5f6f8;--fg:#1b1f26;--muted:#5b6370;--line:#d5d9e0;--panel:#ffffff;--accent:#2b5d8c;--accent-soft:#e4edf6;--code:#eef1f5;--mark:#ffe58a;--ok:#2f7d4f;--warn:#a2620f;--bad:#b23a3a}
@media (prefers-color-scheme: dark){:root:not([data-theme="light"]){--bg:#14171c;--fg:#e6e9ee;--muted:#9aa3b0;--line:#2f353e;--panel:#1b1f26;--accent:#8db8e0;--accent-soft:#213040;--code:#20252c;--mark:#5a4a00;--ok:#6cc08a;--warn:#e0a24a;--bad:#e07070}}
:root[data-theme="dark"]{--bg:#14171c;--fg:#e6e9ee;--muted:#9aa3b0;--line:#2f353e;--panel:#1b1f26;--accent:#8db8e0;--accent-soft:#213040;--code:#20252c;--mark:#5a4a00;--ok:#6cc08a;--warn:#e0a24a;--bad:#e07070}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.75 -apple-system,"Segoe UI","Noto Sans TC","PingFang TC","Microsoft JhengHei",Roboto,sans-serif}
.layout{display:grid;grid-template-columns:300px minmax(0,1fr);min-height:100vh}
nav{position:sticky;top:0;height:100vh;overflow:auto;border-right:1px solid var(--line);background:var(--panel);padding:16px 14px}
nav .brand{font-weight:700;font-size:13px;letter-spacing:.04em;color:var(--muted);margin:0 0 10px}
nav input{width:100%;padding:8px 10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg);font-size:14px}
nav ol{list-style:none;padding:0;margin:12px 0 0}
nav li a{display:block;padding:3px 6px;border-radius:6px;color:var(--fg);text-decoration:none;font-size:13px;line-height:1.45}
nav li a:hover{background:var(--accent-soft)}
nav li.h1>a{font-weight:700;margin-top:10px}
nav li.h2>a{padding-left:16px}
nav li.h3>a{padding-left:28px;color:var(--muted)}
nav li.active>a{background:var(--accent-soft);color:var(--accent)}
main{padding:32px 48px 96px;max-width:960px;width:100%;min-width:0}
main h1{font-size:26px;line-height:1.3;margin:48px 0 16px;padding-top:12px;border-top:2px solid var(--accent)}
main h1:first-of-type{border-top:0;margin-top:0}
main h2{font-size:21px;margin:36px 0 12px}
main h3{font-size:17px;margin:28px 0 8px}
main p{margin:0 0 14px;text-align:justify}
main a{color:var(--accent)}
.tablewrap{overflow-x:auto;margin:14px 0;border:1px solid var(--line);border-radius:8px}
table{border-collapse:collapse;min-width:100%;font-size:13.5px}
th,td{border-bottom:1px solid var(--line);padding:7px 10px;vertical-align:top;text-align:left}
th{background:var(--accent-soft);position:sticky;top:0}
pre{background:var(--code);border:1px solid var(--line);border-radius:8px;padding:12px 14px;overflow-x:auto;font-size:12.5px;line-height:1.5}
code{background:var(--code);padding:1px 4px;border-radius:4px;font-size:.92em}
pre code{background:none;padding:0}
mark{background:var(--mark);color:inherit;padding:0 1px}
.meta{color:var(--muted);font-size:13px}
main h1,main h2,main h3{text-wrap:balance}
table,.ev{font-variant-numeric:tabular-nums}
.ev{display:inline-block;font-size:11px;line-height:1.5;padding:0 6px;border-radius:4px;border:1px solid var(--line);background:var(--panel);color:var(--muted);vertical-align:middle;white-space:nowrap;margin:0 2px}
.ev-src{margin-left:4px;opacity:.85}
.ev-a{border-color:var(--ok);color:var(--ok)}.ev-v{border-color:var(--warn);color:var(--warn)}.ev-t{border-color:var(--accent);color:var(--accent)}.ev-u{border-color:var(--bad);color:var(--bad)}
a:focus-visible,button:focus-visible,input:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
@media (prefers-reduced-motion: reduce){nav{transition:none}}
.hits{font-size:12px;color:var(--muted);margin-top:6px}
.topbar{display:none}
@media (max-width:900px){.layout{grid-template-columns:minmax(0,1fr)}nav{position:fixed;left:0;top:0;width:82vw;max-width:340px;transform:translateX(-100%);transition:transform .2s;z-index:20}nav.open{transform:none}main{padding:64px 18px 80px}.topbar{display:flex;position:fixed;top:0;left:0;right:0;height:48px;align-items:center;gap:12px;padding:0 14px;background:var(--panel);border-bottom:1px solid var(--line);z-index:10}.topbar button{border:1px solid var(--line);background:var(--bg);color:var(--fg);border-radius:6px;padding:6px 10px}}
@media print{nav,.topbar{display:none}.layout{display:block}main{max-width:none;padding:0}}
"""

JS = """
(function(){
  const nav=document.querySelector('nav'), toc=document.getElementById('toc'), q=document.getElementById('q'), hits=document.getElementById('hits');
  const main=document.querySelector('main');
  const heads=[...main.querySelectorAll('h1,h2,h3')];
  heads.forEach((h,i)=>{ if(!h.id){h.id='s'+i;} const li=document.createElement('li'); li.className=h.tagName.toLowerCase(); const a=document.createElement('a'); a.href='#'+h.id; a.textContent=h.textContent; li.appendChild(a); toc.appendChild(li); });
  const items=[...toc.querySelectorAll('li')];
  const io=new IntersectionObserver(es=>{es.forEach(e=>{ if(e.isIntersecting){ items.forEach(x=>x.classList.remove('active')); const it=items.find(x=>x.querySelector('a').getAttribute('href')==='#'+e.target.id); if(it){it.classList.add('active'); it.scrollIntoView({block:'nearest'});} } });},{rootMargin:'0px 0px -80% 0px'});
  heads.forEach(h=>io.observe(h));
  let marks=[];
  function clear(){ marks.forEach(m=>{const t=document.createTextNode(m.textContent); m.parentNode.replaceChild(t,m);}); marks=[]; main.normalize(); }
  function search(term){
    clear(); if(!term||term.length<2){hits.textContent='';return;}
    const walker=document.createTreeWalker(main,NodeFilter.SHOW_TEXT,{acceptNode:n=>n.parentNode.closest('script,style')?NodeFilter.FILTER_REJECT:NodeFilter.FILTER_ACCEPT});
    const nodes=[]; let n; while((n=walker.nextNode())) nodes.push(n);
    const lc=term.toLowerCase(); let count=0, first=null;
    nodes.forEach(node=>{ const txt=node.nodeValue; let idx=txt.toLowerCase().indexOf(lc); if(idx<0) return; const frag=document.createDocumentFragment(); let last=0; while(idx>=0){ frag.appendChild(document.createTextNode(txt.slice(last,idx))); const m=document.createElement('mark'); m.textContent=txt.slice(idx,idx+term.length); frag.appendChild(m); marks.push(m); if(!first) first=m; count++; last=idx+term.length; idx=txt.toLowerCase().indexOf(lc,last);} frag.appendChild(document.createTextNode(txt.slice(last))); node.parentNode.replaceChild(frag,node); });
    hits.textContent=count?count+' 處符合，Enter 跳到第一處':'無符合';
    if(first) hits.dataset.first='1';
    search.first=first;
  }
  q.addEventListener('input',()=>search(q.value.trim()));
  q.addEventListener('keydown',e=>{ if(e.key==='Enter'&&search.first){ search.first.scrollIntoView({block:'center'}); } });
  const btn=document.getElementById('menu'); if(btn){ btn.addEventListener('click',()=>nav.classList.toggle('open')); toc.addEventListener('click',()=>nav.classList.remove('open')); }
})();
"""


def build() -> Path:
    md_text = SRC.read_text(encoding="utf-8")
    md_text = re.sub(r"^---\ntitle:.*?\n---\n", "", md_text, count=1, flags=re.S)
    body = markdown.markdown(md_text, extensions=["tables", "fenced_code", "sane_lists"], output_format="html5")
    body = body.replace("<table>", '<div class="tablewrap"><table>').replace("</table>", "</table></div>")
    # evidence markers 【級別｜來源】 become small chips; the grade drives the colour token
    def chip(m: re.Match) -> str:
        grade, rest = m.group(1), m.group(2)
        cls = {"已證實": "ev-a", "廠商主張": "ev-v", "第三方評論": "ev-t", "尚未證實": "ev-u"}[grade]
        return f'<span class="ev {cls}" title="證據級別：{grade}">{grade}<span class="ev-src">{html.escape(rest)}</span></span>'
    body = re.sub(r"【(已證實|廠商主張|第三方評論|尚未證實)((?:[^】])*)】", chip, body)
    title = "多模型多代理資安審查"
    page = f"""<title>{html.escape(title)}</title>
<style>{CSS}</style>
<div class="topbar"><button id="menu" aria-label="目次">☰ 目次</button><span class="meta">GSMD-RPT-2026-0908-TBD</span></div>
<div class="layout">
<nav><p class="brand">GSMD-RPT-2026-0908-TBD · v0.1.0 · 2026-09-08</p><input id="q" type="search" placeholder="搜尋全文（至少 2 字）" aria-label="搜尋"><div id="hits" class="hits"></div><ol id="toc"></ol></nav>
<main>{body}</main>
</div>
<script>{JS}</script>
"""
    OUT.write_text(page, encoding="utf-8")
    return OUT


if __name__ == "__main__":
    p = build()
    print(f"wrote {p} ({p.stat().st_size:,} bytes)")

"""Build the single-file online edition of the report.

Requirements from the series' delivery conventions: one HTML file, inline CSS and JS, no CDN
(intranets block outbound), sidebar table of contents with anchors, client-side search,
tables that scroll horizontally on narrow screens instead of being cut off, light/dark aware.
"""

from __future__ import annotations

import base64
import hashlib
import html
import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

import markdown

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "docs" / "GSMD-RPT-2026-0908-01_多模型多代理資安審查.md"
OUT = ROOT / "docs" / "GSMD-RPT-2026-0908-01_多模型多代理資安審查.html"

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
@media (max-width:900px){.layout{grid-template-columns:minmax(0,1fr)}nav{position:relative;height:auto;width:100%;transform:none}.js-enabled nav{position:fixed;left:0;top:0;height:100vh;width:82vw;max-width:340px;transform:translateX(-100%);transition:transform .2s;z-index:20}.js-enabled nav.open{transform:none}main{padding:64px 18px 80px}.topbar{display:flex;position:fixed;top:0;left:0;right:0;height:48px;align-items:center;gap:12px;padding:0 14px;background:var(--panel);border-bottom:1px solid var(--line);z-index:10}.topbar button{border:1px solid var(--line);background:var(--bg);color:var(--fg);border-radius:6px;padding:6px 10px}}
@media print{nav,.topbar{display:none}.layout{display:block}main{max-width:none;padding:0}}
"""

JS = """
(function(){
  const nav=document.querySelector('nav'), toc=document.getElementById('toc'), q=document.getElementById('q'), hits=document.getElementById('hits');
  const main=document.querySelector('main');
  const heads=[...main.querySelectorAll('h1,h2,h3')];
  document.documentElement.classList.add('js-enabled');
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
  const btn=document.getElementById('menu'), mobile=matchMedia('(max-width:900px)');
  function menu(open,restore=true){
    nav.classList.toggle('open',open); btn.setAttribute('aria-expanded',String(open));
    nav.inert=mobile.matches&&!open;
    if(open) q.focus(); else if(restore) btn.focus();
  }
  btn.addEventListener('click',()=>menu(!nav.classList.contains('open')));
  toc.addEventListener('click',e=>{if(e.target.closest('a')&&mobile.matches) menu(false);});
  document.addEventListener('keydown',e=>{
    if(e.key==='Escape'&&nav.classList.contains('open')) menu(false);
    if(e.key==='Tab'&&mobile.matches&&nav.classList.contains('open')){
      const focusable=[...nav.querySelectorAll('a,input,button')], first=focusable[0], last=focusable.at(-1);
      if(e.shiftKey&&document.activeElement===first){e.preventDefault();last.focus();}
      else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first.focus();}
    }
  });
  mobile.addEventListener('change',()=>menu(false,false)); menu(false,false);
})();
"""


class SafeReportHTML(HTMLParser):
    """Small formatting allowlist; no active HTML, inline handlers or URL-based script sinks."""
    allowed = {"p", "h1", "h2", "h3", "h4", "h5", "h6", "a", "em", "strong", "code", "pre",
               "ul", "ol", "li", "blockquote", "table", "thead", "tbody", "tr", "th", "td", "hr", "br", "del"}
    void = {"br", "hr"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.output, self.stack, self.headings = [], [], []
        self.heading = None

    def handle_starttag(self, tag, attrs):
        if tag not in self.allowed:
            return
        safe = []
        if tag in {"h1", "h2", "h3"}:
            ident = f"s{len(self.headings)}"
            self.heading = [tag, ident, ""]
            self.headings.append(self.heading)
            safe.append(("id", ident))
        if tag == "a":
            for key, val in attrs:
                if key == "href" and val and not any(ord(c) < 32 for c in val):
                    url = urlsplit(val.strip())
                    if url.scheme in {"https", "http"} or (not url.scheme and not url.netloc and val.startswith("#")):
                        safe.extend([("href", val), ("rel", "noopener noreferrer")])
        self.output.append("<" + tag + "".join(f' {k}="{html.escape(v, quote=True)}"' for k, v in safe) + ">")
        if tag not in self.void:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag in self.stack:
            while self.stack:
                closed = self.stack.pop()
                self.output.append(f"</{closed}>")
                if closed == tag:
                    break
        if self.heading and tag == self.heading[0]:
            self.heading = None

    def handle_data(self, data):
        if self.heading:
            self.heading[2] += data
        if any(t in self.stack for t in {"code", "pre", "a"}):
            self.output.append(html.escape(data))
            return
        last = 0
        for match in re.finditer(r"https?://[^\s<>\"'｜|]+", data):
            self.output.append(html.escape(data[last:match.start()]))
            url = html.escape(match.group(), quote=True)
            self.output.append(f'<a href="{url}" rel="noopener noreferrer">{url}</a>')
            last = match.end()
        self.output.append(html.escape(data[last:]))


def safe_body(md_text: str) -> tuple[str, str]:
    parser = SafeReportHTML()
    parser.feed(markdown.markdown(md_text, extensions=["tables", "fenced_code", "sane_lists"], output_format="html5"))
    toc = "".join(f'<li class="{tag}"><a href="#{ident}">{html.escape(title)}</a></li>'
                  for tag, ident, title in parser.headings)
    return "".join(parser.output), toc


def csp_hash(text: str) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(text.encode()).digest()).decode()


def build() -> Path:
    md_text = SRC.read_text(encoding="utf-8")
    md_text = re.sub(r"^---\ntitle:.*?\n---\n", "", md_text, count=1, flags=re.S)
    body, toc = safe_body(md_text)
    body = body.replace("<table>", '<div class="tablewrap"><table>').replace("</table>", "</table></div>")
    # evidence markers 【級別｜來源】 become small chips; the grade drives the colour token
    def chip(m: re.Match) -> str:
        grade, rest = m.group(1), m.group(2)
        cls = {"已證實": "ev-a", "廠商主張": "ev-v", "第三方評論": "ev-t", "尚未證實": "ev-u"}[grade]
        return f'<span class="ev {cls}" title="證據級別：{grade}">{grade}<span class="ev-src">{html.escape(rest)}</span></span>'
    body = re.sub(r"【(已證實|廠商主張|第三方評論|尚未證實)((?:[^】])*)】", chip, body)
    title = "多模型多代理資安審查"
    csp = (f"default-src 'none'; script-src '{csp_hash(JS)}'; style-src '{csp_hash(CSS)}'; "
           "base-uri 'none'; form-action 'none'; object-src 'none'; require-trusted-types-for 'script'")
    page = f"""<!DOCTYPE html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{csp}">
<title>{html.escape(title)}</title>
<style>{CSS}</style>
</head>
<body>
<div class="topbar"><button id="menu" aria-label="開啟目次" aria-expanded="false" aria-controls="navigation">☰ 目次</button><span class="meta">GSMD-RPT-2026-0908-01</span></div>
<div class="layout">
<nav id="navigation" aria-label="目次"><p class="brand">GSMD-RPT-2026-0908-01 · v0.1.0 · 2026-09-08</p><input id="q" type="search" placeholder="搜尋全文（至少 2 字）" aria-label="搜尋"><div id="hits" class="hits" aria-live="polite"></div><ol id="toc">{toc}</ol></nav>
<main>{body}</main>
</div>
<script>{JS}</script>
</body>
</html>
"""
    OUT.write_text(page, encoding="utf-8")
    return OUT


if __name__ == "__main__":
    p = build()
    print(f"wrote {p} ({p.stat().st_size:,} bytes)")

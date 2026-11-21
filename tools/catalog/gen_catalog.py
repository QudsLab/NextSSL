#!/usr/bin/env python3
"""Generate docs/catalog.html: one page listing every NextSSL algorithm (registered and parked).

Inputs (all read-only):
  docs/algo.generated.json              registry metadata written by `cargo xtask gen`
  algos/**/kat/*.json                   counts of published vectors per algorithm
  algos/**/build.rs, upstream/ORIGIN.md implementation language and port origin
  algos_parked/**/PARKED.md + folder    collected algorithms that do not build or pass yet

Output: docs/catalog.html (the template below + the data as one JSON blob).
Run from anywhere:  python tools/catalog/gen_catalog.py
"""
import glob
import json
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(ROOT, "docs", "catalog.html")


def read(p):
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def kat_vectors(algo_dir, files):
    n = 0
    for f in files:
        try:
            doc = json.loads(read(os.path.join(algo_dir, f)) or "{}")
        except ValueError:
            continue
        v = doc.get("vectors")
        if isinstance(v, list):
            n += len(v)
    return n


def language(algo_dir, up):
    if up.get("crate"):
        return "Rust"
    if os.path.isdir(os.path.join(algo_dir, "upstream", "port")):
        return "C (port)"
    b = read(os.path.join(algo_dir, "build.rs"))
    if "cpp(true)" in b and "CPP_SOURCES: &[&str] = &[]" not in b:
        return "C++"
    if os.path.exists(os.path.join(algo_dir, "upstream", "Cargo.toml")):
        return "Rust (vendored)"
    return "C"


def source_of(up):
    """Short human label of where the code was gathered from."""
    if up.get("crate"):
        return "crates.io: %s %s" % (up["crate"], up.get("version", ""))
    if up.get("repo"):
        r = re.sub(r"^https?://(www\.)?", "", up["repo"]).rstrip("/")
        return r
    u = up.get("url", "")
    m = re.search(r"supercop-(\d+)", u)
    if m:
        return "SUPERCOP " + m.group(1)
    return re.sub(r"^https?://(www\.)?", "", u)[:80]


def pinned(up):
    return bool((up.get("crate") and up.get("version")) or (up.get("repo") and up.get("commit"))
                or (up.get("url") and up.get("sha256")))


def entry(a, algo_dir, status, reason=""):
    up = a.get("upstream", {}) or {}
    kat_files = (a.get("kat") or {}).get("files", [])
    nvec = kat_vectors(algo_dir, kat_files) if os.path.isdir(algo_dir) else 0
    lic = up.get("license", "")
    ev = []
    if pinned(up):
        ev.append("source-pinned")
    if lic and lic != "NOASSERTION":
        ev.append("license-known")
    if status == "registered":
        ev.append("builds")
        ev.append("roundtrip")
    if nvec and status == "registered":
        ev.append("kat")
    plat = "all"
    if a.get("exclude_targets"):
        plat = "not " + "/".join(a["exclude_targets"])
    return {
        "i": a.get("id", ""), "k": a.get("kind", ""), "c": a.get("category", ""), "f": a.get("family", ""),
        "al": a.get("aliases", []), "t": a.get("tier", ""), "st": status, "sd": a.get("standards", []),
        "lic": lic, "cl": bool(a.get("copyleft")), "lang": language(algo_dir, up), "src": source_of(up),
        "up": {k: v for k, v in up.items() if k != "files"}, "nf": len(up.get("files", [])),
        "sz": a.get("sizes", {}), "kv": nvec, "kf": kat_files, "ev": ev, "pl": plat,
        "xr": a.get("exclude_reason", ""), "why": reason, "dir": a.get("dir", ""),
        "pr": sorted((a.get("params") or {}).keys()),
    }


def load_toml_light(text):
    """Enough of algo.toml for parked folders (no toml dependency): id/kind/category/family/tier/upstream."""
    def s(key):
        m = re.search(r'(?m)^%s\s*=\s*"([^"]*)"' % key, text)
        return m.group(1) if m else ""
    up = {}
    m = re.search(r"(?m)^upstream\s*=\s*\{(.*)\}\s*$", text)
    if m:
        for k in ("crate", "version", "repo", "commit", "url", "sha256", "license"):
            mm = re.search(r'\b%s\s*=\s*"([^"]*)"' % k, m.group(1))
            if mm:
                up[k] = mm.group(1)
    kat = re.findall(r'"(kat/[^"]+)"', text)
    return {"id": s("id"), "kind": s("kind"), "category": s("category"), "family": s("family"),
            "tier": s("tier"), "upstream": up, "kat": {"files": kat}, "copyleft": "copyleft  = true" in text
            or "copyleft = true" in text}


def main():
    meta = json.loads(read(os.path.join(ROOT, "docs", "algo.generated.json")))
    rows = []
    seen = set()
    for a in meta["algorithms"]:
        d = os.path.join(ROOT, "algos", a["dir"])
        rows.append(entry(a, d, "registered"))
        seen.add(a["id"])
    for pm in glob.glob(os.path.join(ROOT, "algos_parked", "*", "*", "PARKED.md")):
        pdir = os.path.dirname(pm)
        text = read(pm)
        reason = ""
        for line in text.splitlines()[1:]:
            line = line.strip()
            if line and not line.startswith("#"):
                reason = (reason + " " + line).strip()
        reason = reason[:400]
        tomls = glob.glob(os.path.join(pdir, "*", "algo.toml"))
        if tomls:
            a = load_toml_light(read(tomls[0]))
            d = os.path.dirname(tomls[0])
        else:
            a = {"id": os.path.basename(pdir), "category": os.path.basename(os.path.dirname(pdir))}
            d = pdir
        if not a.get("id") or a["id"] in seen:
            continue
        seen.add(a["id"])
        a["dir"] = os.path.relpath(d, os.path.join(ROOT, "algos_parked")).replace(os.sep, "/")
        rows.append(entry(a, d, "parked", reason))
    rows.sort(key=lambda r: (r["c"], r["f"], r["i"]))
    data = json.dumps(rows, separators=(",", ":"), ensure_ascii=False)
    html = TEMPLATE.replace("/*DATA*/[]", data).replace("{{GENERATED_BY}}", meta.get("generated_by", ""))
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(html)
    reg = sum(1 for r in rows if r["st"] == "registered")
    print("wrote %s: %d algorithms (%d registered, %d parked)" % (os.path.relpath(OUT, ROOT), len(rows), reg,
                                                                  len(rows) - reg))


TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NextSSL Algorithm Catalog</title>
<!-- @generated by tools/catalog/gen_catalog.py. DO NOT EDIT. -->
<style>
:root{--bg:#fbfbfa;--fg:#1d1d1f;--mut:#6b6b70;--line:#e3e3e0;--card:#fff;--acc:#2f5bd3;--chip:#f0f0ee;
--ok:#1f7a3a;--warn:#9a6700;--bad:#b42318;--info:#2f5bd3}
@media (prefers-color-scheme:dark){:root{--bg:#141416;--fg:#ececee;--mut:#9a9aa2;--line:#2a2a2e;--card:#1b1b1e;
--acc:#7c9cff;--chip:#26262a;--ok:#4cc27a;--warn:#e0b04a;--bad:#ff7b72;--info:#7c9cff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
header{padding:20px 16px 8px;max-width:1400px;margin:auto}h1{margin:0 0 4px;font-size:22px}
.sub{color:var(--mut)}.stats{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:8px 12px;min-width:110px}
.stat b{display:block;font-size:20px}.stat span{color:var(--mut);font-size:12px}
.bar{position:sticky;top:0;z-index:5;background:var(--bg);border-bottom:1px solid var(--line)}
.filters{max-width:1400px;margin:auto;padding:10px 16px;display:flex;flex-wrap:wrap;gap:8px;align-items:center}
input,select{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:7px 9px;font:inherit}
input[type=search]{flex:1 1 220px}main{max-width:1400px;margin:auto;padding:8px 16px 40px}
.cat{margin:18px 0 6px;font-size:15px;color:var(--mut);text-transform:uppercase;letter-spacing:.04em}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;color:var(--mut);font-weight:600;cursor:pointer;user-select:none;white-space:nowrap}
tr.r{cursor:pointer}tr.r:hover td{background:var(--chip)}td.id{font-family:ui-monospace,Consolas,monospace;font-weight:600}
.chip{display:inline-block;background:var(--chip);border-radius:999px;padding:1px 8px;margin:1px 2px 1px 0;font-size:12px;white-space:nowrap}
.t-safe,.t-standard{color:var(--ok)}.t-legacy,.t-research{color:var(--warn)}.t-broken{color:var(--bad)}
.t-unverified,.t-provisional{color:var(--info)}.parked{color:var(--bad)}
.ev{font-size:11px}.hide-sm{}@media (max-width:760px){.hide-sm{display:none}}
dialog{border:1px solid var(--line);border-radius:12px;background:var(--card);color:var(--fg);max-width:760px;width:calc(100% - 32px);padding:0}
dialog::backdrop{background:rgba(0,0,0,.45)}.dh{display:flex;justify-content:space-between;align-items:center;padding:14px 16px;border-bottom:1px solid var(--line)}
.dh h2{margin:0;font-size:18px;font-family:ui-monospace,Consolas,monospace}.db{padding:12px 16px 18px}
.kv{display:grid;grid-template-columns:150px 1fr;gap:4px 12px}.kv div:nth-child(odd){color:var(--mut)}
.kv div{word-break:break-word}button{background:var(--chip);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:6px 10px;cursor:pointer}
a{color:var(--acc)}.muted{color:var(--mut)}.count{color:var(--mut);font-size:13px;margin-left:auto}
</style>
</head>
<body>
<header>
  <h1>NextSSL Algorithm Catalog</h1>
  <div class="sub">Every algorithm NextSSL has gathered: registered ones (built into the library) and parked ones (collected, not building or passing yet). Click a row for its source and evidence.</div>
  <div class="stats" id="stats"></div>
</header>
<div class="bar"><div class="filters">
  <input type="search" id="q" placeholder="Search id, family, alias, standard, source...">
  <select id="fk"><option value="">All kinds</option></select>
  <select id="ft"><option value="">All tiers</option></select>
  <select id="fs"><option value="">Registered + parked</option><option>registered</option><option>parked</option></select>
  <select id="fl"><option value="">All languages</option></select>
  <select id="fe"><option value="">Any evidence</option><option value="kat">Has KAT vectors</option><option value="nokat">No KAT vectors</option><option value="license-known">License known</option><option value="copyleft">Copyleft</option></select>
  <select id="fp"><option value="">All platforms</option><option value="all">All targets</option><option value="limited">Platform-limited</option></select>
  <select id="fg"><option value="c">Group by category</option><option value="k">Group by kind</option><option value="f">Group by family</option><option value="">No grouping</option></select>
  <span class="count" id="count"></span>
</div></div>
<main id="out"></main>
<dialog id="dlg"><div class="dh"><h2 id="dt"></h2><button onclick="dlg.close()">Close</button></div><div class="db" id="dbody"></div></dialog>
<script>
const D=/*DATA*/[];
const $=s=>document.querySelector(s);
const uniq=k=>[...new Set(D.map(r=>r[k]).filter(Boolean))].sort();
function fill(sel,vals){const e=$(sel);vals.forEach(v=>{const o=document.createElement('option');o.textContent=v;e.appendChild(o)})}
fill('#fk',uniq('k'));fill('#ft',uniq('t'));fill('#fl',uniq('lang'));
function esc(s){return String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
function stats(){
  const reg=D.filter(r=>r.st==='registered'),kat=reg.filter(r=>r.kv>0);
  const box=(n,l)=>`<div class="stat"><b>${n.toLocaleString()}</b><span>${l}</span></div>`;
  $('#stats').innerHTML=box(D.length,'algorithms gathered')+box(reg.length,'registered')+box(D.length-reg.length,'parked')+
   box(kat.length,'with published KAT vectors')+box(new Set(D.map(r=>r.f)).size,'families')+box(new Set(D.map(r=>r.k)).size,'kinds');
}
function link(up){
  if(up.repo)return `<a href="${esc(up.repo)}${up.commit?'/tree/'+esc(up.commit):''}" target="_blank" rel="noopener">${esc(up.repo)}</a>`;
  if(up.url)return `<a href="${esc(up.url)}" target="_blank" rel="noopener">${esc(up.url)}</a>`;
  if(up.crate)return `<a href="https://crates.io/crates/${esc(up.crate)}" target="_blank" rel="noopener">crates.io/${esc(up.crate)}</a>`;
  return '<span class="muted">none</span>';
}
function show(i){
  const r=D[i];$('#dt').textContent=r.i;const u=r.up||{};
  const row=(k,v)=>v===''||v==null||(Array.isArray(v)&&!v.length)?'':`<div>${k}</div><div>${v}</div>`;
  const sz=Object.entries(r.sz||{}).map(([k,v])=>`${k}=${typeof v==='object'?JSON.stringify(v):v}`).join(', ');
  $('#dbody').innerHTML=`<div class="kv">`+
   row('Status',r.st==='parked'?`<span class="parked">parked</span>`:'registered')+
   row('Why parked',esc(r.why))+row('Kind',esc(r.k))+row('Category / family',esc(r.c)+' / '+esc(r.f))+
   row('Tier',`<span class="t-${esc(r.t)}">${esc(r.t)}</span>`)+row('Aliases',esc(r.al.join(', ')))+
   row('Standards',esc(r.sd.join(', ')))+row('Language',esc(r.lang))+row('Source',link(u))+
   row('Pinned at',esc(u.commit||u.sha256||u.version||''))+row('License',esc(r.lic)+(r.cl?' (copyleft feature)':''))+
   row('Upstream files',r.nf?String(r.nf):'')+row('Sizes',esc(sz))+row('Parameters',esc(r.pr.join(', ')))+
   row('KAT vectors',r.kv?`${r.kv} in ${esc(r.kf.join(', '))}`:'<span class="muted">none yet</span>')+
   row('Evidence',r.ev.map(e=>`<span class="chip ev">${esc(e)}</span>`).join(''))+
   row('Platforms',esc(r.pl)+(r.xr?' — '+esc(r.xr):''))+row('Folder',esc((r.st==='parked'?'algos_parked/':'algos/')+r.dir))+`</div>`;
  $('#dlg').showModal();
}
let sortKey='i',sortDir=1;
function render(){
  const q=$('#q').value.toLowerCase().trim(),fk=$('#fk').value,ft=$('#ft').value,fs=$('#fs').value,fl=$('#fl').value,
        fe=$('#fe').value,fp=$('#fp').value,fg=$('#fg').value;
  let rows=D.map((r,i)=>[r,i]).filter(([r])=>(!fk||r.k===fk)&&(!ft||r.t===ft)&&(!fs||r.st===fs)&&(!fl||r.lang===fl)&&
    (!fe||(fe==='kat'?r.kv>0:fe==='nokat'?!r.kv:fe==='copyleft'?r.cl:r.ev.includes(fe)))&&
    (!fp||(fp==='all'?r.pl==='all':r.pl!=='all'))&&
    (!q||[r.i,r.f,r.c,r.k,r.src,r.lic,...r.al,...r.sd].join(' ').toLowerCase().includes(q)));
  rows.sort((a,b)=>{const x=a[0][sortKey],y=b[0][sortKey];return (typeof x==='number'?x-y:String(x).localeCompare(String(y)))*sortDir});
  $('#count').textContent=`${rows.length.toLocaleString()} of ${D.length.toLocaleString()}`;
  const groups=new Map();rows.forEach(x=>{const g=fg?x[0][fg]:'';if(!groups.has(g))groups.set(g,[]);groups.get(g).push(x)});
  const head=`<tr><th data-k="i">Algorithm</th><th data-k="k">Kind</th><th data-k="t">Tier</th><th data-k="lang" class="hide-sm">Language</th>`+
    `<th data-k="src" class="hide-sm">Source</th><th data-k="kv">KAT</th><th data-k="st">Status</th></tr>`;
  let h='';const keys=[...groups.keys()].sort();
  for(const g of keys){const list=groups.get(g);
    if(fg)h+=`<div class="cat">${esc(g)} <span class="muted">(${list.length})</span></div>`;
    h+=`<table>${head}`+list.slice(0,fg?100000:3000).map(([r,i])=>`<tr class="r" data-i="${i}"><td class="id">${esc(r.i)}</td><td>${esc(r.k)}</td>`+
      `<td class="t-${esc(r.t)}">${esc(r.t)}</td><td class="hide-sm">${esc(r.lang)}</td><td class="hide-sm">${esc(r.src)}</td>`+
      `<td>${r.kv||'<span class="muted">-</span>'}</td><td>${r.st==='parked'?'<span class="parked">parked</span>':'registered'}</td></tr>`).join('')+`</table>`;}
  $('#out').innerHTML=h||'<p class="muted">No algorithm matches.</p>';
}
document.addEventListener('click',e=>{const tr=e.target.closest('tr.r');if(tr)show(+tr.dataset.i);
  const th=e.target.closest('th[data-k]');if(th){const k=th.dataset.k;sortDir=sortKey===k?-sortDir:1;sortKey=k;render()}});
['#q','#fk','#ft','#fs','#fl','#fe','#fp','#fg'].forEach(s=>$(s).addEventListener('input',render));
stats();render();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    sys.exit(main())

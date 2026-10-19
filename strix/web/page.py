"""The single-page dashboard (HTML/CSS/JS) served by the web triage server."""

PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Strix triage console</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--panel2:#1c2330;--line:#30363d;--fg:#e6edf3;
--muted:#8b949e;--crit:#f85149;--high:#ff7b72;--med:#e3b341;--low:#58a6ff;--info:#6e7681;--clean:#3fb950;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
header{display:flex;align-items:center;gap:12px;padding:16px 22px;border-bottom:1px solid var(--line)}
header .logo{font-size:26px} h1{font-size:18px;margin:0}
header small{color:var(--muted)}
.wrap{display:grid;grid-template-columns:340px 1fr;gap:0;min-height:calc(100vh - 62px)}
@media(max-width:860px){.wrap{grid-template-columns:1fr}}
aside{border-right:1px solid var(--line);padding:18px;overflow:auto}
main{padding:22px;overflow:auto}
.drop{border:2px dashed var(--line);border-radius:14px;padding:30px 16px;text-align:center;
color:var(--muted);cursor:pointer;transition:.15s}
.drop.hot{border-color:var(--low);background:#132032;color:var(--fg)}
.drop b{color:var(--fg)}
h2{font-size:12px;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin:22px 0 8px}
.corpus{font-size:12.5px}
.crow{display:flex;justify-content:space-between;gap:8px;padding:6px 8px;border:1px solid var(--line);
border-radius:7px;margin:5px 0;cursor:pointer;background:var(--panel)}
.crow:hover{border-color:var(--low)}
.crow .v{font-weight:700}
.pill{font-size:10px;padding:1px 7px;border-radius:999px;font-weight:700}
.pill.clean{background:var(--clean);color:#000}.pill.low-risk{background:var(--low);color:#000}
.pill.suspicious{background:var(--med);color:#000}.pill.likely-malicious{background:var(--high);color:#000}
.pill.malicious{background:var(--crit);color:#000}
.empty{color:var(--muted);text-align:center;margin-top:16vh}
.head{display:grid;grid-template-columns:150px 1fr;gap:18px;align-items:center;margin-bottom:18px}
.ring{position:relative;width:140px;height:140px}
.ring svg{transform:rotate(-90deg)} .ring .v{position:absolute;inset:0;display:flex;flex-direction:column;
align-items:center;justify-content:center} .ring .v b{font-size:32px} .ring .v span{color:var(--muted);font-size:11px}
.facts dl{display:grid;grid-template-columns:90px 1fr;gap:3px 10px;margin:0;font-size:12.5px}
.facts dt{color:var(--muted)} .facts dd{margin:0;font-family:ui-monospace,Menlo,monospace;word-break:break-all}
.badge{display:inline-block;padding:4px 12px;border-radius:999px;font-weight:800;letter-spacing:.4px}
.sec{margin:18px 0}
.cat{font-size:12px;text-transform:uppercase;letter-spacing:1px;color:var(--low);margin:14px 0 6px}
.f{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--info);
border-radius:8px;padding:10px 12px;margin:7px 0}
.f.crit{border-left-color:var(--crit)}.f.high{border-left-color:var(--high)}
.f.med{border-left-color:var(--med)}.f.low{border-left-color:var(--low)}
.f .t{font-weight:600}
.sev{font-size:10px;font-weight:800;padding:2px 6px;border-radius:4px;margin-right:8px}
.sev.crit{background:var(--crit);color:#000}.sev.high{background:var(--high);color:#000}
.sev.med{background:var(--med);color:#000}.sev.low{background:var(--low);color:#000}.sev.info{background:var(--info);color:#000}
.ev{margin:5px 0 0;padding-left:16px;color:#adbac7;font-family:ui-monospace,Menlo,monospace;font-size:11.5px}
.ev li{word-break:break-all}
.att{display:inline-block;background:var(--panel2);border:1px solid var(--line);color:var(--low);
text-decoration:none;font-size:11px;padding:2px 8px;border-radius:6px;margin:3px 3px 0 0}
.decoded{background:#132032;border:1px solid #1f6feb;border-radius:8px;padding:10px 12px;margin:7px 0}
.decoded code{color:#79c0ff;word-break:break-all}
.spin{display:inline-block;width:18px;height:18px;border:3px solid var(--line);border-top-color:var(--low);
border-radius:50%;animation:spin .8s linear infinite;vertical-align:middle}
@keyframes spin{to{transform:rotate(360deg)}}
.cluster{border:1px solid var(--line);border-radius:8px;padding:8px 10px;margin:6px 0;background:var(--panel);font-size:12px}
</style></head>
<body>
<header><div class="logo">🦉</div><div><h1>Strix triage console</h1>
<small>static analysis only — samples are never executed</small></div></header>
<div class="wrap">
  <aside>
    <div class="drop" id="drop"><b>Drop a file</b><br>or click to choose<br><br>
      <span style="font-size:12px">it is analysed locally, in-process</span>
      <input type="file" id="file" style="display:none"></div>
    <label style="display:block;margin-top:10px;font-size:12px;color:var(--muted)">
      <input type="checkbox" id="save" checked> save to corpus</label>
    <h2>Corpus <span id="cstats" style="float:right;font-weight:400"></span></h2>
    <div class="corpus" id="corpus"></div>
    <h2>Clusters</h2>
    <div id="clusters" class="corpus"></div>
  </aside>
  <main id="main"><div class="empty">Drop a sample to begin triage.</div></main>
</div>
<script>
const $ = s => document.querySelector(s);
const drop = $('#drop'), fileIn = $('#file'), main = $('#main');
drop.onclick = () => fileIn.click();
fileIn.onchange = e => { if (e.target.files[0]) scan(e.target.files[0]); };
;['dragover','dragenter'].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.add('hot')}));
;['dragleave','drop'].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.remove('hot')}));
drop.addEventListener('drop', e => { const f = e.dataTransfer.files[0]; if (f) scan(f); });

async function scan(file){
  main.innerHTML = '<div class="empty"><span class="spin"></span><br><br>analysing '+esc(file.name)+' …</div>';
  const buf = await file.arrayBuffer();
  const r = await fetch('/api/scan?save='+($('#save').checked?1:0), {
    method:'POST', headers:{'X-Filename': encodeURIComponent(file.name)}, body: buf});
  const rep = await r.json();
  render(rep); loadCorpus();
}
function esc(s){return (s+'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
const SEVC = {critical:'crit',high:'high',medium:'med',low:'low',info:'info'};
function render(rep){
  const f = rep.file, dash = (rep.score*3.33).toFixed(1)+' 333';
  const vclass = rep.verdict;
  let h = `<div class="head">
    <div class="ring"><svg width="140" height="140" viewBox="0 0 120 120">
      <circle cx="60" cy="60" r="53" fill="none" stroke="#30363d" stroke-width="10"/>
      <circle cx="60" cy="60" r="53" fill="none" stroke="${scoreColor(rep.score)}" stroke-width="10"
        stroke-linecap="round" stroke-dasharray="${dash}"/></svg>
      <div class="v"><b>${rep.score}</b><span>/100</span></div></div>
    <div class="facts"><div class="badge pill ${vclass}">${rep.verdict.toUpperCase()}</div>
      <dl style="margin-top:10px">
        <dt>file</dt><dd>${esc(f.path.split('/').pop())}</dd>
        <dt>type</dt><dd>${esc(f.file_type)} · ${esc(f.arch||'')}</dd>
        <dt>size</dt><dd>${f.size.toLocaleString()} B · entropy ${f.entropy}</dd>
        <dt>sha256</dt><dd>${esc(f.hashes.sha256||'')}</dd>
        <dt>imphash</dt><dd>${esc(f.hashes.imphash||'—')}</dd>
      </dl></div></div>`;

  const dec = rep.sections.decoded_strings||[];
  if(dec.length){ h += `<div class="sec"><div class="cat">🔓 Emulation-recovered strings (${dec.length})</div>`;
    dec.slice(0,30).forEach(d=> h+=`<div class="decoded"><code>${esc(d.value)}</code>
      <span style="color:var(--muted);font-size:11px"> @${d.address} via ${d.via}</span></div>`);
    h += `</div>`; }

  const by = {};
  (rep.findings||[]).forEach(fd=>{(by[fd.category]=by[fd.category]||[]).push(fd)});
  h += '<div class="sec">';
  for(const cat in by){ h += `<div class="cat">${esc(cat)}</div>`;
    by[cat].forEach(fd=>{ const c=SEVC[fd.severity]||'info';
      h += `<div class="f ${c}"><span class="sev ${c}">${fd.severity.toUpperCase()}</span>
        <span class="t">${esc(fd.title)}</span>`;
      if(fd.attack&&fd.attack.length) h+=`<div style="margin-top:5px">`+fd.attack.map(t=>
        `<a class="att" target="_blank" href="https://attack.mitre.org/techniques/${esc(t.replace('.','/'))}/">${esc(t)}</a>`).join('')+`</div>`;
      if(fd.evidence&&fd.evidence.length) h+=`<ul class="ev">`+fd.evidence.slice(0,6).map(e=>`<li>${esc(e)}</li>`).join('')+`</ul>`;
      h += `</div>`; });
  }
  h += '</div>';
  if(rep.attack_techniques&&rep.attack_techniques.length){
    h += `<div class="sec"><div class="cat">ATT&CK techniques</div>`+
      rep.attack_techniques.map(t=>`<a class="att" target="_blank" href="https://attack.mitre.org/techniques/${esc(t.replace('.','/'))}/">${esc(t)}</a>`).join('')+`</div>`;
  }
  main.innerHTML = h;
}
function scoreColor(s){return s<25?'#3fb950':s<55?'#e3b341':s<80?'#ff7b72':'#f85149';}
async function loadCorpus(){
  const r = await (await fetch('/api/corpus')).json();
  $('#cstats').textContent = r.stats.total+' samples';
  $('#corpus').innerHTML = (r.samples||[]).slice(0,40).map(s=>
    `<div class="crow"><span class="v">${esc((s.path||'').split('/').pop()||s.sha256.slice(0,12))}</span>
      <span><span class="pill ${s.verdict}">${s.score}</span></span></div>`).join('') || '<span class="empty" style="margin:0;color:var(--muted)">empty</span>';
  const cl = await (await fetch('/api/clusters')).json();
  $('#clusters').innerHTML = (cl.clusters||[]).map((g,i)=>
    `<div class="cluster"><b>cluster ${i+1}</b> · ${g.length} samples<br>`+
    g.map(x=>esc((x.path||x.sha256).split('/').pop())).join(', ')+`</div>`).join('')
    || '<span style="color:var(--muted);font-size:12px">no clusters yet</span>';
}
loadCorpus();
</script>
</body></html>"""

const $ = (s, el = document) => el.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let token = sessionStorage.getItem('t'), user = JSON.parse(sessionStorage.getItem('u') || 'null');
let state = {projects: [], pid: null, project: null, report: null, sel: null, all: false};

function toast(msg) { const t = $('#toast'); t.textContent = msg; t.style.display = 'block'; clearTimeout(t._h); t._h = setTimeout(() => t.style.display = 'none', 4500); }

async function api(path, opts = {}) {
  opts.headers = {...(opts.headers || {}), ...(token ? {Authorization: 'Bearer ' + token} : {})};
  const r = await fetch('/api' + path, opts);
  if (r.status === 401 && token) { logout(); throw new Error('Session expired'); }
  const data = r.status === 204 ? null : await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'Request failed (' + r.status + ')');
  return data;
}
const guard = fn => async (...a) => { try { await fn(...a); } catch (e) { toast(e.message); } };
function logout() { sessionStorage.clear(); token = user = null; render(); }

function render() {
  $('#who').innerHTML = user ? `${esc(user.username)} · <b>${esc(user.role)}</b> <button class="ghost" id="out">Sign out</button>` : '';
  if (user) $('#out').onclick = logout;
  user ? shell() : authView();
}

function authView() {
  $('#app').innerHTML = `<div class="panel" style="max-width:420px;margin:40px auto"><h2>Sign in</h2>
  <form id="f" class="row" style="flex-direction:column;align-items:stretch">
   <input id="u" placeholder="Username" autocomplete="username" required>
   <input id="p" type="password" placeholder="Password (8+ characters)" autocomplete="current-password" required>
   <select id="r"><option value="developer">Developer</option><option value="auditor">Security auditor</option></select>
   <input id="inv" placeholder="Auditor invite code" hidden>
   <div class="row"><button type="submit">Sign in</button><button type="button" class="ghost" id="reg">Create account</button></div></form></div>`;
  $('#r').onchange = e => $('#inv').hidden = e.target.value !== 'auditor';
  const login = guard(async () => {
    const body = new URLSearchParams({username: $('#u').value, password: $('#p').value});
    const d = await api('/auth/login', {method: 'POST', body});
    token = d.access_token; user = {username: d.username, role: d.role};
    sessionStorage.setItem('t', token); sessionStorage.setItem('u', JSON.stringify(user)); await loadProjects(); render();
  });
  $('#f').onsubmit = e => { e.preventDefault(); login(); };
  $('#reg').onclick = guard(async () => {
    await api('/auth/register', {method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username: $('#u').value, password: $('#p').value, role: $('#r').value, invite_code: $('#inv').value || null})});
    toast('Account created'); await login();
  });
}

async function loadProjects() { state.projects = await api('/projects'); }

function shell() {
  const dev = user.role === 'developer';
  $('#app').innerHTML = `<div class="grid"><aside><div class="panel"><h2>Projects</h2><div id="plist"></div>
   ${dev ? `<div class="row" style="margin-top:10px"><input id="pn" placeholder="New project name" style="flex:1"><button id="pc">Add</button></div>
   <p><button class="ghost" id="demo" style="width:100%">Load demo project</button></p>` : '<p class="hint">Auditors can read every project and report.</p>'}
  </div></aside><section id="main"><div class="panel hint">Pick a project, or load the demo to see a vulnerable package spread through its dependents.</div></section></div>`;
  drawList();
  if (dev) {
    $('#pc').onclick = guard(async () => { const n = $('#pn').value.trim(); if (!n) return;
      const p = await api('/projects', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({name: n})});
      await loadProjects(); openProject(p.id); });
    $('#demo').onclick = guard(async () => { const p = await api('/projects/demo', {method: 'POST'}); await loadProjects(); await openProject(p.id); await doScan(); });
  }
  if (state.pid) openProject(state.pid);
}

function drawList() {
  $('#plist').innerHTML = state.projects.map(p => `<button class="proj ${p.id === state.pid ? 'on' : ''}" data-id="${p.id}">${esc(p.name)}
    <small>${esc(p.owner)} · ${p.risk_score == null ? 'not scanned' : 'risk ' + p.risk_score}</small></button>`).join('') || '<p class="hint">No projects yet.</p>';
  document.querySelectorAll('.proj').forEach(b => b.onclick = guard(() => openProject(+b.dataset.id)));
}

async function openProject(id) {
  state.pid = id; state.report = null;
  state.project = await api('/projects/' + id);
  drawList(); drawProject();
  const done = state.project.scans.find(s => s.status === 'done');
  if (done) await loadReport(done.id);
}

function drawProject() {
  const p = state.project, dev = user.role === 'developer';
  $('#main').innerHTML = `<div class="panel"><h2>${esc(p.name)}</h2>
   ${dev ? `<div class="row"><input type="file" id="file" accept=".json,application/json"><button id="up" class="ghost">Upload SBOM</button>
   <button id="scan">Scan project</button></div><p class="hint">CycloneDX JSON, up to 2 MB. Latest upload is scanned.</p>` : ''}
   <p class="hint">${p.manifests.length} manifest(s) · ${p.scans.length} scan(s)
   ${p.scans.length ? ' · history: ' + p.scans.slice(0, 6).map(s => `<a href="#" data-s="${s.id}">#${s.id}</a>`).join(' ') : ''}</p></div><div id="rep"></div>`;
  document.querySelectorAll('[data-s]').forEach(a => a.onclick = guard(async e => { e.preventDefault(); await loadReport(+a.dataset.s); }));
  if (dev) {
    $('#up').onclick = guard(async () => { const f = $('#file').files[0]; if (!f) return toast('Choose a .json file first');
      const fd = new FormData(); fd.append('file', f);
      const d = await api(`/projects/${p.id}/manifest`, {method: 'POST', body: fd});
      toast(d.new ? `Uploaded ${d.components} components` : 'Identical manifest already stored'); await openProject(p.id); });
    $('#scan').onclick = guard(doScan);
  }
}

async function doScan() {
  const b = $('#scan'); if (b) b.disabled = true;
  try { const d = await api(`/projects/${state.pid}/scan`, {method: 'POST'});
    await loadProjects(); state.project = await api('/projects/' + state.pid); drawList(); drawProject(); await loadReport(d.scan_id);
  } finally { if ($('#scan')) $('#scan').disabled = false; }
}

async function loadReport(id) {
  state.report = await api(`/scans/${id}/report`);
  state.sel = state.report.vulnerable[0]?.ref || null; state.all = false;
  drawReport();
}

const sevPill = s => `<span class="pill ${esc(s)}">${esc(s)}</span>`;

function drawReport() {
  const r = state.report, s = r.summary, names = {};
  r.graph.nodes.forEach(n => names[n.id] = n.label + (n.version ? '@' + n.version : ''));
  const nm = ref => esc(names[ref] || ref);
  $('#rep').innerHTML = `
  <div class="panel"><div class="stats"><div><span>Risk score (0–100)</span><b class="score">${s.risk_score}</b></div>
   <div><span>Packages</span><b>${s.packages}</b></div><div><span>Max depth</span><b>${s.max_depth}</b></div>
   <div><span>Vulnerable packages</span><b>${s.vulnerable_packages}</b></div>
   <div><span>Dependency cycles</span><b>${s.cycles}</b></div>
   <div>${Object.entries(s.severity).filter(([, n]) => n).map(([k, n]) => `${sevPill(k)} ${n}`).join(' ') || 'No findings'}</div>
   <div><span>Source</span><b>${esc(r.meta.source)}</b></div></div></div>
  <div class="panel"><h2>Blast radius</h2><div class="row"><label for="vs">Vulnerable package</label>
   <select id="vs">${r.vulnerable.map(v => `<option value="${esc(v.ref)}" ${v.ref === state.sel ? 'selected' : ''}>${nm(v.ref)} — affects ${v.blast_radius}</option>`).join('')}</select>
   <button class="ghost" id="tg">${state.all ? 'Focus view' : 'Whole graph'}</button></div>
   <p class="hint" id="blurb"></p><div class="scroll"><svg id="graph" role="img" aria-label="Dependency graph"></svg></div>
   <p class="hint">Red = vulnerable · orange = depends on it · dashed teal = part of a cycle · red line = shortest path from your app.</p></div>
  <div class="panel"><h2>Investigate these first</h2>
   <p class="hint">Smallest set of direct dependencies that, once upgraded, covers every reachable vulnerable package (greedy weighted set cover).</p>
   ${r.fix_first.length ? '<ol>' + r.fix_first.map(f => `<li><b class="mono">${nm(f.ref)}</b> covers ${f.covers.map(nm).join(', ')}</li>`).join('') + '</ol>' : '<p>Nothing to fix.</p>'}</div>
  <div class="panel"><h2>Most critical dependency paths</h2>
   ${r.top_paths.map(p => `<div class="path mono">${p.path.map(nm).join(' → ')} <span class="hint">· ${p.hops} hops · score ${p.score}</span></div>`).join('') || '<p>No vulnerable paths.</p>'}</div>
  <div class="panel"><h2>Findings</h2><div class="scroll"><table><tr><th>Package</th><th>Advisory</th><th>Severity</th><th>CVSS</th><th>Fixed in</th><th>Affects</th></tr>
   ${r.vulnerable.flatMap(v => v.vulns.map(x => `<tr><td class="mono">${nm(v.ref)}</td><td><b>${esc(x.id)}</b><br>${esc(x.summary)}</td>
   <td>${sevPill(x.severity)}</td><td>${x.cvss}</td><td class="mono">${esc(x.fixed.join(', ') || '—')}</td><td>${v.blast_radius} pkgs</td></tr>`)).join('')}</table></div></div>
  ${r.cycles.length ? `<div class="panel"><h2>Circular dependencies</h2>${r.cycles.map(c => `<div class="mono">${c.map(esc).join(' ⇄ ')}</div>`).join('')}</div>` : ''}`;
  $('#vs').onchange = e => { state.sel = e.target.value; drawGraph(); };
  $('#tg').onclick = () => { state.all = !state.all; $('#tg').textContent = state.all ? 'Focus view' : 'Whole graph'; drawGraph(); };
  drawGraph();
}

function drawGraph() {
  const r = state.report, G = r.graph, svg = $('#graph'), NS = 'http://www.w3.org/2000/svg';
  const item = r.vulnerable.find(v => v.ref === state.sel);
  const aff = new Set(item ? item.dependents : []);
  $('#blurb').textContent = item ? `${names0(item)} is used by ${item.blast_radius} package(s), ${item.depth ?? '?'} hop(s) from your app. Fixing it protects everything in orange.` : '';
  let nodes = G.nodes.filter(n => n.depth != null);
  if (!state.all && item) nodes = nodes.filter(n => n.id === G.root || n.id === item.ref || aff.has(n.id));
  const ids = new Set(nodes.map(n => n.id)), cols = {};
  nodes.forEach(n => (cols[n.depth] = cols[n.depth] || []).push(n));
  const pos = {}, W = 190, H = 34, maxRows = Math.max(...Object.values(cols).map(c => c.length));
  Object.entries(cols).forEach(([d, list]) => list.forEach((n, i) => pos[n.id] = {x: 20 + d * (W + 50), y: 20 + i * (H + 12) + (maxRows - list.length) * (H + 12) / 2}));
  const w = 40 + (Math.max(...Object.keys(cols).map(Number)) + 1) * (W + 50), h = 40 + maxRows * (H + 12);
  svg.setAttribute('viewBox', `0 0 ${w} ${h}`); svg.setAttribute('width', Math.max(w, 600)); svg.innerHTML = '';
  const hot = new Set(); const sp = item ? item.shortest_path : [];
  for (let i = 0; i < sp.length - 1; i++) hot.add(sp[i] + '>' + sp[i + 1]);
  const el = (t, a, p) => { const e = document.createElementNS(NS, t); for (const k in a) e.setAttribute(k, a[k]); (p || svg).appendChild(e); return e; };
  G.edges.filter(([a, b]) => ids.has(a) && ids.has(b)).sort((a, b) => hot.has(a.join('>')) - hot.has(b.join('>'))).forEach(([a, b]) => {
    const A = pos[a], B = pos[b], x1 = A.x + W, y1 = A.y + H / 2, x2 = B.x, y2 = B.y + H / 2, m = (x1 + x2) / 2;
    el('path', {d: `M${x1},${y1} C${m},${y1} ${m},${y2} ${x2},${y2}`, class: 'e' + (hot.has(a + '>' + b) ? ' hot' : '')});
  });
  nodes.forEach(n => {
    const cls = ['n', n.id === G.root ? 'root' : '', item && n.id === item.ref ? 'target' : '', aff.has(n.id) ? 'affected' : '', n.cycle ? 'cycle' : '', !item && n.sev ? 'affected' : ''].join(' ');
    const g = el('g', {class: cls, transform: `translate(${pos[n.id].x},${pos[n.id].y})`});
    el('rect', {width: W, height: H, rx: 4}, g);
    const t = el('text', {x: 8, y: 21}, g); const label = n.label + (n.version ? ' ' + n.version : '');
    t.textContent = label.length > 25 ? label.slice(0, 24) + '…' : label;
    const tt = el('title', {}, g); tt.textContent = label + (n.sev ? ` — ${n.sev} (CVSS ${n.cvss})` : '');
  });
}
const names0 = v => v.name.split(':').pop() + '@' + v.version;

render();
if (user) loadProjects().then(render).catch(() => logout());

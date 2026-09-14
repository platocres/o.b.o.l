/* O.B.O.L web surface — single-page controller.
   One engagement library, many targets, one shared store mirrored live over SSE. */
"use strict";

const TOKEN = new URLSearchParams(location.search).get("token") || "";
const PHASES = ["recon", "enum", "creds", "access", "escalate", "loot"];
const PHASE_LABEL = { recon: "Recon", enum: "Enumerate", creds: "Credentials",
  access: "Access", escalate: "Escalate", loot: "Loot / domain" };
const PHASE_COLOR = { recon: "#38BDF8", enum: "#818CF8", creds: "#F59E0B",
  access: "#34D399", escalate: "#F472B6", loot: "#A855F7" };
const SEV_COLOR = { critical: "#E11D48", high: "#F97316", medium: "#EAB308", low: "#3B82F6", info: "#6B7591" };
const CAT_COLOR = { target: "#38BDF8", scan: "#818CF8", service: "#22D3EE", ad: "#F472B6",
  credential: "#F59E0B", access: "#34D399", loot: "#A855F7", config: "#94A3B8", other: "#6B7591" };
const ACCESS = {
  discovered: { c: "#6B7591", t: "Discovered" }, enumerated: { c: "#3B82F6", t: "Enumerated" },
  credentialed: { c: "#EAB308", t: "Credentialed" }, foothold: { c: "#14B8A6", t: "Foothold" },
  privileged: { c: "#10B981", t: "Privileged" },
};
const NODE_COLOR = { domain: "#6366F1", credential: "#EAB308", highvalue: "#E11D48", roastable: "#F97316" };

const state = { view: "engagement", target: null, tab: "overview", secrets: false };
const charts = {};
const $ = (s, el = document) => el.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

// ── api ──────────────────────────────────────────────────────────────────
async function api(path) {
  const r = await fetch(path, { headers: { "X-Obol-Token": TOKEN } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
  return r.json();
}
async function apiPost(path, body) {
  const r = await fetch(path, { method: "POST", headers: { "X-Obol-Token": TOKEN, "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) { const e = new Error(data.detail?.message || data.detail || `HTTP ${r.status}`); e.data = data; e.status = r.status; throw e; }
  return data;
}
async function apiDelete(path) {
  const r = await fetch(path, { method: "DELETE", headers: { "X-Obol-Token": TOKEN } });
  if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json();
}
async function apiUpload(path, form) {
  const r = await fetch(path, { method: "POST", headers: { "X-Obol-Token": TOKEN }, body: form });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) { const e = new Error(data.detail?.message || data.detail || `HTTP ${r.status}`); e.status = r.status; throw e; }
  return data;
}

function toast(title, body, kind) {
  const el = document.createElement("div");
  el.className = "toast " + (kind || "");
  el.innerHTML = `<div class="th">${esc(title)}</div>${body ? `<div class="tb">${esc(body)}</div>` : ""}`;
  $("#toasts").appendChild(el);
  setTimeout(() => { el.style.opacity = "0"; setTimeout(() => el.remove(), 300); }, 5200);
}
function flash() { const f = $("#flash"); f.classList.add("show"); setTimeout(() => f.classList.remove("show"), 1200); }

// ── boot ───────────────────────────────────────────────────────────────────
let ENGS = { engagements: [], active: null };
async function boot() {
  document.querySelectorAll(".nav-item").forEach((b) => b.addEventListener("click", () => setView(b.dataset.view)));
  $("#eng-new").addEventListener("click", newEngagement);
  $("#eng-select").addEventListener("change", async (e) => {
    await apiPost("/api/engagements/activate", { slug: e.target.value });
    state.view = "engagement"; state.target = null; await refreshEngList(); render();
  });
  await refreshEngList();
  connectEvents();
  render();
}
async function refreshEngList() {
  ENGS = await api("/api/engagements");
  const sel = $("#eng-select");
  sel.innerHTML = ENGS.engagements.map((e) => `<option value="${esc(e.slug)}" ${e.active ? "selected" : ""}>${esc(e.name)} · ${e.targets} tgt</option>`).join("")
    || `<option>no engagements</option>`;
}
async function newEngagement() {
  const name = prompt("New engagement name:");
  if (!name) return;
  const r = await apiPost("/api/engagements", { name });
  await refreshEngList();
  toast("Engagement created", r.name, "ok");
  state.view = "engagement"; state.target = null; render();
}
function setView(v) {
  state.view = v; state.target = null;
  document.querySelectorAll(".nav-item").forEach((b) => b.classList.toggle("active", b.dataset.view === v));
  render();
}
function openTarget(host) { state.view = "target"; state.target = host; state.tab = "overview";
  document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active")); render(); }

function connectEvents() {
  const dot = $("#conn-dot"), txt = $("#conn-text");
  const es = new EventSource(`/api/events?token=${encodeURIComponent(TOKEN)}`);
  es.addEventListener("hello", () => { dot.className = "dot live"; txt.textContent = "live"; });
  es.addEventListener("state", async () => { flash(); await refreshEngList(); render(); });
  es.onerror = () => { dot.className = "dot stale"; txt.textContent = "reconnecting…"; };
  es.onopen = () => { dot.className = "dot live"; txt.textContent = "live"; };
}

// ── router ──────────────────────────────────────────────────────────────────
async function render() {
  const c = $("#content");
  if (!ENGS.engagements.length) { renderNoEngagement(c); $("#crumb").textContent = ""; return; }
  try {
    if (state.view === "engagement") { $("#crumb").textContent = ""; return await renderEngagement(c); }
    if (state.view === "targets") { $("#crumb").textContent = "Targets"; return await renderTargets(c); }
    if (state.view === "engpath") { $("#crumb").textContent = "Attack path"; return await renderEngPath(c); }
    if (state.view === "report") { $("#crumb").textContent = "Report"; return await renderReport(c); }
    if (state.view === "target") return await renderTarget(c);
  } catch (e) { c.innerHTML = `<div class="card"><div class="empty">${esc(e.message)}</div></div>`; }
}
function destroyCharts() { Object.values(charts).forEach((ch) => ch && ch.destroy()); for (const k in charts) delete charts[k]; }

function renderNoEngagement(c) {
  c.innerHTML = `<div class="card"><div class="empty">
    <div style="font-size:16px;color:var(--text);margin-bottom:8px">No engagements yet</div>
    Create one to begin — it will hold your targets, evidence, and report.<br><br>
    <button class="btn primary" id="first-eng">＋ New engagement</button></div></div>`;
  $("#first-eng").addEventListener("click", newEngagement);
}

// ── engagement overview ─────────────────────────────────────────────────────
async function renderEngagement(c) {
  destroyCharts();
  const s = await api("/api/overview");
  const t = s.tiles;
  const tiles = [["Targets", s.targets.length], ["Facts proven", t.facts], ["Commands run", t.runs], ["Open ports", t.ports]]
    .map(([l, v]) => `<div class="stat"><div class="stat-label">${l}</div><div class="stat-val">${v}</div></div>`).join("");

  const tgtCards = s.targets.length ? s.targets.map((tg) => {
    const a = ACCESS[tg.access] || ACCESS.discovered;
    return `<div class="tcard" data-open="${esc(tg.host)}">
      <div class="tcard-h"><span class="tdot" style="background:${a.c}"></span><span class="t">${esc(tg.label)}</span>
        <span class="spacer" style="flex:1"></span><span class="mono muted" style="font-size:11px">${esc(tg.host)}</span></div>
      <div class="row" style="margin-top:8px;gap:6px">
        <span class="pill" style="border-color:${a.c}66;color:${a.c}">${a.t}</span>
        <span class="pill">${esc(PHASE_LABEL[tg.phase] || tg.phase)}</span>
        <span class="pill">${(tg.open_ports || []).length} ports</span>
        <span class="pill">${(tg.findings || []).length} findings</span>
      </div></div>`;
  }).join("") : `<div class="empty">No targets yet. <a href="#" id="add-first-tgt">Add one</a>.</div>`;

  const bh = s.bloodhound || {};
  const bhBlock = bh.domain ? `<div class="row" style="gap:14px;flex-wrap:wrap">
      <span class="pill" style="border-color:var(--accent-ring)">domain ${esc(bh.domain)}</span>
      <span class="pill">${(bh.computers || []).length} computers</span>
      <span class="pill" style="border-color:#E11D4866;color:#E11D48">${(bh.domain_admins || []).length} domain admins</span>
      <span class="pill" style="border-color:#F9731666;color:#F97316">${(bh.kerberoastable || []).length} kerberoastable</span>
      <span class="pill" style="border-color:#F9731666;color:#F97316">${(bh.asrep_roastable || []).length} AS-REP</span>
    </div>` : `<div class="muted">No BloodHound data yet.</div>`;

  const catTotal = Object.values(s.category_counts).reduce((a, b) => a + b, 0);
  const feed = (s.activity || []).map((a) => `<div class="feed-item"><span class="feed-tick">${esc((a.at_display || "").slice(5, 16))}</span>
    <span class="feed-body"><span class="ft">${esc(a.tool)}</span>${a.playbook ? `<span class="tag">${esc(a.playbook)}</span>` : ""}
    <div class="fd">${esc(a.command)}</div><div class="fd" style="color:var(--text-2)">${esc(a.status)}${a.produced?.length ? " · +" + a.produced.join(", ") : ""}</div></span></div>`).join("")
    || `<div class="empty">No activity yet.</div>`;

  c.innerHTML = `
    <div class="stat-grid">${tiles}</div>
    <div class="card" style="margin-top:16px"><div class="panel-h"><h2>Targets</h2><button class="btn sm primary" id="add-tgt">＋ Add target</button></div>
      <div class="tgrid">${tgtCards}</div></div>
    <div class="grid-2" style="margin-top:16px">
      <div class="card"><div class="panel-h"><h2>Evidence by category</h2><span class="muted mono">${catTotal}</span></div>
        <div class="grid-2" style="grid-template-columns:190px 1fr;align-items:center"><div class="chart-wrap"><canvas id="catChart"></canvas></div><div class="legend" id="catLegend"></div></div></div>
      <div class="card"><div class="panel-h"><h2>Domain (BloodHound)</h2><button class="btn sm" id="bh-upload-btn">Ingest export</button></div>
        ${bhBlock}<input type="file" id="bh-file" multiple accept=".zip,.json" hidden></div>
    </div>
    <div class="card" style="margin-top:16px"><div class="panel-h"><h2>Engagement attack path</h2><button class="btn ghost sm" data-view="engpath" id="see-path">full view →</button></div>
      <div class="flow-scroll">${engagementSVG(s.engagement_graph)}</div></div>
    <div class="card" style="margin-top:16px"><div class="panel-h"><h2>Activity</h2></div><div class="feed">${feed}</div></div>`;

  drawDonut("catChart", s.category_counts, CAT_COLOR, "catLegend");
  c.querySelectorAll("[data-open]").forEach((el) => el.addEventListener("click", () => openTarget(el.dataset.open)));
  const addBtn = $("#add-tgt") || $("#add-first-tgt");
  c.querySelectorAll("#add-tgt,#add-first-tgt").forEach((b) => b.addEventListener("click", (e) => { e.preventDefault(); addTargetPrompt(); }));
  $("#see-path").addEventListener("click", () => setView("engpath"));
  $("#bh-upload-btn").addEventListener("click", () => $("#bh-file").click());
  $("#bh-file").addEventListener("change", uploadBloodhound);
}

async function addTargetPrompt() {
  const host = prompt("Target host or IP:");
  if (!host) return;
  const label = prompt("Label (optional):") || "";
  try { await apiPost("/api/targets", { host, label }); toast("Target added", host, "ok"); render(); }
  catch (e) { toast("Could not add target", e.message, "err"); }
}
async function uploadBloodhound(e) {
  const files = e.target.files; if (!files.length) return;
  const fd = new FormData(); for (const f of files) fd.append("files", f);
  try { const r = await apiUpload("/api/bloodhound", fd);
    toast("BloodHound ingested", `${r.domain || "domain"} · ${r.users} users · ${r.domain_admins} DAs · ${r.kerberoastable} kerberoastable`, "ok");
    render();
  } catch (err) { toast("Ingest failed", err.message, "err"); }
  e.target.value = "";
}

function drawDonut(canvasId, counts, colorMap, legendId) {
  const labels = Object.keys(counts); const el = document.getElementById(canvasId);
  if (!el) return;
  if (!labels.length) { el.parentElement.innerHTML = `<div class="empty">Nothing yet.</div>`; if (legendId) $("#" + legendId).innerHTML = ""; return; }
  const data = labels.map((k) => counts[k]); const colors = labels.map((k) => colorMap[k] || "#6B7591");
  charts[canvasId] = new Chart(el, { type: "doughnut",
    data: { labels, datasets: [{ data, backgroundColor: colors, borderColor: "#0D1220", borderWidth: 2 }] },
    options: { cutout: "62%", plugins: { legend: { display: false } }, maintainAspectRatio: false } });
  if (legendId) $("#" + legendId).innerHTML = labels.map((k, i) => `<div class="legend-row"><span class="sw" style="background:${colors[i]}"></span><span>${esc(k)}</span><span class="lg-n">${data[i]}</span></div>`).join("");
}

// ── targets list ────────────────────────────────────────────────────────────
async function renderTargets(c) {
  const s = await api("/api/overview");
  const cards = s.targets.map((tg) => {
    const a = ACCESS[tg.access] || ACCESS.discovered;
    return `<div class="tcard" data-open="${esc(tg.host)}">
      <div class="tcard-h"><span class="tdot" style="background:${a.c}"></span><span class="t">${esc(tg.label)}</span>
        <span class="spacer" style="flex:1"></span><button class="btn ghost sm tdel" data-del="${esc(tg.host)}" title="Remove">✕</button></div>
      <div class="mono muted" style="font-size:12px;margin:4px 0">${esc(tg.host)}${tg.os ? " · " + esc(tg.os) : ""}</div>
      <div class="row" style="gap:6px">
        <span class="pill" style="border-color:${a.c}66;color:${a.c}">${a.t}</span>
        <span class="pill">${esc(PHASE_LABEL[tg.phase] || tg.phase)}</span>
        <span class="pill">${(tg.open_ports || []).length} ports</span></div></div>`;
  }).join("") || `<div class="empty">No targets yet.</div>`;
  c.innerHTML = `<div class="card"><div class="panel-h"><h2>Targets</h2><button class="btn sm primary" id="add-tgt">＋ Add target</button></div><div class="tgrid">${cards}</div></div>`;
  c.querySelectorAll("[data-open]").forEach((el) => el.addEventListener("click", (e) => { if (e.target.closest("[data-del]")) return; openTarget(el.dataset.open); }));
  c.querySelectorAll("[data-del]").forEach((b) => b.addEventListener("click", async (e) => {
    e.stopPropagation();
    if (confirm(`Remove target ${b.dataset.del}?`)) { await apiDelete(`/api/target?target=${encodeURIComponent(b.dataset.del)}`); render(); }
  }));
  $("#add-tgt").addEventListener("click", addTargetPrompt);
}

// ── target detail (tabs) ────────────────────────────────────────────────────
const TABS = [["overview", "Overview"], ["tools", "Tools"], ["playbooks", "Playbooks"],
  ["checklist", "Checklist"], ["findings", "Findings"], ["evidence", "Evidence"], ["commands", "Commands"]];
let _bundle = null;

async function renderTarget(c) {
  const host = state.target;
  const b = await api(`/api/target?target=${encodeURIComponent(host)}`);
  _bundle = b;
  const a = ACCESS[b.access] || ACCESS.discovered;
  $("#crumb").innerHTML = `<a href="#" id="crumb-tgts">Targets</a> / ${esc(b.meta.label)}`;
  const tabs = TABS.map(([id, label]) => `<button class="tab ${state.tab === id ? "active" : ""}" data-tab="${id}">${label}</button>`).join("");
  c.innerHTML = `
    <div class="card tdetail-h">
      <div class="row" style="gap:12px;align-items:center">
        <span class="tdot lg" style="background:${a.c}"></span>
        <div><div style="font-size:18px;font-weight:700">${esc(b.meta.label)}</div>
          <div class="mono muted" style="font-size:12px">${esc(b.meta.host)}${b.meta.os ? " · " + esc(b.meta.os) : ""}</div></div>
        <span class="spacer" style="flex:1"></span>
        <span class="pill" style="border-color:${a.c}66;color:${a.c}">${a.t}</span>
        ${b.meta.active ? `<span class="pill" style="border-color:var(--green)66;color:var(--green)">active</span>` : `<button class="btn sm" id="mk-active">Make active</button>`}
      </div>
      ${chainBar(b.chain)}
    </div>
    <div class="tabbar">${tabs}</div>
    <div id="tabc"></div>`;
  $("#crumb-tgts").addEventListener("click", (e) => { e.preventDefault(); setView("targets"); });
  const mk = $("#mk-active"); if (mk) mk.addEventListener("click", async () => { await apiPost("/api/target/activate", { target: host }); render(); });
  c.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => { state.tab = t.dataset.tab; renderTarget(c); }));
  c.querySelectorAll("[data-chain]").forEach((seg) => seg.addEventListener("click", () => {
    state.tab = "overview"; renderTarget(c).then(() => { const el = document.getElementById("phase-" + seg.dataset.chain); if (el) el.scrollIntoView({ behavior: "smooth", block: "center" }); });
  }));
  renderTab($("#tabc"), b);
}

function chainBar(chain) {
  return `<div class="chain">${chain.map((seg) => `
    <div class="chain-seg ${seg.reached ? "on" : ""} ${seg.current ? "cur" : ""}" data-chain="${seg.phase}" title="${seg.move_count} moves">
      <div class="chain-bar" style="${seg.reached ? `background:${PHASE_COLOR[seg.phase]}` : ""}"></div>
      <div class="chain-lbl">${esc(seg.label)}</div>
      ${seg.move_count ? `<div class="chain-n">${seg.move_count}</div>` : ""}
    </div>`).join("")}</div>`;
}

function renderTab(el, b) {
  if (state.tab === "overview") return tabOverview(el, b);
  if (state.tab === "tools") return tabTools(el, b);
  if (state.tab === "playbooks") return tabPlaybooks(el, b);
  if (state.tab === "checklist") return tabChecklist(el, b);
  if (state.tab === "findings") return tabFindings(el, b);
  if (state.tab === "evidence") return tabEvidence(el, b);
  if (state.tab === "commands") return tabCommands(el, b);
}

function moveCard(a, host) {
  const v = a.variants[0]; const pc = PHASE_COLOR[a.phase] || "#6B7591";
  return `<div class="move" id="move-${esc(a.id)}">
    <div class="move-h"><span class="phase-tag" style="background:${pc}22;color:${pc};border:1px solid ${pc}55">${esc(a.phase)}</span>
      <span class="t">${esc(a.title)}</span><span class="spacer" style="flex:1"></span>
      <span class="muted mono" style="font-size:11px">${esc((a.tools || []).join(", "))}</span></div>
    ${a.desc ? `<div class="desc">${esc(a.desc)}</div>` : ""}
    ${v ? `<pre class="cmd">$ ${esc(v.command)}</pre>` : ""}
    <div class="row" style="margin-top:11px"><button class="btn primary sm" data-run="${esc(a.id)}">Run</button>
      <button class="btn sm" data-run="${esc(a.id)}" data-dry="1">Dry-run</button></div></div>`;
}

function tabOverview(el, b) {
  const groups = PHASES.map((ph) => {
    const moves = b.next.filter((m) => m.phase === ph);
    if (!moves.length) return "";
    return `<div id="phase-${ph}" class="phase-group"><div class="phase-head" style="color:${PHASE_COLOR[ph]}">${esc(PHASE_LABEL[ph])}</div>${moves.map((m) => moveCard(m, b.meta.host)).join("")}</div>`;
  }).join("") || `<div class="empty">No live moves — run a scan to unlock this target's methodology.</div>`;
  el.innerHTML = `
    <div class="grid-2">
      <div class="card"><div class="panel-h"><h2>Open ports</h2></div>${(b.open_ports || []).length ? `<div class="row" style="gap:6px;flex-wrap:wrap">${b.open_ports.map((p) => `<span class="pill mono">${esc(p)}</span>`).join("")}</div>` : `<div class="muted">None parsed yet — run the nmap prelude.</div>`}</div>
      <div class="card"><div class="panel-h"><h2>Where we are</h2></div><div class="muted">Phase: <b style="color:var(--text)">${esc(PHASE_LABEL[b.phase] || b.phase)}</b> · Access: <b style="color:var(--text)">${esc((ACCESS[b.access] || {}).t || b.access)}</b></div><div class="muted" style="margin-top:6px">${b.next.length} live moves · ${b.findings.length} findings</div></div>
    </div>
    <div class="card" style="margin-top:16px"><div class="panel-h"><h2>Path</h2></div><div class="flow-scroll">${flowSVG(b.graph)}</div></div>
    <div class="card" style="margin-top:16px"><div class="panel-h"><h2>Next moves — run from here</h2><span class="muted mono">${b.next.length}</span></div>${groups}</div>`;
  wireRun(el, b.meta.host);
}

function tabTools(el, b) {
  if (!b.tools.length) { el.innerHTML = `<div class="card"><div class="empty">No applicable tools yet — run the nmap prelude to learn this target's services.</div></div>`; return; }
  el.innerHTML = b.tools.map((grp) => `<div class="card"><div class="panel-h"><h2 style="color:${PHASE_COLOR[grp.phase]}">${esc(grp.label)}</h2><span class="muted mono">${grp.actions.length}</span></div>
    <div class="tool-grid">${grp.actions.map((a) => toolCard(a)).join("")}</div></div>`).join("");
  wireRun(el, b.meta.host);
}
function toolCard(a) {
  const v = a.variants[0];
  return `<div class="tool-card"><div class="tc-h"><span class="t">${esc(a.title)}</span></div>
    <div class="tc-tools mono">${esc((a.tools || []).join(", "))}</div>
    ${v ? `<pre class="cmd sm">$ ${esc(v.command)}</pre>` : ""}
    <div class="row" style="margin-top:9px"><button class="btn primary sm" data-run="${esc(a.id)}">Run</button>
      <button class="btn sm" data-run="${esc(a.id)}" data-dry="1">Dry-run</button></div></div>`;
}

async function tabPlaybooks(el, b) {
  const { playbooks } = await api("/api/playbooks");
  el.innerHTML = `<div class="card"><div class="panel-h"><h2>Playbooks</h2><span class="muted mono">${playbooks.length}</span></div>
    <div class="muted" style="margin-bottom:10px">Ordered sequences run through the same runner, scoped to this target. Steps tagged <span class="tag" style="background:#F9731622;color:#F97316">approval</span> confirm first.</div>
    <div id="pb-list">${playbooks.map((p) => `<div class="move" data-pb="${esc(p.name)}" style="cursor:pointer"><div class="move-h"><span class="t">${esc(p.title)}</span><span class="spacer" style="flex:1"></span><span class="muted mono" style="font-size:11px">${esc(p.name)}</span></div>${p.description ? `<div class="desc">${esc(p.description)}</div>` : ""}</div>`).join("") || `<div class="empty">No playbooks.</div>`}</div>
    <div id="pb-detail"></div></div>`;
  el.querySelectorAll("[data-pb]").forEach((d) => d.addEventListener("click", () => openPlaybook(d.dataset.pb, b.meta.host)));
}
async function openPlaybook(name, host) {
  const pb = await api(`/api/playbook/${encodeURIComponent(name)}?target=${encodeURIComponent(host)}`);
  $("#pb-detail").innerHTML = `<div class="panel-h" style="margin-top:16px"><h2>${esc(pb.title)} — steps</h2></div>${pb.steps.map((s) => `
    <div class="move"><div class="move-h"><span class="phase-tag" style="background:var(--accent-soft);color:var(--accent-2)">step ${s.step}</span><span class="t">${esc(s.label)}</span>${s.require_approval ? `<span class="tag" style="background:#F9731622;color:#F97316">approval</span>` : ""}</div>
      <pre class="cmd">$ ${esc(s.command)}</pre>
      <div class="row" style="margin-top:9px"><button class="btn primary sm" data-pbrun="${esc(pb.name)}" data-step="${s.step}" data-approval="${s.require_approval ? 1 : 0}">Run step</button>
        <button class="btn sm" data-pbrun="${esc(pb.name)}" data-step="${s.step}" data-dry="1">Dry-run</button></div></div>`).join("")}`;
  $("#pb-detail").querySelectorAll("[data-pbrun]").forEach((btn) => btn.addEventListener("click", () => runPlaybookStep(btn.dataset.pbrun, +btn.dataset.step, btn.dataset.dry === "1", btn.dataset.approval === "1", host)));
}

function tabChecklist(el, b) {
  el.innerHTML = `<div class="card"><div class="panel-h"><h2>Attack-chain checklist</h2><span class="muted">static reference · tick as you go</span></div>
    ${b.checklist.map((grp) => `<div class="chk-group"><div class="phase-head" style="color:${PHASE_COLOR[grp.phase]}">${esc(grp.label)}</div>
      ${grp.items.map((i) => `<label class="chk-item"><input type="checkbox" data-chk="${esc(i.id)}" ${i.checked ? "checked" : ""}>
        <span class="chk-body"><span class="chk-t">${esc(i.title)}</span><code class="chk-cmd">${esc(i.command)}</code></span></label>`).join("")}</div>`).join("")}</div>`;
  el.querySelectorAll("[data-chk]").forEach((cb) => cb.addEventListener("change", async () => {
    try { await apiPost("/api/target/checklist", { target: b.meta.host, item: cb.dataset.chk, checked: cb.checked }); }
    catch (e) { toast("Could not save", e.message, "err"); cb.checked = !cb.checked; }
  }));
}

function tabFindings(el, b) {
  const rows = b.findings.map((f) => `<tr><td class="kind">${esc(f.kind)}</td><td>${esc(f.label)}${Object.keys(f.value || {}).length ? `<div class="fd muted mono" style="font-size:11px">${esc(JSON.stringify(f.value))}</div>` : ""}</td>
    <td><span class="cat-chip" style="border-color:${(CAT_COLOR[f.category] || "#6B7591")}66;color:${CAT_COLOR[f.category] || "#B0B8C9"}">${esc(f.category)}</span></td>
    <td class="mono muted" style="font-size:11px;max-width:320px;word-break:break-all">${esc(f.evidence)}</td></tr>`).join("")
    || `<tr><td colspan="4"><div class="empty">No findings for this target yet.</div></td></tr>`;
  el.innerHTML = `<div class="card"><div class="panel-h"><h2>Findings</h2><span class="muted mono">${b.findings.length}</span></div>
    <table><thead><tr><th>Kind</th><th>Finding</th><th>Category</th><th>Evidence</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

function tabEvidence(el, b) {
  const gallery = b.evidence.length ? b.evidence.map((e) => `<div class="ev-card">
    <img src="${esc(e.url)}?token=${encodeURIComponent(TOKEN)}" alt="${esc(e.caption)}" loading="lazy">
    <div class="ev-meta"><div class="ev-cap">${esc(e.caption || e.filename)}</div>${e.phase ? `<span class="tag">${esc(e.phase)}</span>` : ""}
      <button class="btn ghost sm" data-evdel="${esc(e.id)}" title="Delete">✕</button></div></div>`).join("")
    : `<div class="empty">No screenshots yet — add evidence to embed it in the report.</div>`;
  el.innerHTML = `<div class="card"><div class="panel-h"><h2>Evidence & screenshots</h2></div>
    <div class="ev-upload"><input type="file" id="ev-file" accept="image/*">
      <input type="text" id="ev-cap" class="inp" placeholder="caption (e.g. WinRM shell as svc-alfresco)">
      <select id="ev-phase" class="inp">${["", ...PHASES].map((p) => `<option value="${p}">${p ? PHASE_LABEL[p] : "phase…"}</option>`).join("")}</select>
      <button class="btn primary sm" id="ev-add">Add</button></div>
    <div class="ev-grid" style="margin-top:14px">${gallery}</div></div>`;
  $("#ev-add").addEventListener("click", async () => {
    const f = $("#ev-file").files[0]; if (!f) { toast("Pick a file first", "", "err"); return; }
    const fd = new FormData(); fd.append("file", f); fd.append("target", b.meta.host);
    fd.append("caption", $("#ev-cap").value); fd.append("phase", $("#ev-phase").value);
    try { await apiUpload("/api/target/evidence", fd); toast("Evidence added", f.name, "ok"); render(); }
    catch (e) { toast("Upload failed", e.message, "err"); }
  });
  el.querySelectorAll("[data-evdel]").forEach((btn) => btn.addEventListener("click", async () => {
    if (confirm("Delete this evidence?")) { await apiDelete(`/api/evidence/${btn.dataset.evdel}`); render(); }
  }));
}

function tabCommands(el, b) {
  const rows = b.commands.length ? b.commands.map((r) => `<div class="feed-item"><span class="feed-tick">${esc((new Date((r.at || 0) * 1000)).toISOString().slice(5, 16).replace("T", " "))}</span>
    <span class="feed-body"><span class="ft">${esc(r.tool)}</span>${r.playbook ? `<span class="tag">${esc(r.playbook)}</span>` : ""}
    <div class="fd">$ ${esc(r.command)}</div><div class="fd" style="color:var(--text-2)">${esc(r.status)}${r.produced.length ? " · +" + r.produced.join(", ") : ""}</div></span></div>`).join("")
    : `<div class="empty">No commands run against this target yet.</div>`;
  el.innerHTML = `<div class="card"><div class="panel-h"><h2>Commands & evidence ledger</h2></div><div class="feed">${rows}</div></div>`;
}

function wireRun(el, host) {
  el.querySelectorAll("[data-run]").forEach((b) => b.addEventListener("click", () => runAction(b.dataset.run, host, b.dataset.dry === "1")));
}
async function runAction(actionId, host, dry) {
  try {
    const o = await apiPost("/api/run/action", { action_id: actionId, target: host, dry_run: dry });
    if (o.dry_run) toast("Dry-run", `${o.command}\n(not executed)`, "ok");
    else if (o.added_count) toast("Ran " + o.tool, `+${o.added_count}: ${o.added.map((f) => f.kind).join(", ")}`, "ok");
    else toast("Ran " + o.tool, "no new facts — raw output saved", "");
  } catch (e) { toast("Run failed", e.message, "err"); }
}
async function runPlaybookStep(name, step, dry, needsApproval, host) {
  if (needsApproval && !dry && !confirm(`Step ${step} is noisy/intrusive. Run it now?`)) return;
  try {
    const o = await apiPost("/api/run/playbook", { name, step, target: host, dry_run: dry, approve: needsApproval });
    if (o.dry_run) toast(`Dry-run · step ${step}`, o.command, "ok");
    else if (o.added_count) toast(`Ran step ${step}`, `+${o.added_count}: ${o.added.map((f) => f.kind).join(", ")}`, "ok");
    else toast(`Ran step ${step}`, "no new facts — raw output saved", "");
  } catch (e) { toast(e.status === 409 ? "Needs approval" : "Step failed", e.message, e.status === 409 ? "" : "err"); }
}

// ── engagement attack path ──────────────────────────────────────────────────
async function renderEngPath(c) {
  const g = await api("/api/engagement/graph");
  c.innerHTML = `<div class="card"><div class="panel-h"><h2>Engagement attack path</h2></div>
    <div class="flow-legend"><span class="flk"><span class="sw rect" style="background:${NODE_COLOR.domain}"></span>domain</span>
      <span class="flk"><span class="sw rect" style="background:${ACCESS.foothold.c}"></span>target (by access)</span>
      <span class="flk"><span class="sw rect" style="background:${NODE_COLOR.credential}"></span>credential</span>
      <span class="flk"><span class="sw rect" style="background:${NODE_COLOR.highvalue}"></span>high-value</span>
      <span class="flk"><span class="sw rect" style="background:${NODE_COLOR.roastable}"></span>roastable</span></div>
    <div class="flow-scroll">${engagementSVG(g)}</div></div>`;
}

// tiered top-down graph: domain (0) → targets (1) → creds/high-value (2) → roastable (3)
function engagementSVG(g) {
  if (!g.nodes.length) return `<div class="empty">Add targets (and ingest BloodHound) to see the engagement path.</div>`;
  const tiers = {}; g.nodes.forEach((n) => (tiers[n.tier] = tiers[n.tier] || []).push(n));
  const NW = 190, NH = 46, GAPX = 30, ROWY = 110, PADX = 24, PADY = 24;
  const maxRow = Math.max(...Object.values(tiers).map((r) => r.length));
  const width = Math.max(560, PADX * 2 + maxRow * (NW + GAPX) - GAPX);
  const tierKeys = Object.keys(tiers).map(Number).sort((a, b) => a - b);
  const height = PADY * 2 + tierKeys.length * ROWY;
  const pos = {};
  tierKeys.forEach((tk, ti) => {
    const row = tiers[tk]; const rowW = row.length * (NW + GAPX) - GAPX; const startX = (width - rowW) / 2;
    row.forEach((n, i) => { pos[n.id] = { x: startX + i * (NW + GAPX), y: PADY + ti * ROWY, node: n }; });
  });
  let edges = "";
  g.edges.forEach((e) => { const a = pos[e.from], b = pos[e.to]; if (!a || !b) return;
    const x1 = a.x + NW / 2, y1 = a.y + NH, x2 = b.x + NW / 2, y2 = b.y;
    edges += `<path d="M${x1},${y1} C${x1},${(y1 + y2) / 2} ${x2},${(y1 + y2) / 2} ${x2},${y2}" fill="none" stroke="#3D4D75" stroke-width="1.5"/>`; });
  let nodes = "";
  Object.values(pos).forEach(({ x, y, node }) => {
    let fill = NODE_COLOR[node.type] || "#334155", sub = "";
    if (node.type === "target") { const a = ACCESS[node.meta.access] || ACCESS.discovered; fill = a.c; sub = a.t + (node.meta.dc ? " · DC" : ""); }
    const click = node.type === "target" ? ` data-egtgt="${esc(node.meta.host)}" style="cursor:pointer"` : "";
    nodes += `<foreignObject x="${x}" y="${y}" width="${NW}" height="${NH}"${click}>
      <div xmlns="http://www.w3.org/1999/xhtml" class="egnode" style="border-color:${fill};box-shadow:inset 0 0 0 9999px ${fill}22" title="${esc(node.label)}">
      <span class="egt">${esc(node.label)}</span>${sub ? `<span class="egs" style="color:${fill}">${esc(sub)}</span>` : ""}</div></foreignObject>`;
  });
  return `<svg class="flow" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" preserveAspectRatio="xMidYMin meet">${edges}${nodes}</svg>`;
}

// per-target methodology flow (phase columns) — shared with the report
function flowSVG(g) {
  const byPhase = {}; PHASES.forEach((p) => (byPhase[p] = []));
  g.nodes.forEach((n) => (byPhase[n.phase] || (byPhase[n.phase] = [])).push(n));
  const cols = PHASES.filter((p) => byPhase[p] && byPhase[p].length);
  if (!cols.length) return `<div class="empty">Nothing on the path yet — run a scan.</div>`;
  const NW = 178, NH = 42, COLW = 214, ROW = 56, PADX = 22, PADY = 46;
  const pos = {};
  cols.forEach((p, ci) => byPhase[p].forEach((n, ri) => { pos[n.id] = { x: PADX + ci * COLW, y: PADY + ri * ROW, w: NW, h: NH, node: n }; }));
  const height = PADY + Math.max(...cols.map((p) => byPhase[p].length)) * ROW + 14;
  const width = PADX * 2 + (cols.length - 1) * COLW + NW;
  let edges = "";
  g.edges.forEach((e) => { const a = pos[e.from], b = pos[e.to]; if (!a || !b) return;
    const x1 = a.x + a.w, y1 = a.y + a.h / 2, x2 = b.x, y2 = b.y + b.h / 2, mx = (x1 + x2) / 2;
    const future = b.node.type === "fact" && b.node.state === "future";
    edges += `<path d="M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}" fill="none" stroke="${future ? "#3D4D75" : "#4b5a86"}" stroke-width="1.5"${future ? ' stroke-dasharray="4 4"' : ""}/>`; });
  const headers = cols.map((p, ci) => `<text x="${PADX + ci * COLW + NW / 2}" y="24" text-anchor="middle" fill="${PHASE_COLOR[p]}" font-size="11" font-weight="700" letter-spacing="1.2">${PHASE_LABEL[p].toUpperCase()}</text><line x1="${PADX + ci * COLW}" y1="32" x2="${PADX + ci * COLW + NW}" y2="32" stroke="${PHASE_COLOR[p]}" stroke-opacity="0.35" stroke-width="1.5"/>`).join("");
  let nodes = "";
  Object.values(pos).forEach(({ x, y, w, h, node }) => {
    const cls = node.type === "fact" ? `fnode fact ${node.state}` : `fnode action ${node.state}`;
    nodes += `<foreignObject x="${x}" y="${y}" width="${w}" height="${h}"><div xmlns="http://www.w3.org/1999/xhtml" class="${cls}" title="${esc(node.label)}"><span>${esc(node.label)}</span></div></foreignObject>`;
  });
  return `<svg class="flow" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" preserveAspectRatio="xMinYMin meet">${headers}${edges}${nodes}</svg>`;
}

// ── report ──────────────────────────────────────────────────────────────────
async function renderReport(c) {
  const r = await api(`/api/report?include_secrets=${state.secrets ? "1" : "0"}`);
  const m = r.meta;
  const statRow = [["Engagement", esc(m.name)], ["Targets", r.targets.length], ["Facts", r.tiles.facts], ["Commands", r.tiles.runs], ["Domain", esc(m.domain || "—")]]
    .map(([l, v]) => `<div class="stat"><div class="stat-label">${l}</div><div class="stat-val" style="font-size:19px">${v}</div></div>`).join("");
  const targets = r.targets.map((t) => {
    const a = ACCESS[t.access] || ACCESS.discovered;
    const finds = t.findings.map((f) => `<tr><td class="kind">${esc(f.kind)}</td><td>${esc(f.label)}<div class="muted mono" style="font-size:11px">${esc(f.evidence)}</div></td></tr>`).join("") || `<tr><td colspan="2" class="muted">No findings.</td></tr>`;
    const ev = t.evidence.map((e) => `<figure class="ev-fig"><img src="${esc(e.url)}?token=${encodeURIComponent(TOKEN)}" alt="${esc(e.caption)}"><figcaption>${esc(e.caption || e.filename)}${e.phase ? ` · ${esc(e.phase)}` : ""}</figcaption></figure>`).join("");
    return `<div class="card"><div class="report-head"><h2 style="font-size:16px">${esc(t.label)}</h2><span class="mono muted">${esc(t.host)}</span>
        <span class="pill" style="border-color:${a.c}66;color:${a.c}">${a.t}</span><span class="pill">${esc(PHASE_LABEL[t.phase] || t.phase)}</span></div>
      ${t.open_ports.length ? `<div class="report-section-title">Open ports</div><div class="row" style="gap:6px;flex-wrap:wrap">${t.open_ports.map((p) => `<span class="pill mono">${esc(p)}</span>`).join("")}</div>` : ""}
      <div class="report-section-title">Findings (${t.findings.length})</div><table><tbody>${finds}</tbody></table>
      ${ev ? `<div class="report-section-title">Evidence</div><div class="ev-grid">${ev}</div>` : ""}</div>`;
  }).join("");
  c.innerHTML = `<div class="card"><div class="report-head"><h2>${esc(m.name)}</h2><span class="muted">OSCP-style evidence report</span><span class="spacer" style="flex:1"></span>
      <label class="pill" style="cursor:pointer"><input type="checkbox" id="sec-toggle" ${state.secrets ? "checked" : ""} style="margin-right:6px">include secrets</label>
      <a class="btn sm primary" href="/api/report.md?include_secrets=${state.secrets ? "1" : "0"}&token=${encodeURIComponent(TOKEN)}">Download .md</a></div>
      <div class="muted" style="margin-top:6px">Generated ${esc(m.generated_at)} · ${m.include_secrets ? "secrets shown" : "secrets redacted"} · every finding is only as strong as its cited evidence.</div>
      <div class="stat-grid" style="margin-top:16px">${statRow}</div></div>
    <div class="card"><div class="panel-h"><h2>Engagement attack path</h2></div><div class="flow-scroll">${engagementSVG(r.engagement_graph)}</div></div>
    ${targets || `<div class="card"><div class="empty">No targets yet.</div></div>`}`;
  $("#sec-toggle").addEventListener("change", (e) => { state.secrets = e.target.checked; renderReport(c); });
}

boot();

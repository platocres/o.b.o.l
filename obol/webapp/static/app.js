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

const state = { view: "engagement", target: null, tab: "overview", secrets: false, toolTarget: "", lastRun: null };
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

function shortJson(value, limit = 150) {
  if (!value || (typeof value === "object" && !Object.keys(value).length)) return "";
  let s = typeof value === "string" ? value : JSON.stringify(value);
  if (s.length > limit) s = s.slice(0, limit - 1) + "…";
  return s;
}
function factChip(f) {
  const val = shortJson(f.value);
  return `<div class="fact-chip">
    <div class="fc-top"><span class="fc-label">${esc(f.label || f.kind)}</span><span class="cat-chip" style="border-color:${(CAT_COLOR[f.category] || "#6B7591")}66;color:${CAT_COLOR[f.category] || "#B0B8C9"}">${esc(f.category || "other")}</span></div>
    <div class="fc-kind">${esc(f.kind)}</div>
    ${val ? `<code class="fc-val">${esc(val)}</code>` : ""}
    ${f.evidence ? `<div class="fc-src" title="${esc(f.evidence)}">${esc(f.evidence)}</div>` : ""}</div>`;
}
function factsSummaryHtml(summary) {
  const sections = summary || [];
  if (!sections.length) return `<div class="empty">No facts recorded yet. Run the nmap prelude to start filling this in.</div>`;
  return `<div class="facts-summary">${sections.map((s) => `<section class="fact-section">
    <div class="fact-section-h"><span>${esc(s.title)}</span><span class="muted mono">${s.count}</span></div>
    <div class="fact-chip-grid">${(s.facts || []).map(factChip).join("")}</div>
  </section>`).join("")}</div>`;
}
function statusText(p) {
  if (!p) return "Unknown";
  if (p.status === "ready") return "Ready";
  if (p.status === "manual") return "Manual handoff";
  if (p.status === "done") return "Done";
  if (p.status === "waiting") return "Waiting";
  return "Blocked";
}
function preflightBadges(p) {
  if (!p) return `<span class="pf-badge blocked">No preflight</span>`;
  const cls = p.status === "ready" ? "ready" : (p.status === "manual" ? "manual" : "blocked");
  const tool = p.tool || {};
  const parser = p.parser || {};
  const toolCls = tool.found ? "ready" : "blocked";
  const parserCls = parser.state === "supported" ? "parser" : "warn";
  const miss = (p.missing_inputs || []).length;
  return `<div class="preflight-badges"><span class="pf-badge ${cls}">${esc(statusText(p))}</span>` +
    `<span class="pf-badge ${toolCls}">${tool.found ? "tool found" : "tool missing"}: ${esc(tool.label || tool.binary || p.tool || "tool")}</span>` +
    `<span class="pf-badge ${parserCls}">${esc(parser.label || "Raw evidence")}</span>` +
    (miss ? `<span class="pf-badge blocked">${miss} input${miss === 1 ? "" : "s"} needed</span>` : "") + `</div>`;
}
function preflightIssues(p) {
  const issues = (p && p.issues) || [];
  if (!issues.length) return "";
  return `<div class="pf-issues">${issues.slice(0, 4).map((i) => `<div class="pf-issue ${esc(i.severity || "")}">${esc(i.message || i.kind)}${i.fix ? ` <span class="muted">${esc(i.fix)}</span>` : ""}</div>`).join("")}</div>`;
}
function missingInputControls(p) {
  const inputs = (p && p.missing_inputs) || [];
  if (!inputs.length) return "";
  return `<div class="missing-inputs"><span class="hint">Missing:</span>${inputs.map((i) => i.promptable
    ? `<button class="btn xs" data-setinput="${esc(i.name)}" title="${esc(i.hint || "")}">Set ${esc(i.name)}</button>`
    : `<span class="pill" title="${esc(i.hint || "")}">${esc(i.name)} from facts</span>`).join("")}</div>`;
}
function variantRows(a, host) {
  const variants = a.variants || [];
  if (!variants.length) return `<div class="empty compact">No command variants available.</div>`;
  return `<div class="composer">${variants.map((v) => {
    const p = v.preflight || {};
    const canRun = !!p.can_run;
    const copyLabel = p.needs_handoff ? "Copy handoff" : "Copy";
    return `<div class="variant-row">
      <div class="variant-top"><div class="variant-title"><span class="pill mono">#${esc(v.index)}</span><span class="mono muted">${esc(v.tool || "")}</span></div>${preflightBadges(p)}</div>
      <pre class="cmd sm">$ ${esc(v.command)}</pre>
      ${v.note ? `<div class="variant-note">${esc(v.note)}</div>` : ""}
      ${missingInputControls(p)}${preflightIssues(p)}
      <div class="composer-actions"><button class="btn primary sm" data-run="${esc(a.id)}" data-cmd="${esc(v.index)}" ${canRun ? "" : "disabled"}>Run</button>
        <button class="btn sm" data-copycmd="${esc(v.command)}">${copyLabel}</button></div>
    </div>`;
  }).join("")}</div>`;
}
function runStatusPanel(host) {
  const r = state.lastRun;
  if (!r || r.target !== host) return "";
  if (r.pending) {
    const title = r.quickstart ? "Quick Start running" : "Running command";
    const detail = r.quickstart ? "Running nmap first, then service-aware baseline enumeration as facts unlock it." : "Waiting for the shared runner to return…";
    return `<div class="run-panel pending"><div class="run-head"><span class="pulse"></span><div><b>${esc(title)}</b><div class="muted">${esc(detail)}</div></div></div>
      <div class="muted mono" style="margin-top:8px">${esc(r.action_id || "")}</div></div>`;
  }
  if (r.error) {
    return `<div class="run-panel failed"><div class="run-head"><span class="status-dot bad"></span><div><b>Run refused</b><div class="muted">${esc(r.error)}</div></div></div></div>`;
  }
  const o = r.outcome || {};
  const facts = o.facts || o.added || [];
  const okClass = o.success ? (o.dry_run ? "pending" : "ok") : (o.status === "partial" ? "pending" : "failed");
  const title = o.quickstart ? (o.success ? "Quick Start complete" : (o.status === "partial" ? "Quick Start partially complete" : "Quick Start blocked")) : (o.dry_run ? "Preview complete" : (o.success ? "Command succeeded" : "Command failed"));
  const preview = (!o.success || !facts.length)
    ? `<div class="run-previews">${o.stderr_preview ? `<div><div class="rp-label">stderr preview</div><pre>${esc(o.stderr_preview)}</pre></div>` : ""}${o.stdout_preview ? `<div><div class="rp-label">stdout preview</div><pre>${esc(o.stdout_preview)}</pre></div>` : ""}</div>`
    : "";
  const steps = (o.steps || []).length ? `<div class="run-steps"><div class="rp-label">Commands run (${o.steps.length})</div>${o.steps.map((s) => `<div class="step-row"><span class="status-dot ${s.success ? "good" : "bad"}"></span><span>${esc(s.title || s.action_id)}</span><span class="muted mono">${esc(s.status || "")}${s.added_count ? ` · +${s.added_count}` : ""}</span></div>`).join("")}</div>` : "";
  const skipped = (o.skipped || []).length ? `<details class="skipped"><summary>${o.skipped.length} skipped quick-start step${o.skipped.length === 1 ? "" : "s"}</summary>${o.skipped.map((s) => `<div class="muted">${esc(s.title || s.action_id)} · ${esc(s.reason || s.status || "skipped")}</div>`).join("")}</details>` : "";
  return `<div class="run-panel ${okClass}">
    <div class="run-head"><span class="status-dot ${o.success ? "good" : "bad"}"></span>
      <div><b>${esc(title)}</b><div class="muted">${esc(o.message || "")}${o.duration_ms ? ` · ${o.duration_ms}ms` : ""}${o.returncode !== null && o.returncode !== undefined ? ` · rc ${o.returncode}` : ""}</div></div></div>
    ${o.command ? `<pre class="cmd run-cmd">$ ${esc(o.command)}</pre>` : ""}
    ${steps}${skipped}
    ${facts.length ? `<div class="run-facts"><div class="rp-label">Facts stored (${facts.length})</div><div class="fact-chip-grid compact">${facts.map(factChip).join("")}</div></div>` : `<div class="muted" style="margin-top:8px">No new facts were parsed and stored from this output.</div>`}
    ${preview}
    ${o.stdout_path || o.stderr_path ? `<div class="muted mono" style="font-size:11px;margin-top:8px">${o.stdout_path ? `stdout ${esc(o.stdout_path)}` : ""}${o.stderr_path ? ` · stderr ${esc(o.stderr_path)}` : ""}</div>` : ""}
  </div>`;
}

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
    if (state.view === "tools") { $("#crumb").textContent = "Tools"; return await renderTools(c); }
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
        <span class="spacer" style="flex:1"></span><button class="btn primary sm" data-quickstart="${esc(tg.host)}">Quick Start</button>
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
  c.querySelectorAll("[data-open]").forEach((el) => el.addEventListener("click", (e) => { if (e.target.closest("[data-quickstart]")) return; openTarget(el.dataset.open); }));
  wireQuickStart(c);
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
        <span class="pill">${(tg.open_ports || []).length} ports</span><span class="spacer" style="flex:1"></span><button class="btn primary sm" data-quickstart="${esc(tg.host)}">Quick Start</button></div></div>`;
  }).join("") || `<div class="empty">No targets yet.</div>`;
  c.innerHTML = `<div class="card"><div class="panel-h"><h2>Targets</h2><button class="btn sm primary" id="add-tgt">＋ Add target</button></div><div class="tgrid">${cards}</div></div>`;
  c.querySelectorAll("[data-open]").forEach((el) => el.addEventListener("click", (e) => { if (e.target.closest("[data-del],[data-quickstart]")) return; openTarget(el.dataset.open); }));
  c.querySelectorAll("[data-del]").forEach((b) => b.addEventListener("click", async (e) => {
    e.stopPropagation();
    if (confirm(`Remove target ${b.dataset.del}?`)) { await apiDelete(`/api/target?target=${encodeURIComponent(b.dataset.del)}`); render(); }
  }));
  $("#add-tgt").addEventListener("click", addTargetPrompt);
  wireQuickStart(c);
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
        <button class="btn primary sm" data-quickstart="${esc(b.meta.host)}">Quick Start</button>
        ${b.meta.active ? `<span class="pill" style="border-color:var(--green)66;color:var(--green)">active</span>` : `<button class="btn sm" id="mk-active">Make active</button>`}
      </div>
      ${chainBar(b.chain)}
      ${runStatusPanel(b.meta.host)}
    </div>
    <div class="tabbar">${tabs}</div>
    <div id="tabc"></div>`;
  $("#crumb-tgts").addEventListener("click", (e) => { e.preventDefault(); setView("targets"); });
  const mk = $("#mk-active"); if (mk) mk.addEventListener("click", async () => { await apiPost("/api/target/activate", { target: host }); render(); });
  c.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => { state.tab = t.dataset.tab; renderTarget(c); }));
  c.querySelectorAll("[data-chain]").forEach((seg) => seg.addEventListener("click", () => {
    state.tab = "overview"; renderTarget(c).then(() => { const el = document.getElementById("phase-" + seg.dataset.chain); if (el) el.scrollIntoView({ behavior: "smooth", block: "center" }); });
  }));
  wireQuickStart(c);
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
  const pc = PHASE_COLOR[a.phase] || "#6B7591";
  return `<div class="move" id="move-${esc(a.id)}">
    <div class="move-h"><span class="phase-tag" style="background:${pc}22;color:${pc};border:1px solid ${pc}55">${esc(a.phase)}</span>
      <span class="t">${esc(a.title)}</span><span class="spacer" style="flex:1"></span>
      <span class="muted mono" style="font-size:11px">${esc((a.tools || []).join(", "))}</span></div>
    ${a.desc ? `<div class="desc">${esc(a.desc)}</div>` : ""}
    ${variantRows(a, host)}</div>`;
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
      <div class="card"><div class="panel-h"><h2>Where we are</h2></div><div class="muted">Phase: <b style="color:var(--text)">${esc(PHASE_LABEL[b.phase] || b.phase)}</b> · Access: <b style="color:var(--text)">${esc((ACCESS[b.access] || {}).t || b.access)}</b></div><div class="muted" style="margin-top:6px">${b.next.length} live moves · ${b.findings.length} findings · ${b.facts_total || 0} facts</div></div>
    </div>
    <div class="card" style="margin-top:16px"><div class="panel-h"><h2>Useful facts</h2><span class="muted">operator memory and report source</span></div>${factsSummaryHtml(b.facts_summary)}</div>
    <div class="card" style="margin-top:16px"><div class="panel-h"><h2>Path</h2></div><div class="flow-scroll">${flowSVG(b.graph)}</div></div>
    <div class="card" style="margin-top:16px"><div class="panel-h"><h2>Next moves — run from here</h2><span class="muted mono">${b.next.length}</span></div>${groups}</div>`;
  wireRun(el, b.meta.host);
}

function tabTools(el, b) {
  const link = `<div class="card" style="display:flex;align-items:center;justify-content:space-between">
    <div class="muted">Service-aware tools for <b style="color:var(--text)">${esc(b.meta.label)}</b>, pre-filled and ready to run.</div>
    <button class="btn sm" id="all-tools">▸ All tools &amp; availability</button></div>`;
  const body = b.tools.length
    ? b.tools.map((grp) => `<div class="card"><div class="panel-h"><h2 style="color:${PHASE_COLOR[grp.phase]}">${esc(grp.label)}</h2><span class="muted mono">${grp.actions.length}</span></div>
        <div class="tool-grid">${grp.actions.map((a) => toolCard(a)).join("")}</div></div>`).join("")
    : `<div class="card"><div class="empty">No applicable tools yet — run the nmap prelude to learn this target's services.<br><button class="btn sm" style="margin-top:12px" id="all-tools2">Browse all tools</button></div></div>`;
  el.innerHTML = link + body;
  wireRun(el, b.meta.host);
  el.querySelectorAll("#all-tools,#all-tools2").forEach((x) => x.addEventListener("click", () => { state.toolTarget = b.meta.host; setView("tools"); }));
}

// ── global Tools page: system scan, availability, install/add, run any ───────
async function renderTools(c) {
  const [s, meta] = await Promise.all([api("/api/tools"), api("/api/meta")]);
  if (!state.toolTarget || !meta.targets.some((t) => t.host === state.toolTarget))
    state.toolTarget = meta.active_target || (meta.targets[0] && meta.targets[0].host) || "";
  const pct = s.total ? Math.round((s.found / s.total) * 100) : 0;
  const tgtOpts = meta.targets.map((t) => `<option value="${esc(t.host)}" ${t.host === state.toolTarget ? "selected" : ""}>${esc(t.label)} (${esc(t.host)})</option>`).join("") || `<option value="">no targets</option>`;
  const groups = s.groups.map((g) => `<div class="card"><div class="panel-h"><h2>${esc(g.category)}</h2><span class="muted mono">${g.tools.filter((t) => t.found).length}/${g.tools.length}</span></div>
    <div class="tool-grid">${g.tools.map(toolAvailCard).join("")}</div></div>`).join("");
  c.innerHTML = `
    <div class="card"><div class="row" style="justify-content:space-between;flex-wrap:wrap;gap:12px">
      <div><div style="font-size:22px;font-weight:750">${s.found} <span class="muted" style="font-size:16px">/ ${s.total} tools available</span></div>
        <div class="muted" style="font-size:12px">Found tools are guaranteed to run. Grey tools are missing — install or point O.B.O.L at them.</div>
        <div class="avail-bar" style="margin-top:8px"><div style="width:${pct}%"></div></div></div>
      <div class="row" style="gap:8px"><label class="muted" style="font-size:12px">run against</label>
        <select id="tool-target" class="inp">${tgtOpts}</select>
        <button class="btn sm" id="tool-rescan">↻ Rescan</button></div>
    </div></div>${groups}`;
  $("#tool-target").addEventListener("change", (e) => { state.toolTarget = e.target.value; });
  $("#tool-rescan").addEventListener("click", () => render());
  c.querySelectorAll("[data-install]").forEach((b) => b.addEventListener("click", () => installTool(b.dataset.install)));
  c.querySelectorAll("[data-copy]").forEach((b) => b.addEventListener("click", () => copyText(b.dataset.copy)));
  c.querySelectorAll("[data-addpath]").forEach((b) => b.addEventListener("click", () => addToolPath(b.dataset.addpath)));
  c.querySelectorAll("[data-toolrun]").forEach((b) => b.addEventListener("click", () => {
    if (!state.toolTarget) { toast("Pick a target first", "add a target to run tools against", "err"); return; }
    runAction(b.dataset.toolrun, state.toolTarget);
  }));
}

function toolAvailCard(t) {
  const runnable = t.found && t.actions.length;
  const actions = runnable ? `<div class="tool-actions">${t.actions.slice(0, 8).map((a) => `<div class="ta-row"><span class="ta-t">${esc(a.title)}</span>
      <button class="btn primary xs" data-toolrun="${esc(a.id)}">Run</button></div>`).join("")}</div>` : "";
  let foot = "";
  if (!t.found) {
    const install = t.install_cmd
      ? `<div class="install-row"><button class="btn primary sm" data-install="${esc(t.key)}">Install</button>
          <code class="inst-cmd">${esc(t.install_cmd)}</code><button class="btn xs" data-copy="${esc(t.install_cmd)}" title="copy">⧉</button></div>`
      : `<div class="muted" style="font-size:12px">${esc(t.note || "operator-supplied — add its path")}</div>`;
    foot = `${install}<div style="margin-top:7px"><button class="btn sm" data-addpath="${esc(t.key)}">I have it — add path…</button></div>`;
  }
  return `<div class="tool-card ${t.found ? "" : "missing"}">
    <div class="tc-h"><span class="tdot" style="background:${t.found ? "var(--green)" : "var(--muted)"}"></span>
      <span class="t">${esc(t.label)}</span><span class="spacer" style="flex:1"></span>
      ${t.found ? `<span class="pill" style="border-color:var(--green)66;color:var(--green)">found</span>` : `<span class="pill">missing</span>`}</div>
    ${t.found ? `<div class="tc-tools mono" title="${esc(t.path)}">${esc(t.path)}</div>` : ""}
    <div class="tc-tools mono muted">${(t.bins || []).slice(0, 3).join(", ")}${t.actions.length ? ` · ${t.actions.length} actions` : ""}</div>
    ${actions}${foot}</div>`;
}

async function installTool(key) {
  toast("Installing…", key, "");
  try {
    const r = await apiPost("/api/tools/install", { tool: key });
    if (r.ok) toast("Installed", `${key} → ${r.path}`, "ok");
    else toast("Install did not complete", `${r.command}\nCopy & run it in a terminal (sudo/network may be needed).`, "err");
    render();
  } catch (e) { toast("Install failed", e.message, "err"); }
}
async function addToolPath(key) {
  const path = prompt(`Absolute path to the ${key} binary/script:`);
  if (!path) return;
  try { const d = await apiPost("/api/tools/add", { tool: key, path }); toast("Added", `${key} → ${d.path}`, "ok"); render(); }
  catch (e) { toast("Could not add", e.message, "err"); }
}
function copyText(txt) {
  (navigator.clipboard ? navigator.clipboard.writeText(txt) : Promise.reject()).then(() => toast("Copied", txt, "ok")).catch(() => toast("Copy this", txt, ""));
}
function toolCard(a) {
  return `<div class="tool-card"><div class="tc-h"><span class="t">${esc(a.title)}</span></div>
    <div class="tc-tools mono">${esc((a.tools || []).join(", "))}</div>
    ${variantRows(a, state.target || "")}</div>`;
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
  $("#pb-detail").innerHTML = `<div class="panel-h" style="margin-top:16px"><h2>${esc(pb.title)} — steps</h2></div>${pb.steps.map((s) => {
    const p = s.preflight || {};
    return `<div class="move"><div class="move-h"><span class="phase-tag" style="background:var(--accent-soft);color:var(--accent-2)">step ${s.step}</span><span class="t">${esc(s.label)}</span>${s.require_approval ? `<span class="tag" style="background:#F9731622;color:#F97316">approval</span>` : ""}</div>
      <div style="margin-top:8px">${preflightBadges(p)}</div>
      <pre class="cmd">$ ${esc(s.command)}</pre>
      ${missingInputControls(p)}${preflightIssues(p)}
      <div class="row" style="margin-top:9px"><button class="btn primary sm" data-pbrun="${esc(pb.name)}" data-step="${s.step}" data-approval="${s.require_approval ? 1 : 0}" ${p.can_run ? "" : "disabled"}>Run step</button>
        <button class="btn sm" data-copycmd="${esc(s.command)}">${p.needs_handoff ? "Copy handoff" : "Copy"}</button></div></div>`;
  }).join("")}`;
  wireCommandControls($("#pb-detail"), host);
  $("#pb-detail").querySelectorAll("[data-pbrun]").forEach((btn) => btn.addEventListener("click", () => runPlaybookStep(btn.dataset.pbrun, +btn.dataset.step, btn.dataset.approval === "1", host)));
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

function wireCommandControls(el, host) {
  el.querySelectorAll("[data-copycmd]").forEach((b) => b.addEventListener("click", () => copyText(b.dataset.copycmd || "")));
  el.querySelectorAll("[data-setinput]").forEach((b) => b.addEventListener("click", () => setInput(host, b.dataset.setinput)));
}
function wireRun(el, host) {
  el.querySelectorAll("[data-run]").forEach((b) => b.addEventListener("click", () => runAction(b.dataset.run, host, +(b.dataset.cmd || 1))));
  wireCommandControls(el, host);
}
function wireQuickStart(el) {
  el.querySelectorAll("[data-quickstart]").forEach((b) => b.addEventListener("click", (e) => { e.preventDefault(); e.stopPropagation(); runQuickStart(b.dataset.quickstart); }));
}
async function setInput(host, key) {
  const value = prompt(`Value for ${key}:`);
  if (!value) return;
  try { await apiPost("/api/inputs", { target: host, inputs: { [key]: value } }); toast("Input saved", `${key} = ${value}`, "ok"); render(); }
  catch (e) { toast("Could not save input", e.message, "err"); }
}
async function runAction(actionId, host, cmdIndex) {
  state.lastRun = { target: host, pending: true, action_id: actionId };
  if (state.view === "target" && state.target === host) render();
  try {
    const o = await apiPost("/api/run/action", { action_id: actionId, target: host, cmd_index: cmdIndex || 1 });
    state.lastRun = { target: host, pending: false, outcome: o };
    if (!o.success) toast("Run failed", o.message || "command failed", "err");
    else if (o.added_count) toast("Ran " + o.tool, `+${o.added_count}: ${o.facts.map((f) => f.kind).join(", ")}`, "ok");
    else toast("Ran " + o.tool, "no new facts — raw output saved", "");
    render();
  } catch (e) {
    state.lastRun = { target: host, pending: false, error: e.message };
    toast("Run failed", e.message, "err");
    if (state.view === "target" && state.target === host) render();
  }
}
async function runQuickStart(host) {
  if (!host) return;
  state.lastRun = { target: host, pending: true, action_id: "Quick Start", quickstart: true };
  if (state.view === "target" && state.target === host) render();
  try {
    const o = await apiPost("/api/run/quickstart", { target: host });
    state.lastRun = { target: host, pending: false, outcome: o };
    if (o.success) toast("Quick Start complete", `ran ${o.steps.length} command(s), stored ${o.added_count} fact(s)`, "ok");
    else if (o.status === "partial") toast("Quick Start partially complete", o.message || "some commands failed or were skipped", "");
    else toast("Quick Start blocked", o.message || "no command could run", "err");
    render();
  } catch (e) {
    state.lastRun = { target: host, pending: false, error: e.message };
    toast("Quick Start failed", e.message, "err");
    if (state.view === "target" && state.target === host) render();
  }
}
async function runPlaybookStep(name, step, needsApproval, host) {
  if (needsApproval && !confirm(`Step ${step} is noisy/intrusive. Run it now?`)) return;
  state.lastRun = { target: host, pending: true, action_id: `${name} step ${step}` };
  if (state.view === "target" && state.target === host) render();
  try {
    const o = await apiPost("/api/run/playbook", { name, step, target: host, approve: needsApproval });
    state.lastRun = { target: host, pending: false, outcome: o };
    if (!o.success) toast(`Step ${step} failed`, o.message || "command failed", "err");
    else if (o.added_count) toast(`Ran step ${step}`, `+${o.added_count}: ${o.facts.map((f) => f.kind).join(", ")}`, "ok");
    else toast(`Ran step ${step}`, "no new facts — raw output saved", "");
    render();
  } catch (e) {
    state.lastRun = { target: host, pending: false, error: e.message };
    toast(e.status === 409 ? "Needs approval" : "Step failed", e.message, e.status === 409 ? "" : "err");
    if (state.view === "target" && state.target === host) render();
  }
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

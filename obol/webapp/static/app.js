/* obol web surface — single-page controller.
   One shared workspace state, mirrored live: every /api call carries the access
   token; an EventSource on /api/events pushes a tick whenever the .obol state file
   changes (from a web run OR a terminal run) and we re-render the current view. */
"use strict";

const TOKEN = new URLSearchParams(location.search).get("token") || "";
const PHASES = ["recon", "enum", "creds", "access", "escalate", "loot"];
const PHASE_LABEL = { recon: "Recon", enum: "Enumerate", creds: "Credentials",
  access: "Access", escalate: "Escalate", loot: "Loot / domain" };
const PHASE_COLOR = { recon: "#38BDF8", enum: "#818CF8", creds: "#F59E0B",
  access: "#34D399", escalate: "#F472B6", loot: "#A855F7" };
const SEV_COLOR = { critical: "#E11D48", high: "#F97316", medium: "#EAB308",
  low: "#3B82F6", info: "#6B7591" };
const CAT_COLOR = { target: "#38BDF8", scan: "#818CF8", service: "#22D3EE",
  ad: "#F472B6", credential: "#F59E0B", access: "#34D399", loot: "#A855F7",
  config: "#94A3B8", other: "#6B7591" };

const state = { view: "overview", findingFilter: "all", openPlaybook: null, secrets: false };
const charts = {};
const $ = (sel, el = document) => el.querySelector(sel);
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

// ── api ────────────────────────────────────────────────────────────────
async function api(path) {
  const r = await fetch(path, { headers: { "X-Obol-Token": TOKEN } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
  return r.json();
}
async function apiPost(path, body) {
  const r = await fetch(path, {
    method: "POST",
    headers: { "X-Obol-Token": TOKEN, "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) { const e = new Error(data.detail?.message || data.detail || `HTTP ${r.status}`); e.data = data; e.status = r.status; throw e; }
  return data;
}

// ── toasts + flash ──────────────────────────────────────────────────────
function toast(title, body, kind) {
  const el = document.createElement("div");
  el.className = "toast " + (kind || "");
  el.innerHTML = `<div class="th">${esc(title)}</div>${body ? `<div class="tb">${esc(body)}</div>` : ""}`;
  $("#toasts").appendChild(el);
  setTimeout(() => { el.style.opacity = "0"; setTimeout(() => el.remove(), 300); }, 5200);
}
function flash() { const f = $("#flash"); f.classList.add("show"); setTimeout(() => f.classList.remove("show"), 1200); }

// ── boot ────────────────────────────────────────────────────────────────
async function boot() {
  document.querySelectorAll(".nav-item").forEach((b) =>
    b.addEventListener("click", () => setView(b.dataset.view)));
  try {
    const meta = await api("/api/meta");
    $("#ws-name").textContent = meta.name || "obol";
    $("#ws-target").textContent = meta.target || "no target";
  } catch (e) {
    $("#content").innerHTML = `<div class="card"><div class="empty">Could not reach the workspace.<br><span class="muted">${esc(e.message)}</span></div></div>`;
    return;
  }
  connectEvents();
  render();
}
function setView(v) {
  state.view = v;
  document.querySelectorAll(".nav-item").forEach((b) => b.classList.toggle("active", b.dataset.view === v));
  render();
}

// ── real-time ─────────────────────────────────────────────────────────────
function connectEvents() {
  const dot = $("#conn-dot"), txt = $("#conn-text");
  const es = new EventSource(`/api/events?token=${encodeURIComponent(TOKEN)}`);
  es.addEventListener("hello", () => { dot.className = "dot live"; txt.textContent = "live"; });
  es.addEventListener("state", () => { flash(); render(); });
  es.onerror = () => { dot.className = "dot stale"; txt.textContent = "reconnecting…"; };
  es.onopen = () => { dot.className = "dot live"; txt.textContent = "live"; };
}

// ── router ────────────────────────────────────────────────────────────────
async function render() {
  const c = $("#content");
  const view = state.view;
  try {
    if (view === "overview") return await renderOverview(c);
    if (view === "flow") return await renderFlow(c);
    if (view === "findings") return await renderFindings(c);
    if (view === "playbooks") return await renderPlaybooks(c);
    if (view === "report") return await renderReport(c);
  } catch (e) {
    c.innerHTML = `<div class="card"><div class="empty">${esc(e.message)}</div></div>`;
  }
}
function destroyCharts() { Object.values(charts).forEach((ch) => ch && ch.destroy()); for (const k in charts) delete charts[k]; }

// ── overview ──────────────────────────────────────────────────────────────
async function renderOverview(c) {
  destroyCharts();
  const s = await api("/api/overview");
  const t = s.tiles;
  const tiles = [
    ["Facts proven", t.facts, ""],
    ["Open ports", t.ports, ""],
    ["Commands run", t.runs, ""],
  ].map(([l, v, sub]) => `<div class="stat"><div class="stat-label">${l}</div><div class="stat-val">${v}</div><div class="stat-sub">${sub}</div></div>`).join("");

  const ladder = s.access_ladder.map((seg) =>
    `<div class="ladder-seg ${seg.reached ? "on" : ""}"><div class="ladder-bar"></div><div class="ladder-lbl">${esc(seg.stage)}</div></div>`).join("");

  const catTotal = Object.values(s.category_counts).reduce((a, b) => a + b, 0);
  const sevTotal = Object.values(s.severity_counts).reduce((a, b) => a + b, 0);

  const feed = (s.activity || []).map((a) => `
    <div class="feed-item">
      <span class="feed-tick">${esc((a.at_display || "").slice(5, 16))}</span>
      <span class="feed-body"><span class="ft">${esc(a.tool)}</span>${a.playbook ? `<span class="tag">${esc(a.playbook)}</span>` : ""}
        <div class="fd">${esc(a.command)}</div>
        <div class="fd" style="color:var(--text-2)">${esc(a.status)}${a.produced?.length ? " · +" + a.produced.join(", ") : ""}</div>
      </span></div>`).join("") || `<div class="empty">No commands run yet.</div>`;

  c.innerHTML = `
    <div class="stat-grid">${tiles}
      <div class="stat"><div class="stat-label">Access</div><div class="stat-sub" style="font-size:14px;color:var(--text);margin-top:8px">${esc(t.access_state)}</div></div>
      <div class="stat"><div class="stat-label">Credentials</div><div class="stat-sub" style="font-size:14px;color:var(--text);margin-top:8px">${esc(t.credential_state)}</div></div>
    </div>
    <div class="card" style="margin-top:16px"><div class="panel-h"><h2>Engagement progress</h2><span class="muted mono" style="font-size:12px">${esc(s.meta.domain || s.meta.target || "")}</span></div><div class="ladder">${ladder}</div></div>
    <div class="grid-2" style="margin-top:16px">
      <div class="card"><div class="panel-h"><h2>Evidence by category</h2><span class="muted mono">${catTotal}</span></div>
        <div class="grid-2" style="grid-template-columns:200px 1fr;align-items:center">
          <div class="chart-wrap"><canvas id="catChart"></canvas></div>
          <div class="legend" id="catLegend"></div>
        </div></div>
      <div class="card"><div class="panel-h"><h2>Finding severity</h2><span class="muted mono">${sevTotal}</span></div>
        ${sevTotal ? `<div class="chart-wrap"><canvas id="sevChart"></canvas></div>`
          : `<div class="empty">No severity-rated findings yet.<br><span class="muted">Mapped from Orange cards as their facts are proven.</span></div>`}
      </div>
    </div>
    <div class="card" style="margin-top:16px"><div class="panel-h"><h2>Activity</h2></div><div class="feed">${feed}</div></div>`;

  drawDonut("catChart", s.category_counts, CAT_COLOR, "catLegend");
  if (sevTotal) drawSevBars("sevChart", s.severity_counts);
}

function drawDonut(canvasId, counts, colorMap, legendId) {
  const labels = Object.keys(counts);
  const el = document.getElementById(canvasId);
  if (!el) return;
  if (!labels.length) { el.parentElement.innerHTML = `<div class="empty">Nothing yet.</div>`; return; }
  const data = labels.map((k) => counts[k]);
  const colors = labels.map((k) => colorMap[k] || "#6B7591");
  charts[canvasId] = new Chart(el, {
    type: "doughnut",
    data: { labels, datasets: [{ data, backgroundColor: colors, borderColor: "#0D1220", borderWidth: 2 }] },
    options: { cutout: "62%", plugins: { legend: { display: false } }, maintainAspectRatio: false },
  });
  if (legendId) {
    $("#" + legendId).innerHTML = labels.map((k, i) =>
      `<div class="legend-row"><span class="sw" style="background:${colors[i]}"></span><span>${esc(k)}</span><span class="lg-n">${data[i]}</span></div>`).join("");
  }
}
function drawSevBars(canvasId, counts) {
  const known = ["critical", "high", "medium", "low", "info"];
  const order = [...known.filter((k) => counts[k]),
    ...Object.keys(counts).filter((k) => counts[k] && !known.includes(k))];
  const el = document.getElementById(canvasId);
  charts[canvasId] = new Chart(el, {
    type: "bar",
    data: { labels: order.map((k) => k[0].toUpperCase() + k.slice(1)),
      datasets: [{ data: order.map((k) => counts[k]), backgroundColor: order.map((k) => SEV_COLOR[k] || "#6B7591"), borderRadius: 5 }] },
    options: { plugins: { legend: { display: false } }, maintainAspectRatio: false,
      scales: { x: { grid: { display: false }, ticks: { color: "#B0B8C9" } },
        y: { beginAtZero: true, ticks: { precision: 0, color: "#6B7591" }, grid: { color: "#1E2940" } } } },
  });
}

// ── flow & next ─────────────────────────────────────────────────────────────
async function renderFlow(c) {
  const [g, nx] = await Promise.all([api("/api/graph"), api("/api/next")]);
  const legend = `<div class="flow-legend">
    <span class="flk"><span class="sw pill" style="background:var(--green)"></span>evidence proven</span>
    <span class="flk"><span class="sw pill ghost"></span>evidence still to find</span>
    <span class="flk"><span class="sw rect" style="background:#2b5d8a"></span>move done</span>
    <span class="flk"><span class="sw rect" style="background:var(--accent)"></span>move available now</span>
    <span class="flk muted">pill = evidence · box = move · column = phase (left → right)</span></div>`;

  const moves = nx.actions.length ? nx.actions.map(moveCard).join("") :
    `<div class="empty">No live moves — every unlocked action is done.</div>`;

  c.innerHTML = `
    <div class="card"><div class="panel-h"><h2>Path &amp; live moves</h2></div>
      ${legend}<div class="flow-scroll">${flowSVG(g)}</div></div>
    <div class="card" style="margin-top:16px"><div class="panel-h"><h2>Next moves — run from here</h2><span class="muted mono">${nx.actions.length}</span></div>
      <div id="moves">${moves}</div></div>`;

  c.querySelectorAll("[data-run]").forEach((b) => b.addEventListener("click", () => runAction(b.dataset.run, +b.dataset.cmd || 1, b.dataset.dry === "1")));
  c.querySelectorAll("[data-node-action]").forEach((n) => n.addEventListener("click", () => {
    const card = document.getElementById("move-" + n.dataset.nodeAction);
    if (card) { card.scrollIntoView({ behavior: "smooth", block: "center" }); card.animate([{ background: "var(--accent-soft)" }, { background: "var(--bg2)" }], { duration: 1200 }); }
  }));
}

function moveCard(a) {
  const v = a.variants[0];
  const pc = PHASE_COLOR[a.phase] || "#6B7591";
  return `<div class="move" id="move-${esc(a.id)}">
    <div class="move-h">
      <span class="phase-tag" style="background:${pc}22;color:${pc};border:1px solid ${pc}55">${esc(a.phase)}</span>
      <span class="t">${esc(a.title)}</span>
      <span class="spacer" style="flex:1"></span>
      <span class="muted mono" style="font-size:11px">${esc((a.tools || []).join(", "))}</span>
    </div>
    ${a.desc ? `<div class="desc">${esc(a.desc)}</div>` : ""}
    ${v ? `<pre class="cmd">$ ${esc(v.command)}</pre>` : ""}
    <div class="row" style="margin-top:11px">
      <button class="btn primary sm" data-run="${esc(a.id)}" data-cmd="1">Run</button>
      <button class="btn sm" data-run="${esc(a.id)}" data-cmd="1" data-dry="1">Dry-run</button>
    </div></div>`;
}

function flowSVG(g) {
  const byPhase = {};
  PHASES.forEach((p) => (byPhase[p] = []));
  g.nodes.forEach((n) => (byPhase[n.phase] || (byPhase[n.phase] = [])).push(n));
  const cols = PHASES.filter((p) => byPhase[p] && byPhase[p].length);
  if (!cols.length) return `<div class="empty">Nothing on the path yet — run a scan.</div>`;

  // Geometry. Nodes are foreignObject cards so labels wrap/ellipsis inside the box
  // (no SVG text overflow) and the whole column fits a fixed width.
  const NW = 178, NH = 42, COLW = 214, ROW = 56, PADX = 22, PADY = 46;
  const pos = {};
  cols.forEach((p, ci) => {
    byPhase[p].forEach((n, ri) => {
      pos[n.id] = { x: PADX + ci * COLW, y: PADY + ri * ROW, w: NW, h: NH, node: n };
    });
  });
  const height = PADY + Math.max(...cols.map((p) => byPhase[p].length)) * ROW + 14;
  const width = PADX * 2 + (cols.length - 1) * COLW + NW;

  // Edges: solid when the evidence is already in hand, dashed toward evidence not
  // yet found (a "this move will turn that up" hint).
  let edges = "";
  g.edges.forEach((e) => {
    const a = pos[e.from], b = pos[e.to];
    if (!a || !b) return;
    const x1 = a.x + a.w, y1 = a.y + a.h / 2, x2 = b.x, y2 = b.y + b.h / 2;
    const mx = (x1 + x2) / 2;
    const future = b.node.type === "fact" && b.node.state === "future";
    edges += `<path d="M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}" fill="none" ` +
      `stroke="${future ? "#3D4D75" : "#4b5a86"}" stroke-width="1.5"${future ? ' stroke-dasharray="4 4"' : ""}/>`;
  });

  const headers = cols.map((p, ci) =>
    `<text x="${PADX + ci * COLW + NW / 2}" y="24" text-anchor="middle" fill="${PHASE_COLOR[p]}" font-size="11" font-weight="700" letter-spacing="1.2">${PHASE_LABEL[p].toUpperCase()}</text>` +
    `<line x1="${PADX + ci * COLW}" y1="32" x2="${PADX + ci * COLW + NW}" y2="32" stroke="${PHASE_COLOR[p]}" stroke-opacity="0.35" stroke-width="1.5"/>`).join("");

  let nodes = "";
  Object.values(pos).forEach(({ x, y, w, h, node }) => {
    const isFact = node.type === "fact";
    const cls = isFact ? `fnode fact ${node.state}` : `fnode action ${node.state}`;
    const clickable = !isFact && node.state === "next";
    const attrs = clickable ? ` data-node-action="${esc(node.action_id)}" style="cursor:pointer"` : "";
    nodes += `<foreignObject x="${x}" y="${y}" width="${w}" height="${h}"${attrs}>` +
      `<div xmlns="http://www.w3.org/1999/xhtml" class="${cls}" title="${esc(node.label)}">` +
      `<span>${esc(node.label)}</span></div></foreignObject>`;
  });

  return `<svg class="flow" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" preserveAspectRatio="xMinYMin meet">${headers}${edges}${nodes}</svg>`;
}

// ── findings ──────────────────────────────────────────────────────────────
async function renderFindings(c) {
  const { findings } = await api("/api/findings");
  const cats = ["all", ...Array.from(new Set(findings.map((f) => f.category)))];
  const chips = cats.map((cat) =>
    `<button class="chip ${state.findingFilter === cat ? "active" : ""}" data-cat="${esc(cat)}">${esc(cat)}${cat !== "all" ? ` · ${findings.filter((f) => f.category === cat).length}` : ` · ${findings.length}`}</button>`).join("");
  const rows = findings.filter((f) => state.findingFilter === "all" || f.category === state.findingFilter).map((f) => `
    <tr>
      <td class="kind">${esc(f.kind)}</td>
      <td><div>${esc(f.label)}</div>${Object.keys(f.value || {}).length ? `<div class="fd muted mono" style="font-size:11px">${esc(JSON.stringify(f.value))}</div>` : ""}</td>
      <td><span class="cat-chip" style="border-color:${(CAT_COLOR[f.category] || "#6B7591")}66;color:${CAT_COLOR[f.category] || "#B0B8C9"}">${esc(f.category)}</span></td>
      <td class="mono muted" style="font-size:11px">${esc(f.scope)}</td>
      <td class="mono muted" style="font-size:11px;max-width:280px;word-break:break-all">${esc(f.evidence)}</td>
    </tr>`).join("") || `<tr><td colspan="5"><div class="empty">No facts in this category.</div></td></tr>`;

  c.innerHTML = `<div class="card"><div class="panel-h"><h2>Evidence-backed facts</h2><span class="muted mono">${findings.length}</span></div>
    <div class="chips">${chips}</div>
    <table><thead><tr><th>Kind</th><th>Finding</th><th>Category</th><th>Scope</th><th>Evidence</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  c.querySelectorAll(".chip").forEach((b) => b.addEventListener("click", () => { state.findingFilter = b.dataset.cat; renderFindings(c); }));
}

// ── playbooks ───────────────────────────────────────────────────────────────
async function renderPlaybooks(c) {
  const { playbooks } = await api("/api/playbooks");
  if (state.openPlaybook) {
    let pb;
    try { pb = await api(`/api/playbook/${encodeURIComponent(state.openPlaybook)}`); }
    catch (e) { state.openPlaybook = null; return renderPlaybooks(c); }
    const steps = pb.steps.map((s) => `
      <div class="move" id="pb-step-${s.step}">
        <div class="move-h"><span class="phase-tag" style="background:var(--accent-soft);color:var(--accent-2)">step ${s.step}</span>
          <span class="t">${esc(s.label)}</span>${s.require_approval ? `<span class="tag" style="background:#F9731622;color:#F97316">approval</span>` : ""}
          <span class="spacer" style="flex:1"></span><span class="muted mono" style="font-size:11px">${esc(s.action_id)}</span></div>
        ${s.note ? `<div class="desc">${esc(s.note)}</div>` : ""}
        <pre class="cmd">$ ${esc(s.command)}</pre>
        <div class="row" style="margin-top:11px">
          <button class="btn primary sm" data-pb="${esc(pb.name)}" data-step="${s.step}" data-approval="${s.require_approval ? 1 : 0}">Run step</button>
          <button class="btn sm" data-pb="${esc(pb.name)}" data-step="${s.step}" data-dry="1">Dry-run</button>
        </div></div>`).join("");
    c.innerHTML = `<div class="card"><div class="row" style="justify-content:space-between"><div><h2 style="margin:0">${esc(pb.title)}</h2><div class="muted" style="margin-top:3px">${esc(pb.description || "")}</div></div><button class="btn ghost sm" id="pb-back">← all playbooks</button></div></div>
      <div class="card" style="margin-top:16px"><div class="panel-h"><h2>Steps</h2><span class="muted mono">${pb.steps.length}</span></div>${steps}</div>`;
    $("#pb-back").addEventListener("click", () => { state.openPlaybook = null; renderPlaybooks(c); });
    c.querySelectorAll("[data-pb]").forEach((b) => b.addEventListener("click", () =>
      runPlaybookStep(b.dataset.pb, +b.dataset.step, b.dataset.dry === "1", b.dataset.approval === "1")));
    return;
  }
  const list = playbooks.length ? playbooks.map((pb) => `
    <div class="move" data-open="${esc(pb.name)}" style="cursor:pointer">
      <div class="move-h"><span class="t">${esc(pb.title)}</span><span class="spacer" style="flex:1"></span><span class="muted mono" style="font-size:11px">${esc(pb.name)}</span></div>
      ${pb.description ? `<div class="desc">${esc(pb.description)}</div>` : ""}</div>`).join("") : `<div class="empty">No playbooks available.</div>`;
  c.innerHTML = `<div class="card"><div class="panel-h"><h2>Playbooks</h2><span class="muted mono">${playbooks.length}</span></div>
    <div class="muted" style="margin-bottom:12px">Named, ordered action sequences — run a step through the same runner as the terminal. Steps marked <span class="tag" style="background:#F9731622;color:#F97316">approval</span> confirm before running.</div>${list}</div>`;
  c.querySelectorAll("[data-open]").forEach((el) => el.addEventListener("click", () => { state.openPlaybook = el.dataset.open; renderPlaybooks(c); }));
}

// ── report ──────────────────────────────────────────────────────────────────
async function renderReport(c) {
  const r = await api(`/api/report?include_secrets=${state.secrets ? "1" : "0"}`);
  const m = r.meta, t = r.tiles;
  const statRow = [
    ["Target", esc(m.target || "—")], ["Facts", t.facts], ["Ports", t.ports],
    ["Commands", t.runs], ["Domain", esc(m.domain || "—")],
  ].map(([l, v]) => `<div class="stat"><div class="stat-label">${l}</div><div class="stat-val" style="font-size:20px">${v}</div></div>`).join("");

  const ladder = r.access_ladder.map((seg) =>
    `<div class="ladder-seg ${seg.reached ? "on" : ""}"><div class="ladder-bar"></div><div class="ladder-lbl">${esc(seg.stage)}</div></div>`).join("");

  const byCat = {};
  r.facts.forEach((f) => (byCat[f.category] = byCat[f.category] || []).push(f));
  const findingSections = Object.keys(byCat).map((cat) => `
    <div class="report-section-title">${esc(cat)} · ${byCat[cat].length}</div>
    <table><tbody>${byCat[cat].map((f) => `<tr><td class="kind">${esc(f.kind)}</td><td>${esc(f.label)}${Object.keys(f.value || {}).length ? ` <span class="muted mono" style="font-size:11px">${esc(JSON.stringify(f.value))}</span>` : ""}<div class="muted mono" style="font-size:11px">evidence: ${esc(f.evidence)}</div></td></tr>`).join("")}</tbody></table>`).join("");

  const timeline = r.timeline.length ? r.timeline.map((row) => `
    <div class="feed-item"><span class="feed-tick">${esc((row.at_display || "").slice(5, 16))}</span>
      <span class="feed-body"><span class="ft">${esc(row.tool)}</span>${row.playbook ? `<span class="tag">${esc(row.playbook)}</span>` : ""}
        <div class="fd">$ ${esc(row.command)}</div>
        <div class="fd" style="color:var(--text-2)">${esc(row.status)}${row.produced.length ? " · +" + row.produced.join(", ") : " · no new facts"}</div></span></div>`).join("") : `<div class="empty">No commands recorded.</div>`;

  const nextList = r.next_actions.length ? r.next_actions.map((a) => `<li><b>${esc(a.title)}</b>${a.desc ? ` — <span class="muted">${esc(a.desc)}</span>` : ""}${a.report?.severity ? ` <span class="sev-badge" style="background:${SEV_COLOR[String(a.report.severity).toLowerCase()] || "#6B7591"}22;color:${SEV_COLOR[String(a.report.severity).toLowerCase()] || "#B0B8C9"}">${esc(a.report.severity)}</span>` : ""}</li>`).join("") : "<li class='muted'>None queued.</li>";

  c.innerHTML = `
    <div class="card">
      <div class="report-head"><h2>${esc(m.name)}</h2><span class="muted">OSCP-style evidence report</span><span class="spacer" style="flex:1"></span>
        <label class="pill" style="cursor:pointer"><input type="checkbox" id="sec-toggle" ${state.secrets ? "checked" : ""} style="margin-right:6px">include secrets</label>
        <a class="btn sm primary" href="/api/report.md?include_secrets=${state.secrets ? "1" : "0"}&token=${encodeURIComponent(TOKEN)}">Download .md</a></div>
      <div class="muted" style="margin-top:6px">Generated ${esc(m.generated_at)} · ${m.include_secrets ? "secrets shown" : "secrets redacted"} · every finding is only as strong as its cited evidence.</div>
      <div class="stat-grid" style="margin-top:16px">${statRow}</div>
    </div>
    <div class="card"><div class="panel-h"><h2>Engagement progress</h2></div><div class="ladder">${ladder}</div></div>
    <div class="card"><div class="panel-h"><h2>Path</h2></div><div class="flow-scroll">${flowSVG(r.graph)}</div></div>
    <div class="card"><div class="panel-h"><h2>Recommended next</h2></div><ul style="margin:0;padding-left:18px;line-height:1.9">${nextList}</ul></div>
    <div class="card"><div class="panel-h"><h2>Evidence-backed findings</h2><span class="muted mono">${r.facts.length}</span></div>${findingSections || '<div class="empty">No facts yet.</div>'}</div>
    <div class="card"><div class="panel-h"><h2>Activity timeline</h2></div><div class="feed">${timeline}</div></div>`;

  $("#sec-toggle").addEventListener("change", (e) => { state.secrets = e.target.checked; renderReport(c); });
}

// ── run-from-site ─────────────────────────────────────────────────────────
async function runAction(actionId, cmdIndex, dry) {
  try {
    const o = await apiPost("/api/run/action", { action_id: actionId, cmd_index: cmdIndex, dry_run: dry });
    if (o.dry_run) toast("Dry-run", `${o.command}\n(not executed)`, "ok");
    else if (o.added_count) toast("Ran " + o.tool, `+${o.added_count} fact(s): ${o.added.map((f) => f.kind).join(", ")}`, "ok");
    else toast("Ran " + o.tool, "no new facts — raw output saved", "");
  } catch (e) { toast("Run failed", e.message, "err"); }
}
async function runPlaybookStep(name, step, dry, needsApproval) {
  if (needsApproval && !dry && !confirm(`Step ${step} is noisy/intrusive. Run it now?`)) return;
  try {
    const o = await apiPost("/api/run/playbook", { name, step, dry_run: dry, approve: needsApproval });
    if (o.dry_run) toast(`Dry-run · step ${step}`, `${o.command}\n(not executed)`, "ok");
    else if (o.added_count) toast(`Ran step ${step}`, `+${o.added_count} fact(s): ${o.added.map((f) => f.kind).join(", ")}`, "ok");
    else toast(`Ran step ${step}`, "no new facts — raw output saved", "");
  } catch (e) {
    if (e.status === 409) toast("Needs approval", e.data?.detail?.message || "confirm to run", "err");
    else toast("Step failed", e.message, "err");
  }
}

boot();

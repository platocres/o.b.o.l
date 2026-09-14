/*
 * import_orange_web.js — provenance / regeneration tool (not run at obol runtime).
 *
 * Converts the web lane of the prior obol project's methodology data into obol's
 * fact-gated Action pack schema. Companion to import_orange_ad.js; the source
 * cards are derived from the Orange Cyberdefense 2025.03 mind map (pinned upstream
 * commit 6d16ca0d1434875e0617f2f3cfa825fad0bc7d7e). The resulting pack is a
 * distinct, attributed component — see obol/packs/NOTICE.md.
 *
 * Usage:  node scripts/import_orange_web.js /path/to/old-obol/data/lanes.js > obol/packs/orange_web_2025_03.json
 *
 * Two deliberate transformations keep the pack honest and interoperable:
 *   1. Fact-kind REMAP onto the shared obol namespace, so cross-domain gating
 *      works: the old web lane's `web.reachable` is obol's `http.reachable`
 *      (produced by the nmap parser), and a caught web reverse shell is the
 *      OS-agnostic `access.shell`. Applied to BOTH produces and prereqs.
 *   2. A small, documented set of per-card prereq/produce fixes (see PREREQ_ADD
 *      and PRODUCE_FIX) so the shared namespace does not silently widen a claim
 *      (a WordPress user enum is `web.users`, NOT the AD `ad.user_list`) and so
 *      recon cards actually unlock after content discovery.
 *
 * proves / does_not_prove are DERIVED conservatively from the produced fact kinds;
 * the full reasoning stays in `hypothesis` and per-command `note`s.
 */
const fs = require("fs");

const src = process.argv[2] || "/home/user/platocres/obol/data/lanes.js";
global.window = global;
eval(fs.readFileSync(src, "utf8"));
const web = (global.OBOL_LANES || []).find((l) => l.lane === "web");
if (!web) { console.error("no web lane found in", src); process.exit(1); }

// 1. Fact-kind remap onto the shared obol namespace (AGENTS.md fact-kind namespace).
const REMAP = {
  "web.reachable": "http.reachable", // nmap parser produces http.reachable for web ports
  "shell.reverse": "access.shell",   // OS-agnostic interactive shell
};
const remap = (k) => REMAP[k] || k;

// 2a. Per-card produce fixes: keep each claim to the narrowest supported fact.
const PRODUCE_FIX = {
  // WPScan enumerates the application's own users, not the AD domain user list —
  // producing ad.user_list here would falsely unlock the AS-REP / Kerberos chain.
  wordpress: (produces) => produces.map((p) => (p === "ad.user_list" ? "web.users" : p)),
};

// 2b. Per-card prereq additions so recon cards are reachable in obol's model.
// The old lane assumed a human-set `web.parameterized`/`web.upload_form`; obol has
// no producer for those, so these cards would be permanently dead. Unlocking them
// after content discovery (or bare HTTP reachability) matches the methodology
// ("probe the parameters/forms you found") without fabricating a box win.
const PREREQ_ADD = {
  "sqli-basics": ["web.content_map"],
  idor: ["web.content_map"],
  "file-upload": ["http.reachable"],
};

// Priority: recon spine first (high overrides), everything else by produced value.
const WEIGHT = [
  [["access.admin"], 82],
  [["foothold.webshell", "foothold.linux", "foothold.windows", "access.shell"], 80],
  [["credential.plaintext", "db.creds"], 76],
  [["credential.candidate", "loot.files", "cloud.aws_access", "web.users"], 66],
  [["web.sqli_confirmed", "web.cmdi_confirmed", "web.lfi_confirmed", "web.ssrf_confirmed", "web.upload_confirmed"], 60],
  [["web.content_map", "web.vhost", "web.source", "exploit.candidate"], 55],
];
function priority(produces) {
  let best = 50;
  for (const [kinds, w] of WEIGHT)
    if (produces.some((p) => kinds.includes(p))) best = Math.max(best, w);
  return best;
}
function actionPriority(id, produces) {
  const override = {
    "content-discovery": 90,
    "nikto-scan": 88,
    "vhost-discovery": 86,
    "git-exposed": 84,
    "svn-exposed": 83,
  };
  return override[id] || priority(produces);
}

function doesNotProve(produces) {
  const has = (k) => produces.includes(k);
  const confirmed = produces.some((p) => p.endsWith("_confirmed"));
  if (has("access.admin"))
    return "administrative access in the application context — not an OS shell or system privilege unless separately proven";
  if (has("foothold.webshell") || has("access.shell") || has("foothold.linux") || has("foothold.windows"))
    return "code execution in the web/app context — not elevated privilege";
  if (has("credential.plaintext") || has("db.creds"))
    return "recovered credential material — not access until it authenticates against a service";
  if (has("credential.candidate") || has("web.users"))
    return "candidate material only — not a validated credential, and not access";
  if (confirmed)
    return "a confirmed injection point — not yet code execution, data, or access until exploited";
  if (has("web.content_map") || has("web.vhost") || has("web.source") || has("exploit.candidate"))
    return "discovered attack surface — not a vulnerability, credential, or access";
  return "enumeration/context only — no access, credential, or privilege";
}

const FRIENDLY = {
  "http.reachable": "HTTP is reachable",
  "web.content_map": "a map of discovered web content",
  "web.vhost": "a discovered virtual host",
  "web.source": "exposed application source",
  "web.parameterized": "a parameterized web endpoint",
  "web.authenticated": "authenticated web access",
  "web.upload_form": "a file-upload form",
  "web.upload_confirmed": "a confirmed file upload",
  "web.lfi_confirmed": "a confirmed local file inclusion",
  "web.sqli_confirmed": "a confirmed SQL injection",
  "web.cmdi_confirmed": "a confirmed command injection",
  "web.ssrf_confirmed": "a confirmed SSRF",
  "web.users": "enumerated application users",
  "foothold.webshell": "a web shell",
  "foothold.linux": "a Linux foothold", "foothold.windows": "a Windows foothold",
  "access.shell": "an interactive shell", "access.admin": "administrative access",
  "db.creds": "database credentials", "loot.files": "recovered files",
  "cloud.aws_access": "AWS cloud access", "exploit.candidate": "a candidate exploit",
  "credential.candidate": "candidate credentials", "credential.plaintext": "a plaintext password",
};
const friendly = (k) => FRIENDLY[k] || k;

const actions = web.cards.map((c) => {
  let produces = (c.produces || []).map(remap);
  if (PRODUCE_FIX[c.id]) produces = PRODUCE_FIX[c.id](produces);
  produces = [...new Set(produces)];

  const requiresAll = ((c.prereq && c.prereq.all) || []).map(remap);
  let requiresAny = ((c.prereq && c.prereq.any) || []).map(remap);
  for (const extra of PREREQ_ADD[c.id] || [])
    if (!requiresAny.includes(extra)) requiresAny.push(extra);
  requiresAny = [...new Set(requiresAny)];

  const cmds = (c.commands || []).map((cmd) => ({
    tool: cmd.tool || "", run: cmd.run || "", note: cmd.note || "",
  }));
  return {
    id: c.id,
    title: c.title,
    hypothesis: c.hypothesis || "",
    tool: (c.tools && c.tools[0]) || (cmds[0] && cmds[0].tool) || "",
    tools: c.tools || [],
    os: c.os || [],
    requires_all: [...new Set(requiresAll)],
    requires_any: requiresAny,
    produces,
    priority: actionPriority(c.id, produces),
    proves: produces.length ? "establishes " + produces.map(friendly).join(", ") : "",
    does_not_prove: doesNotProve(produces),
    report: c.report || null,
    refs: c.refs || [],
    commands: cmds,
  };
});

process.stdout.write(JSON.stringify({
  id: "orange_web_2025_03",
  title: "Web (Orange Cyberdefense 2025.03)",
  source: "Orange Cyberdefense ocd-mindmaps web 2025.03",
  upstream_commit: "6d16ca0d1434875e0617f2f3cfa825fad0bc7d7e",
  license: "GPL-3.0 (methodology data); see obol/packs/NOTICE.md",
  actions,
}, null, 1) + "\n");
console.error(`converted ${actions.length} web actions`);

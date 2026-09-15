/*
 * import_orange_privesc.js — provenance / regeneration tool (not run at obol runtime).
 *
 * Converts the linux-privesc or windows-privesc lane of the prior obol project's
 * methodology data into obol's fact-gated Action pack schema. Companion to the AD
 * and web importers; the source cards are derived from the Orange Cyberdefense
 * 2025.03 mind map (pinned upstream commit 6d16ca0d1434875e0617f2f3cfa825fad0bc7d7e).
 *
 * Usage:
 *   node scripts/import_orange_privesc.js /path/to/old-obol/data/lanes.js linux-privesc > obol/packs/orange_linux_privesc_2025_03.json
 *   node scripts/import_orange_privesc.js /path/to/old-obol/data/lanes.js windows-privesc > obol/packs/orange_windows_privesc_2025_03.json
 *
 * Deliberate transformations:
 *   1. access.root -> access.admin, persist.* -> persistence.* so the packs reuse
 *      obol's shared namespace.
 *   2. Post-foothold local enum cards are first. Specific abuse cards are gated by
 *      the lead facts parsers can prove (e.g. privesc.sudo_rights), so a foothold
 *      alone does not flood the user with every exploit-shaped branch.
 *   3. proves / does_not_prove are derived conservatively from produced fact kinds.
 */
const fs = require("fs");

const src = process.argv[2] || "/home/user/platocres/obol/data/lanes.js";
const laneName = process.argv[3] || "";
if (!["linux-privesc", "windows-privesc"].includes(laneName)) {
  console.error("usage: node scripts/import_orange_privesc.js <lanes.js> <linux-privesc|windows-privesc>");
  process.exit(1);
}

global.window = global;
eval(fs.readFileSync(src, "utf8"));
const lane = (global.OBOL_LANES || []).find((l) => l.lane === laneName);
if (!lane) {
  console.error("no lane found:", laneName, "in", src);
  process.exit(1);
}

const PACK_META = {
  "linux-privesc": {
    id: "orange_linux_privesc_2025_03",
    title: "Linux Privilege Escalation (Orange Cyberdefense 2025.03)",
  },
  "windows-privesc": {
    id: "orange_windows_privesc_2025_03",
    title: "Windows Privilege Escalation (Orange Cyberdefense 2025.03)",
  },
};

const REMAP = {
  "access.root": "access.admin",
  "persist.linux": "persistence.linux",
  "persist.windows": "persistence.windows",
  "ad.tickets": "kerberos.tickets",
};
const remap = (kind) => REMAP[kind] || kind;

const PRODUCE_FIX = {
  "linux-enum": () => ["privesc.leads", "host.kernel", "host.arch"],
  "pspy-monitor": () => ["privesc.process_lead", "credential.candidate"],
  "windows-enum": () => ["privesc.leads", "host.kernel", "host.arch"],
  "stored-credentials": (produces) => [...produces, "privesc.stored_credentials"],
  "wesng-patch-gaps": () => ["exploit.candidate", "privesc.patch_gap"],
};

const REQUIRE_FIX = {
  "sudo-abuse": { any: ["privesc.sudo_rights"] },
  "writable-passwd": { any: ["privesc.passwd_writable"] },
  "nfs-squash": { any: ["privesc.nfs_no_root_squash", "port:2049"] },
  "lxc-lxd-escape": { any: ["privesc.lxd_group"] },
  "docker-socket": { any: ["privesc.docker_group"] },
  "suid-gtfobins": { any: ["privesc.suid_candidate"] },
  "cron-abuse": { any: ["privesc.cron_writable", "privesc.process_lead"] },
  "capabilities": { any: ["privesc.capability"] },
  "seimpersonate": { any: ["privesc.windows_privilege"] },
  "unquoted-service-path": { any: ["privesc.unquoted_service_path"] },
  "weak-service-permissions": { any: ["privesc.weak_service_permission"] },
  "alwaysinstallelevated": { any: ["privesc.always_install_elevated"] },
};

const REQUIRE_ADD = {
  "pspy-monitor": { any: ["privesc.leads"] },
  "linux-loot-hunt": { any: ["privesc.leads"] },
};

const PRIORITY = {
  "linux-enum": 94,
  "windows-enum": 94,
  "linux-loot-hunt": 82,
  "stored-credentials": 82,
  "sudo-abuse": 80,
  "seimpersonate": 80,
  "suid-gtfobins": 78,
  "capabilities": 78,
  "alwaysinstallelevated": 78,
  "weak-service-permissions": 76,
  "unquoted-service-path": 76,
  "pspy-monitor": 72,
  "wesng-patch-gaps": 70,
};

const FRIENDLY = {
  "host.kernel": "host kernel/version",
  "host.arch": "host architecture",
  "privesc.leads": "local privilege escalation leads",
  "privesc.sudo_rights": "sudo rights lead",
  "privesc.suid_candidate": "SUID/SGID candidate",
  "privesc.capability": "dangerous Linux capability",
  "privesc.cron_writable": "writable scheduled task or cron lead",
  "privesc.process_lead": "process-monitoring privesc lead",
  "privesc.passwd_writable": "writable /etc/passwd lead",
  "privesc.nfs_no_root_squash": "NFS no_root_squash lead",
  "privesc.lxd_group": "LXD group escape lead",
  "privesc.docker_group": "Docker socket/group escape lead",
  "privesc.windows_privilege": "dangerous Windows privilege",
  "privesc.always_install_elevated": "AlwaysInstallElevated lead",
  "privesc.unquoted_service_path": "unquoted service path lead",
  "privesc.weak_service_permission": "weak service permission lead",
  "privesc.stored_credentials": "stored Windows credential lead",
  "privesc.patch_gap": "missing-patch privesc lead",
  "access.admin": "administrative/root access",
  "access.system": "SYSTEM access",
  "credential.candidate": "candidate credentials",
  "credential.plaintext": "a plaintext password",
  "hash.ntlm": "NTLM hashes",
  "kerberos.tickets": "Kerberos tickets",
  "loot.files": "recovered files",
  "exploit.candidate": "a candidate exploit",
  "persistence.linux": "Linux persistence",
  "persistence.windows": "Windows persistence",
};
const friendly = (kind) => FRIENDLY[kind] || kind;

function unique(items) {
  return [...new Set((items || []).filter(Boolean))];
}

function fixedProduces(card) {
  let produces = (card.produces || []).map(remap);
  if (PRODUCE_FIX[card.id]) produces = PRODUCE_FIX[card.id](produces);
  return unique(produces);
}

function fixedRequires(card) {
  let all = ((card.prereq && card.prereq.all) || []).map(remap);
  let any = ((card.prereq && card.prereq.any) || []).map(remap);
  const replace = REQUIRE_FIX[card.id];
  if (replace) {
    all = (replace.all || []).map(remap);
    any = (replace.any || []).map(remap);
  }
  const add = REQUIRE_ADD[card.id] || {};
  all = unique([...all, ...((add.all || []).map(remap))]);
  any = unique([...any, ...((add.any || []).map(remap))]);
  return { all, any };
}

function actionPriority(card, produces) {
  if (PRIORITY[card.id]) return PRIORITY[card.id];
  if (produces.some((p) => ["access.system", "access.admin"].includes(p))) return 74;
  if (produces.some((p) => p.startsWith("privesc."))) return 68;
  if (produces.some((p) => p.startsWith("credential."))) return 66;
  return 50;
}

function doesNotProve(produces) {
  const has = (kind) => produces.includes(kind);
  if (has("access.system"))
    return "SYSTEM only when command output proves it; a privilege or service lead alone is not SYSTEM";
  if (has("access.admin"))
    return "root/admin only when command output proves it; discovered local leads alone are not privileged access";
  if (produces.some((p) => p.startsWith("privesc.")))
    return "local privilege escalation lead only — not admin/root/SYSTEM until separately proven";
  if (has("credential.plaintext") || has("credential.candidate"))
    return "credential material only — not access until it authenticates against a service";
  if (has("hash.ntlm") || has("kerberos.tickets"))
    return "dumped credential material — not plaintext or access by itself";
  if (has("persistence.linux") || has("persistence.windows"))
    return "persistence setup context — document and clean up; not a new privilege level";
  return "post-foothold enumeration context only";
}

const actions = lane.cards.map((card) => {
  const produces = fixedProduces(card);
  const requires = fixedRequires(card);
  const commands = (card.commands || []).map((cmd) => ({
    tool: cmd.tool || "",
    run: cmd.run || "",
    note: cmd.note || "",
  }));
  return {
    id: card.id,
    title: card.title,
    hypothesis: card.hypothesis || "",
    tool: (card.tools && card.tools[0]) || (commands[0] && commands[0].tool) || "",
    tools: card.tools || [],
    os: card.os || [],
    requires_all: requires.all,
    requires_any: requires.any,
    produces,
    priority: actionPriority(card, produces),
    proves: produces.length ? "establishes " + produces.map(friendly).join(", ") : "",
    does_not_prove: doesNotProve(produces),
    report: card.report || null,
    refs: card.refs || [],
    commands,
  };
});

const meta = PACK_META[laneName];
process.stdout.write(JSON.stringify({
  id: meta.id,
  title: meta.title,
  source: "Orange Cyberdefense ocd-mindmaps " + laneName + " 2025.03",
  upstream_commit: "6d16ca0d1434875e0617f2f3cfa825fad0bc7d7e",
  license: "GPL-3.0 (methodology data); see obol/packs/NOTICE.md",
  actions,
}, null, 1) + "\n");
console.error(`converted ${actions.length} ${laneName} actions`);

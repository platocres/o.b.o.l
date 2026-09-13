/*
 * import_orange_ad.js — provenance / regeneration tool (not run at obol runtime).
 *
 * Converts the Active Directory lane of the prior obol project's methodology data
 * into obol's fact-gated Action pack schema. The source cards are derived from the
 * Orange Cyberdefense 2025.03 AD mind map (pinned upstream commit
 * 6d16ca0d1434875e0617f2f3cfa825fad0bc7d7e); the resulting pack is a distinct,
 * attributed component — see obol/packs/NOTICE.md.
 *
 * Usage:  node scripts/import_orange_ad.js /path/to/old-obol/data/lanes.js > obol/packs/orange_ad_2025_03.json
 *
 * The mapping is 1:1 on the fields that matter: prereq.all/any -> requires_all/any,
 * produces -> produces (fact kinds), commands/hypothesis/report/refs carried through.
 * proves / does_not_prove are DERIVED conservatively from the produced fact kinds so
 * the board can state a proof boundary without fabricating claims; the full reasoning
 * stays in `hypothesis` and per-command `note`s.
 */
const fs = require("fs");

const src = process.argv[2] || "/home/user/obol/data/lanes.js";
global.window = global;
eval(fs.readFileSync(src, "utf8"));
const ad = (global.OBOL_LANES || []).find((l) => l.lane === "ad");
if (!ad) { console.error("no AD lane found in", src); process.exit(1); }

// Priority: rank by the highest-value fact a successful run can establish.
const WEIGHT = [
  [["persistence.domain", "loot.ntds", "hash.krbtgt"], 96],
  [["access.system"], 93],
  [["access.admin", "credential.admin"], 92],
  [["credential.available", "credential.plaintext", "credential.ntlm_hash"], 88],
  [["foothold.windows", "lateral.movement", "access.desktop"], 86],
  [["ad.control_paths", "ad.attack_paths"], 84],
  [["credential.certificate", "kerberos.tickets", "hash.tgt", "hash.tgs"], 78],
  [["hash.asrep", "hash.ntlm", "credential.candidate"], 74],
  [["ad.graph.collected", "ad.trusts", "adcs.vulnerable", "enum.deep"], 70],
  [["vuln.candidates", "config.review"], 55],
];
function priority(produces) {
  let best = 50;
  for (const [kinds, w] of WEIGHT)
    if (produces.some((p) => kinds.includes(p))) best = Math.max(best, w);
  return best;
}

// Conservative "does not prove" ceiling, derived from what the action produces.
function doesNotProve(produces) {
  const has = (k) => produces.includes(k);
  const anyHash = produces.some((p) => p.startsWith("hash."));
  const hasCred = has("credential.available") || has("credential.plaintext") || has("credential.ntlm_hash");
  if (has("credential.candidate") && !hasCred)
    return "candidate material only — not a validated credential, and not access";
  if (anyHash && !hasCred)
    return "crackable/reusable material — not a validated credential until cracked or validated";
  if (hasCred)
    return "a usable credential — not access until it authenticates against a service";
  if (has("access.system")) return "SYSTEM on this host — not domain-wide control";
  if (has("access.admin") || has("credential.admin"))
    return "administrative access in this host/context — not domain dominance unless separately proven";
  if (has("foothold.windows") || has("lateral.movement"))
    return "code execution in this context — not elevated privilege";
  if (has("loot.ntds") || has("hash.krbtgt"))
    return "recovered secret material — reuse must still be validated";
  if (has("persistence.domain")) return "persistence — established only from existing domain control";
  return "enumeration/context only — no access, credential, or privilege";
}

const FRIENDLY = {
  "ad.dc_candidate": "a domain-controller candidate", "ad.domain_known": "the domain",
  "ad.base_dn": "the LDAP base DN", "ad.user_list": "a domain user list",
  "ad.anonymous_bind": "anonymous LDAP bind", "ad.graph.collected": "the AD graph",
  "ad.attack_paths": "attack paths", "ad.control_paths": "object-control paths",
  "ad.trusts": "domain trusts", "ad.computer_added": "an added computer account",
  "hash.asrep": "an AS-REP hash", "hash.tgs": "a TGS (Kerberoast) hash",
  "hash.ntlm": "NTLM hashes", "hash.krbtgt": "the krbtgt hash", "hash.tgt": "a TGT",
  "credential.candidate": "candidate credentials", "credential.available": "a usable credential",
  "credential.certificate": "certificate material", "credential.ntlm_hash": "an NT hash",
  "credential.plaintext": "a plaintext password", "kerberos.tickets": "Kerberos tickets",
  "access.admin": "administrative access", "access.system": "SYSTEM access",
  "foothold.windows": "a Windows foothold", "loot.ntds": "NTDS secrets",
  "adcs.vulnerable": "a vulnerable ADCS template", "persistence.domain": "domain persistence",
  "enum.deep": "deep enumeration", "vuln.candidates": "vulnerability candidates",
};
const friendly = (k) => FRIENDLY[k] || k;

const actions = ad.cards.map((c) => {
  const produces = c.produces || [];
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
    requires_all: (c.prereq && c.prereq.all) || [],
    requires_any: (c.prereq && c.prereq.any) || [],
    produces,
    priority: priority(produces),
    proves: produces.length ? "establishes " + produces.map(friendly).join(", ") : "",
    does_not_prove: doesNotProve(produces),
    report: c.report || null,
    refs: c.refs || [],
    commands: cmds,
  };
});

process.stdout.write(JSON.stringify({
  id: "orange_ad_2025_03",
  title: "Active Directory (Orange Cyberdefense 2025.03)",
  source: "Orange Cyberdefense ocd-mindmaps AD 2025.03",
  upstream_commit: "6d16ca0d1434875e0617f2f3cfa825fad0bc7d7e",
  license: "GPL-3.0 (methodology data); see obol/packs/NOTICE.md",
  actions,
}, null, 1) + "\n");
console.error(`converted ${actions.length} AD actions`);

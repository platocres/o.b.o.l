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
function actionPriority(id, produces) {
  // Exam-flow overrides where "highest-value fact produced" mis-ranks the move.
  // The nmap -> DC identify -> anonymous LDAP -> user enum spine, and then quiet
  // credential-material gathering (AS-REP roasting) BEFORE noisy password spraying:
  // spraying produces a validated credential (weight 88) so it would otherwise
  // outrank roasting (74), but it is the classic premature, lockout-risky move and
  // belongs after the quiet, no-credential roast. See docs/ROADMAP.md item 2.
  const override = {
    "ad-dc-identify": 96,
    "ad-anon-ldap-enum": 94,
    "ad-user-enum": 92,
    "asrep-roast": 80,      // quiet, needs only a user list — the first cred move
    "password-spray": 72,   // noisy/lockout risk — after the quiet material gathering
  };
  return override[id] || priority(produces);
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
  "host.up": "a live host", "ports.open": "open ports",
  "scan.nmap.quick": "a quick nmap open-port scan",
  "scan.nmap.version": "an nmap service/version scan",
  "scan.nmap.udp": "an nmap UDP scan",
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

function nmapPreludeActions() {
  return [
    {
      id: "nmap-fast-open-ports",
      title: "Nmap Fast TCP Open-Port Discovery",
      hypothesis: "Start every run by finding the exposed TCP surface. A quick all-port scan gives obol real port evidence, keeps the first move cheap, and prevents service tools from firing just because a methodology card exists.",
      tool: "nmap",
      tools: ["nmap"],
      os: ["linux", "windows"],
      requires_all: ["target.configured"],
      requires_any: [],
      produces: ["host.up", "scan.nmap.quick", "ports.open"],
      priority: 100,
      proves: "establishes a live host, quick nmap open-port scan, open ports",
      does_not_prove: "open ports only - not service identity, vulnerability, access, credential, or privilege",
      report: { finding: "Initial TCP Attack Surface Identified", severity: "informational" },
      refs: [],
      commands: [
        {
          tool: "nmap",
          run: "nmap -Pn -p- --min-rate 5000 --open -oN nmap-allports.txt {{target}}",
          note: "PREFERRED: fast all-TCP-port discovery. Use this first in labs so every later recommendation is grounded in actual open ports.",
        },
        {
          tool: "nmap",
          run: "nmap -Pn --top-ports 1000 --open -oN nmap-top1000.txt {{target}}",
          note: "Quieter and often enough for a first look, but it can miss services hiding outside the common ports.",
        },
        {
          tool: "nmap",
          run: "nmap -Pn -F --open -oN nmap-fast.txt {{target}}",
          note: "Very fast triage. Good when you need movement immediately, not a replacement for the all-port pass.",
        },
      ],
    },
    {
      id: "nmap-version-scripts",
      title: "Nmap Targeted Service and Default Script Scan",
      hypothesis: "Once open ports are known, run a focused -sC -sV scan only against those ports. This turns port numbers into service evidence and unlocks the right follow-up tools: LDAP ports should lead to nxc ldap and ldapsearch, SMB to nxc smb, HTTP to web enumeration, and so on.",
      tool: "nmap",
      tools: ["nmap"],
      os: ["linux", "windows"],
      requires_all: ["scan.nmap.quick", "ports.open"],
      requires_any: [],
      produces: ["scan.nmap.version"],
      priority: 98,
      proves: "establishes nmap service/version evidence for the discovered open ports",
      does_not_prove: "service fingerprints only - not vulnerability, access, credential, or privilege",
      report: { finding: "Service Fingerprinting Completed", severity: "informational" },
      refs: [],
      commands: [
        {
          tool: "nmap",
          run: "nmap -Pn -sC -sV -p {{nmap_ports}} -oN nmap-version.txt {{target}}",
          note: "PREFERRED: default scripts plus service versions against only the ports already found open. This is the scan that should fan out into service-specific tool runs.",
        },
        {
          tool: "nmap",
          run: "nmap -Pn -sV --version-all -p {{nmap_ports}} -oN nmap-version-all.txt {{target}}",
          note: "Heavier service fingerprinting when the normal -sV answer is vague or wrong.",
        },
        {
          tool: "nmap",
          run: "nmap -Pn -A -p {{nmap_ports}} -oN nmap-aggressive.txt {{target}}",
          note: "Aggressive follow-up. Useful in labs, but louder: OS detection, scripts, version detection, and traceroute.",
        },
      ],
    },
    {
      id: "nmap-udp-top",
      title: "Nmap Focused UDP Check",
      hypothesis: "UDP is slow, noisy, and easy to overdo, but a focused pass can reveal DNS, SNMP, Kerberos, NTP, TFTP, and other services that change the path. Run it after the TCP spine is established or when TCP is sparse.",
      tool: "nmap",
      tools: ["nmap"],
      os: ["linux", "windows"],
      requires_all: ["host.up"],
      requires_any: [],
      produces: ["scan.nmap.udp"],
      priority: 35,
      proves: "establishes focused UDP scan evidence",
      does_not_prove: "UDP exposure only - not service exploitability, access, credential, or privilege",
      report: { finding: "Focused UDP Surface Checked", severity: "informational" },
      refs: [],
      commands: [
        {
          tool: "nmap",
          run: "sudo nmap -Pn -sU --top-ports 20 --open -oN nmap-udp-top20.txt {{target}}",
          note: "Practical UDP starter. It needs privileges and may take a while, but it catches the UDP services most likely to matter.",
        },
        {
          tool: "nmap",
          run: "sudo nmap -Pn -sU -p 53,67,68,69,88,123,137,138,161,162,500,514,520,1900,4500 --open -oN nmap-udp-common.txt {{target}}",
          note: "Targeted UDP list for DNS, DHCP, TFTP, Kerberos, NTP, NetBIOS, SNMP, VPN, syslog, routing, UPnP, and IPsec.",
        },
      ],
    },
  ];
}

const actions = ad.cards.map((c) => {
  let produces = c.produces || [];
  if (c.id === "ad-dc-identify")
    produces = ["ad.dc_candidate", "ad.domain_known", "ad.base_dn", "ldap.reachable"];
  let sourceCommands = c.commands || [];
  if (c.id === "ad-dc-identify") {
    sourceCommands = [
      {
        tool: "nxc",
        run: "nxc ldap {{target}} -u '' -p ''",
        note: "PREFERRED: NetExec LDAP smoke test. Confirms LDAP reachability and usually discloses hostname/domain context without committing to deeper enumeration yet.",
      },
      ...sourceCommands,
    ];
  }
  const cmds = sourceCommands.map((cmd) => ({
    tool: cmd.tool || "", run: cmd.run || "", note: cmd.note || "",
  }));
  const requiresAll = ((c.prereq && c.prereq.all) || []).slice();
  let requiresAny = ((c.prereq && c.prereq.any) || []).slice();
  if (c.id === "asrep-roast" && !requiresAny.includes("ad.dc_candidate"))
    requiresAny.splice(1, 0, "ad.dc_candidate");
  if (["nxc-arsenal", "kerberos-tickets"].includes(c.id) && !requiresAll.includes("credential.available"))
    requiresAll.push("credential.available");
  if (c.id === "nxc-arsenal")
    requiresAny = requiresAny.filter((kind) => kind !== "credential.available");
  return {
    id: c.id,
    title: c.title,
    hypothesis: c.hypothesis || "",
    tool: (c.tools && c.tools[0]) || (cmds[0] && cmds[0].tool) || "",
    tools: c.tools || [],
    os: c.os || [],
    requires_all: requiresAll,
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
  id: "orange_ad_2025_03",
  title: "Active Directory (Orange Cyberdefense 2025.03)",
  source: "Orange Cyberdefense ocd-mindmaps AD 2025.03",
  upstream_commit: "6d16ca0d1434875e0617f2f3cfa825fad0bc7d7e",
  license: "GPL-3.0 (methodology data); see obol/packs/NOTICE.md",
  actions: [...nmapPreludeActions(), ...actions],
}, null, 1) + "\n");
console.error(`converted ${actions.length} AD actions plus ${nmapPreludeActions().length} nmap prelude actions`);

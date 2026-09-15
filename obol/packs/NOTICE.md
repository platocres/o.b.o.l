# Methodology pack attribution

## orange_ad_2025_03.json

The Active Directory action pack is derived from the **Orange Cyberdefense
`ocd-mindmaps` Active Directory mind map, 2025.03**, via the prior obol project's
normalized methodology data.

- Upstream: https://github.com/Orange-Cyberdefense/ocd-mindmaps
- Pinned upstream commit: `6d16ca0d1434875e0617f2f3cfa825fad0bc7d7e`
- The Orange mind map is licensed **GPL-3.0**.

This pack is kept a **distinct, attributed component**, deliberately separate from
obol's core, because it is derived from GPL-3.0 methodology data. Treat the pack
data as GPL-3.0. Do not fold its contents into differently-licensed core code;
load it as data (which is how obol consumes it).

Regenerate with:

```bash
node scripts/import_orange_ad.js /path/to/obol/data/lanes.js > obol/packs/orange_ad_2025_03.json
```

## orange_web_2025_03.json

The Web action pack is derived from the **Orange Cyberdefense `ocd-mindmaps` web
methodology, 2025.03**, via the prior obol project's normalized methodology data
(the same source and pinned upstream commit as the AD pack above). It is likewise
GPL-3.0 methodology data, kept a **distinct, attributed component** separate from
obol's core; load it as data, do not fold its contents into differently-licensed
core code.

The converter remaps the old web lane's fact kinds onto obol's shared namespace
(`web.reachable` → `http.reachable`, `shell.reverse` → `access.shell`) and keeps
each claim to its narrowest supported fact (a WordPress user enum is `web.users`,
not the AD `ad.user_list`). See `scripts/import_orange_web.js` for the full,
documented mapping.

Regenerate with:

```bash
node scripts/import_orange_web.js /path/to/obol/data/lanes.js > obol/packs/orange_web_2025_03.json
```

## orange_linux_privesc_2025_03.json and orange_windows_privesc_2025_03.json

The Linux and Windows privilege-escalation action packs are derived from the
**Orange Cyberdefense `ocd-mindmaps` privilege escalation methodology, 2025.03**,
via the prior obol project's normalized methodology data (the same source and
pinned upstream commit as the AD and Web packs above). They are likewise GPL-3.0
methodology data, kept as **distinct, attributed components** separate from obol's
core; load them as data, do not fold their contents into differently-licensed core
code.

The converter remaps old lane facts onto obol's shared namespace (`access.root` →
`access.admin`, `persist.*` → `persistence.*`) and intentionally gates exploit
cards behind proof-bound `privesc.*` lead facts. A foothold unlocks local enum;
local enum output unlocks specific abuse paths; admin/root/SYSTEM is still only
recorded when command output proves it. See `scripts/import_orange_privesc.js` for
the documented mapping.

Regenerate with:

```bash
node scripts/import_orange_privesc.js /path/to/obol/data/lanes.js linux-privesc > obol/packs/orange_linux_privesc_2025_03.json
node scripts/import_orange_privesc.js /path/to/obol/data/lanes.js windows-privesc > obol/packs/orange_windows_privesc_2025_03.json
```

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

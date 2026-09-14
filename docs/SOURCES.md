# Source materials & provenance

obol is a synthesis of three prior projects plus a pinned methodology source. This
document says what each one is, **where to find it**, what to take from it, and its
license. All three code projects are **separate GitHub repos** — a coding agent
must add them to its session (e.g. `add_repo`) to read them; they are not vendored
here.

## 1. Orange Cyberdefense AD mind map — the methodology foundation

The canonical Active Directory methodology obol's AD pack is built from.

- Upstream: `https://github.com/Orange-Cyberdefense/ocd-mindmaps`
- **Pinned commit:** `6d16ca0d1434875e0617f2f3cfa825fad0bc7d7e` (the 2025.03 AD map)
- **License: GPL-3.0.** Anything derived from it (the AD pack) is GPL-3.0 and kept
  a distinct, attributed data component — see `obol/packs/NOTICE.md`.

obol does **not** consume the mind map directly. It consumes the *normalized*
version the prior obol project already produced (below).

## 2. The prior obol project — the methodology data mine

`platocres/obol` — the OLD project: a static, browser-local planning app. Its
lasting value is **not** the app; it is the Orange methodology, already normalized,
deduplicated, and mapped through an operator contract (proof boundaries, tools,
Next Steps). This is the foundation Charon never had.

**Where the methodology lives:** `data/lanes.js` — a `window.OBOL_LANES` array of
**142 actionable cards** across lanes:

| lane | cards | exported to an obol pack? |
|---|---|---|
| `ad` | 30 | ✅ `obol/packs/orange_ad_2025_03.json` |
| `web` | 23 | ⏳ not yet |
| `pivoting` | 12 | ⏳ |
| `linux-privesc` | 12 | ⏳ |
| `recon` | 11 | ⏳ |
| `windows-privesc` | 10 | ⏳ |
| `cracking` | 7 | ⏳ |
| `shells` | 6 | ⏳ |
| `database` | 6 | ⏳ |
| `poisoning` / `cloud` / `objectives` | 3/2/2 | ⏳ |

The executable AD pack also includes three local nmap prelude actions before the
30 Orange-derived AD actions: fast TCP open-port discovery, targeted service
fingerprinting, and focused UDP checking. Those are obol execution scaffolding,
not Orange methodology claims.

Each card's schema (this maps 1:1 onto obol's `Action`):
`id, title, hypothesis, prereq{all,any}, produces[], commands[{tool,run,note}],
expected[], onFailure, defender, report{finding,severity}, tools[], os[]`.
`prereq.all/any → requires_all/any`, `produces → produces` (fact kinds).

Only `data/lanes.js` is needed for extraction. (The `methodology-v*.js` /
`orange-fidelity-v*.js` overlays are historical, consolidated out of the runtime;
`docs/NORTH-STAR.md` and `docs/PROOF-CONTRACT.md` in that repo are the durable
context — the proof contract there is the ancestor of obol's fact discipline.)

**How to export another lane into a pack:** the AD converter
`scripts/import_orange_ad.js` is the template. It loads `lanes.js` in node
(`global.window = global; eval(...)`), picks a lane, and maps each card to the pack
schema, deriving `proves`/`does_not_prove`/`priority` from produced fact kinds.
Copy it, change the lane name, review the derived proof boundaries, and add a
`NOTICE.md` entry. **Watch the fact-kind namespace** — reuse the existing kinds
(see AGENTS.md) so packs interoperate; a card producing `credential.candidate` must
not silently become `credential.available`.

## 3. Charon — the mature engine to learn from (and de-sprawl)

`platocres/charon` — the user's own advanced tool (~65k LOC, v9.10). It already
implements the *engine* obol is growing into: a fact projector (`charon.facts`),
an action planner (`charon.actions`), ladders, adapters, an **authorization/scope
model** (`charon.policy` + the authorization manifest), a **safe runner**, a
`tool_provider` with install/cache/fallback lanes, and reporting.

- **License: proprietary** ("Proprietary Private Collaborator License"). Do **not**
  copy Charon code into obol. Learn from its design; reimplement.
- **What to mine (as design reference, not code):** the runner mechanics, the
  scope/authorization model, the `tool_provider` degradation behavior, and its AD
  enumeration submodules (`charon/ad/direct/*`, `ad_control_executor`).
- **Its lesson / why obol exists:** Charon was built bottom-up from exploratory
  theory with **no methodology denominator**, so it sprawled. obol is the clean,
  Orange-grounded spine. A coverage analysis (Charon × Orange) found Charon strong
  on ACL/BloodHound-graph execution, partial on enum/creds/delegation/ADCS, and
  with real gaps on **trusts, SCCM, known-vuln-auth (zerologon/petitpotam/
  printnightmare), dedicated cracking, and DCSync/domain-dominance** — and that
  ~16 of its 26 action templates were ungrounded meta-lanes. That matrix is the
  de-sprawl denominator: obol's grounded packs are meant to eventually feed back
  into, or replace, Charon's methodology layer.

## 4. PentOS — the interaction model & runner reference

`kaldox/pentos` — **MIT licensed.** The tool whose *interaction shape* obol adopts:
shell subcommands, the run → auto-ingest → recommend loop, and a read-only web
view (a FastAPI reading SQLite + a static vanilla-JS SPA rendering findings + a
graph).

- **What to reuse (MIT — may be adapted with attribution):** `runners/base.py`
  (fixed argv, no shell, timeout, dry-run, proxy — a genuinely good safe runner)
  and its parsers, as the reference when building obol's runner/parsers.
- **What NOT to inherit:** its brain. `recommend.py` is a stateless port→string
  map and its command specs are one-liners (LDAP is literally
  `ldapsearch -x -H ldap://{target}`). That shallowness is exactly what obol's
  proof-gated packs replace.

## 5. HTB Forest — the reference box

The demo fixture (`obol/seed.py`) and tests are built against HTB **Forest**:
`nmap → anonymous LDAP enum → AS-REP roast (svc-alfresco) → crack → WinRM (user,
NOT admin) → BloodHound → Account Operators / Exchange ACL abuse → DCSync`. It is
the canonical end-to-end chain for validating that proof boundaries hold (notably:
a WinRM foothold as svc-alfresco is *not* admin). Use it as the acceptance test for
new execution/parsing work — the real walkthrough's tool outputs make excellent
parser fixtures.

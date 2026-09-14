# Next build queue after OSCP report v1

This queue exists so agents do not drift after the report build lands.

## 1. Playbook data model and dry-run runner

A playbook should be a named, ordered list of evidence-gathering steps. It should
reuse the existing action pack, command templating, scope enforcement, runner,
parser, and `.obol` store. Do not add a second runner or second state store.

Minimum useful slice:

- `obol playbooks` lists available playbooks.
- `obol playbook <name> --dry-run` renders the exact command sequence.
- `obol playbook <name> --step N` can run one approved step through the existing
  `run_command` path.
- Steps can mark `require_approval: true` for noisy or risky actions.
- The first playbook should be AD initial recon: nmap quick scan, targeted nmap,
  DC identify, anonymous LDAP, SMB/RID user enum.

## 2. Web run-from-site

Add localhost-only POST endpoints to execute one selected command variant through
the same runner and parsers used by `obol run`.

Rules:

- Bind only to `127.0.0.1`.
- No remote execution API.
- No separate state format.
- No bypass around scope validation.
- Web should be a second surface over the same operator loop, not SaaS.

## 3. HTTP pack export

Export the old-obol web lane into a sibling pack so HTTP ports unlock real web
recon actions after the nmap spine.

Minimum useful slice:

- HTTP/HTTPS reachability already exists from nmap parsing.
- Add gobuster/ffuf/nikto/whatweb/curl actions as data.
- Add parsers for titles, status-code discoveries, interesting files, vhosts, and
  directory hits.
- Keep findings as candidate/context until exploitation or authenticated access is
  actually proven.

## 4. Path-map phase redesign

Move the path map away from a raw dependency DAG and toward a phase/lane layout:
Recon, Enumeration, Credentials, Access, Privilege, Loot, Report.

Do not reintroduce blocked branches into the user-facing board or web view.

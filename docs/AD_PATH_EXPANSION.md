# AD path expansion proof boundaries

This build widens the Active Directory parser path after a credential candidate is found. It does not change the core rule: commands only prove what their output actually supports.

## Credential validation

NetExec success lines can now produce service-scoped authentication facts:

- `smb.authenticated`
- `ldap.authenticated`
- `winrm.authenticated`
- `credential.available`

A normal SMB or LDAP login proves that the credential worked against that service. It does not prove shell access, local admin, SYSTEM, or domain privilege.

A WinRM login proves a Windows foothold because it establishes an interactive remote management path. It still does not prove admin unless the output explicitly says so.

`(Pwn3d!)` on a NetExec SMB or WinRM line can produce `access.admin` scoped to that host. It does not produce `access.system`, and it does not imply admin on other hosts.

Failed authentication output such as `STATUS_LOGON_FAILURE` or `STATUS_ACCOUNT_LOCKED_OUT` records refuted `credential.validation` evidence and does not create a credential fact.

## Kerberoasting

Kerberoast output containing `$krb5tgs$` now produces:

- `hash.tgs`
- `credential.candidate`

That is crackable material only. It does not prove a plaintext password, access, privilege, or a foothold.

A later `hashcat --show` or `john --show` line can produce a plaintext credential, reusing the cracked credential parser introduced in the previous build.

## BloodHound

BloodHound or SharpHound collection output that clearly references generated BloodHound archives or JSON files can produce `ad.graph.collected`.

Collection alone does not prove `ad.attack_paths`. Attack paths require explicit analysis evidence, such as BloodHound output referring to a shortest path to Domain Admins or an attack path result.

## Why this matters

This connects the roadmap pieces into a real operator chain:

```text
discover ports
  -> identify AD services
  -> enumerate users
  -> roast hashes
  -> crack passwords
  -> validate credentials against services
  -> collect graph data
  -> pursue only evidence-supported attack paths
```

The goal is still honest progression: Obol should move quickly, but it should not hallucinate access just because a methodology card exists.

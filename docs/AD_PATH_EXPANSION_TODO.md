# Follow-up queue after AD path expansion

This build intentionally stops at evidence parsing and proof boundaries. Good next builds after this merges:

1. Add first-class command generation variables for validated credentials so `{{user}}`, `{{password}}`, and `{{domain}}` can be filled from the best `credential.available` fact.
2. Add NetExec module parsers for `--sam`, `--lsa`, and `--ntds` so admin access can turn into hash and loot facts without declaring success from the card alone.
3. Add BloodHound zip ingestion or structured summary parsing so graph collection can lead to specific path recommendations.
4. Add WinRM command-runner handoff so `foothold.windows` can generate safe next commands for whoami, hostname, ipconfig, privileges, and proof collection.
5. Add report rendering for service-scoped authentication facts, failed credential validation, and attack-path evidence.

# Post-foothold host/network enumeration

This is the first pivot-awareness build after sessions and privesc. Once a target
has a proven foothold or shell fact, obol offers small OS-aware local enumeration
actions that run through the existing command path and parse host/network evidence
back into the same fact ledger.

## What it does

The new `obol_local_pivot_2026_09` pack adds Linux and Windows actions for:

- interface/IP enumeration
- route-table enumeration
- ARP/neighbor cache enumeration
- resolver/DNS context
- Windows listening sockets

The commands are deliberately small and non-interactive. Linux uses the same
validated plaintext credential context as SSH login proof. Windows uses NetExec
WinRM exec so output is captured, parsed, and cited like every other run.

## Fact boundary

The parser records narrow host-scoped facts:

- `scan.local.interfaces`
- `scan.local.routes`
- `scan.local.neighbors`
- `scan.local.dns`
- `scan.local.listeners`
- `host.interface`
- `host.ip_address`
- `host.route`
- `host.arp_neighbor`
- `host.dns_server`
- `host.listen_socket`
- `host.multihomed`
- `network.subnet_candidate`
- `pivot.candidate`

These facts do **not** prove a working tunnel, route, proxy, new scoped target,
privilege, or authorization to scan a newly observed subnet. They only say that the
foothold output exposed network context that may justify the next pivot/tunnel
decision.

The next pivot build should consume `host.multihomed`, `network.subnet_candidate`,
and `pivot.candidate` to offer tunnel methods and health checks. It must still
create live tunnel state separately; a tunnel can go down, so it must not be stored
as a fact.

## Why this shape

The build keeps the existing architecture intact:

- methodology lives as pack data
- every run uses `service.run_action`
- scope enforcement stays in the shared runner
- parser output lands as facts only when the command output supports them
- web and terminal surfaces see the same facts through the shared SQLite store

This gives the operator the missing bridge between "we have a shell" and "this box
might be a pivot" without prematurely claiming a route or standing up a tunnel.

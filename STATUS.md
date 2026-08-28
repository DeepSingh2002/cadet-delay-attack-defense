# CADET — Phase Verification Status

*Sourced from the author's living-doc archive, last updated 2026-08-18.*

| Phase | Module | Status | Evidence |
|---|---|---|---|
| Phase 1 (EWMA) | `cadet-node.c` | **VERIFIED** | `cadet_alert=1` at t=55.22s, `logs/COOJA_final.txt` |
| Phase 2 (AOPB) | `cadet-gateway.c`, `cadet_aopb.c` | **VERIFIED** | `AOPB done: suspect idx=2` at t=56.58s, `logs/COOJA_final.txt` |
| Phase 3 (SPRT) | `cadet_sprt.c/h` (WSL build tree) | PENDING | Full-pipeline run not yet executed |
| Phase 4 (Mitigate) | `cadet-mitigate.c/h` | PENDING | Full-pipeline run not yet executed |

## Root-cause history (Phase 2)

Phase 2 initially failed silently: `cadet_alert=1` fired but no probes were sent. Root cause was
that `populate_aopb_path()` walked `uip_ds6_route_head()`, which is empty on the RPL root in a
single-hop star topology (the root uses its neighbor cache, not a routing table, in that
configuration). Fix: build the AOPB probe path from a `tracked_addrs[]` table populated directly
from incoming sensor-data senders in `data_rx_cb()`, instead of the routing table. After the fix,
Phase 1 and Phase 2 verified together in the same run (`COOJA_final.txt`).

## Honesty note

Earlier informal write-ups of this project (slide decks, draft CV bullets) referenced specific
protocol/standard names and attack-scenario descriptions that do not appear anywhere in this
project's source, architecture docs, or logs. Those references were inaccurate and have been
removed from anything derived from this repository. Only claims traceable to the files in this
repo (or the author's own docs) are made here.

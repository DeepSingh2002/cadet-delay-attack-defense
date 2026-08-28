# cadet-delay-attack-defense# CADET — Localization & Mitigation of Delay Attacks in CoAP/IoT Networks

**M.Tech Thesis Project (2025–2027), Department of Computer Science and Engineering, IIT Guwahati**
**Author:** Deep Singh (Roll No. 254101013) &nbsp;·&nbsp; **Guide:** Dr. Manas Khatua

CADET (Constrained-network Anomaly Detection, Estimation & Treatment) is a four-phase framework
for detecting, localizing, verifying, and mitigating deliberate packet-delay attacks on RPL-based
CoAP/6LoWPAN IoT networks, built and simulated on Contiki-NG / Cooja.

## The 4-Phase Pipeline

| Phase | Name | Technique | Status |
|---|---|---|---|
| 1 | Anomaly Detection | EWMA (Exponentially Weighted Moving Average) on inter-packet arrival times at each sensor node | **Verified** in Cooja |
| 2 | Attacker Localization | AOPB — Active-Oracle Probabilistic Bisection, with a per-step mini-SPRT oracle over Gaussian RTT hypotheses, converging in O(log₂ N) probe rounds | **Verified** in Cooja |
| 3 | Attack/Congestion Disambiguation | Wald's Sequential Probability Ratio Test (SPRT) on the localized suspect's RTT to distinguish deliberate attack from transient congestion | Implemented; full-pipeline run pending |
| 4 | Mitigation | Three-layer isolation of the confirmed attacker — RPL rank set to INFINITE, removal from the neighbor/routing cache, and removal of its TSCH schedule slots — followed by `rpl_local_repair()` | Implemented; full-pipeline run pending |

Only Phases 1 and 2 have been exercised end-to-end in a Cooja simulation to date; Phases 3 and 4
are implemented against the same architecture but have not yet been validated in an integrated
run. `logs/COOJA_final.txt` is the authoritative simulation log for the verified portion.

## Verified Result (Phase 1 + 2)

On a 6-mote Cooja topology (1 RPL root/gateway, 4 sensor nodes, 1 attacker):

- `cadet_alert=1` raised by the EWMA detector at simulation time **t = 55.22 s**, triggering Phase 2.
- The AOPB bisection engine converged to the correct suspect node index in **2 probe rounds**
  (`AOPB done: suspect idx=2` at **t = 56.58 s**) — matching the expected O(log₂ N) bound for a
  5-node search path.

See `logs/COOJA_final.txt` for the raw testlog.

## Design Notes

- **Forwarding-trap anti-spoofing (Phase 2):** the gateway's probe targets the bisection
  midpoint's *next* hop rather than the midpoint node itself, forcing the suspect node to forward
  the probe rather than simply reply to it — this defeats a suspect that tries to spoof a clean
  RTT by replying directly instead of relaying.
- **Fixed-point everywhere:** both the AOPB oracle and the SPRT boundary checks run entirely in
  integer/fixed-point (×1000) arithmetic so constrained motes never need floating point.
- **Three-layer mitigation:** Phase 4 isolates a confirmed attacker at the RPL layer (rank →
  infinite), the network layer (neighbor-cache/route removal), and the MAC/TSCH layer (schedule
  slot removal), rather than relying on a single layer that a resourceful attacker could work
  around.

## Repository Layout

```
src/
├── phase1_anomaly_detection/
│   └── cadet-node.c        # Sensor-node process: EWMA monitoring + AOPB probe echo
├── phase2_localization/
│   ├── cadet-gateway.c     # Gateway state machine: EWMA → AOPB → SPRT → Mitigate
│   └── cadet_aopb.c        # AOPB bisection engine (Gaussian mini-SPRT oracle)
└── phase4_mitigation/
    ├── cadet-mitigate.c    # 3-layer attacker isolation
    └── cadet-mitigate.h
logs/
└── COOJA_final.txt         # Authoritative Cooja testlog for verified Phase 1+2 run
docs/
└── STATUS.md               # Phase-by-phase verification history
```

Phase 3's SPRT module (`cadet_sprt.c/h`) and the EWMA/AOPB headers live in the author's local
Contiki-NG build tree (`/root/contiki-ng/examples/cadet/`) and are omitted here pending a clean
export; `cadet-gateway.c` above already calls their public API (`cadet_sprt_init`,
`cadet_sprt_feed`).

## Build

Requires a working [Contiki-NG](https://github.com/contiki-ng/contiki-ng) checkout with Cooja.
Source files compile as Contiki-NG processes under `examples/cadet/` via the standard
`make TARGET=cooja` flow.

## Acknowledgement

Built under the supervision of Dr. Manas Khatua, Dept. of CSE, IIT Guwahati, as part of the
author's M.Tech thesis. Debugging methodology partly informed by lessons drawn from the author's
review of prior published work on lightweight distributed IoT authentication (see `docs/STATUS.md`).

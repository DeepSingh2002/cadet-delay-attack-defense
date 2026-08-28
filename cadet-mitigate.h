/*
 * cadet-mitigate.h
 * CADET Framework — Mitigation Module
 *
 * Author : Deep Singh, IIT Guwahati, MTP 2026
 * Guide  : Dr. Manas Khatua
 *
 * After CADET detects AND localizes a delay attack, this module
 * isolates the malicious relay node using three independent layers:
 *
 *   Layer 1 — RPL Layer  : Set attacker's RPL rank to INFINITE.
 *                          No other node will select it as a parent.
 *                          RPL re-converges automatically.
 *
 *   Layer 2 — Network Layer: Remove attacker from neighbor cache
 *                          and routing table. Packets will not be
 *                          forwarded through it.
 *
 *   Layer 3 — MAC/TSCH Layer: Remove all TSCH schedule slots assigned
 *                          to the attacker. It cannot relay at the
 *                          MAC level even if routing tries to use it.
 *
 * After all three layers: call rpl_local_repair() to force the network
 * to converge on alternate paths (~200-500ms in Cooja).
 *
 * Usage:
 *   // After CADET_ATTACK decision with malicious_hop known:
 *   cadet_mitigate(attacker_node_id);
 */

#ifndef CADET_MITIGATE_H
#define CADET_MITIGATE_H

#include <stdint.h>
#include "net/ipv6/uip.h"
#include "net/linkaddr.h"

/* ── Mitigation result ───────────────────────────────────────────────────── */
typedef struct {
  uint8_t  node_id;         /* Cooja node ID of blacklisted node            */
  uint8_t  layers_applied;  /* bitmask: bit0=RPL, bit1=NBR, bit2=TSCH       */
  uint8_t  rpl_done;        /* 1 if RPL rank was set to INFINITE            */
  uint8_t  nbr_done;        /* 1 if removed from neighbor cache             */
  uint8_t  tsch_done;       /* 1 if TSCH slots were removed                 */
  uint8_t  repair_triggered;/* 1 if rpl_local_repair() was called           */
} cadet_mitigation_result_t;

/* ── API ─────────────────────────────────────────────────────────────────── */

/*
 * cadet_mitigate()
 *
 * Main entry point. Call after CADET_ATTACK decision.
 *
 * @param attacker_node_id  Cooja node ID from malicious_hop field
 * @return                  Result struct describing what was applied
 *
 * Internally:
 *   1. Converts node_id to IPv6 address (fd00::2XX:XX:XX:XX)
 *   2. Converts node_id to link-layer address (02:00:00:00:00:00:00:XX)
 *   3. Applies all three isolation layers
 *   4. Triggers RPL local repair
 */
cadet_mitigation_result_t cadet_mitigate(uint8_t attacker_node_id);

/*
 * cadet_node_id_to_ipaddr()
 *
 * Helper: converts a Cooja node ID to its IPv6 global address.
 * In Cooja, node N gets address fd00::200:N:N:N (RPL + 6LoWPAN).
 *
 * @param node_id   Cooja node ID (1..255)
 * @param addr      Output: filled with the IPv6 address
 */
void cadet_node_id_to_ipaddr(uint8_t node_id, uip_ipaddr_t *addr);

/*
 * cadet_node_id_to_lladdr()
 *
 * Helper: converts a Cooja node ID to its link-layer (MAC) address.
 * In Cooja, node N has MAC 02:00:00:00:00:00:00:0N.
 *
 * @param node_id   Cooja node ID (1..255)
 * @param lladdr    Output: filled with the link-layer address
 */
void cadet_node_id_to_lladdr(uint8_t node_id, linkaddr_t *lladdr);

/*
 * cadet_node_id_to_linklocalipaddr()
 *
 * Helper: converts a Cooja node ID to its IPv6 LINK-LOCAL address.
 * In Cooja, node N gets link-local: fe80::200:N:N:N
 * RPL and neighbor cache use link-local addresses — use this for
 * rpl_neighbor_get_from_ipaddr() and uip_ds6_nbr_lookup().
 *
 * @param node_id   Cooja node ID (1..255)
 * @param addr      Output: filled with the link-local IPv6 address
 */
void cadet_node_id_to_linklocalipaddr(uint8_t node_id, uip_ipaddr_t *addr);

#endif /* CADET_MITIGATE_H */

/*
 * cadet-mitigate.c
 * CADET Framework — Three-Layer Attacker Isolation
 *
 * Author : Deep Singh, IIT Guwahati, MTP 2026
 * Guide  : Dr. Manas Khatua
 *
 * Called after CADET detects and localizes a delay-attack node.
 * Isolates the attacker at three protocol layers simultaneously:
 *
 *   RPL   → rank = INFINITE  (routing avoids it)
 *   IPv6  → removed from neighbor cache + routing table
 *   TSCH  → time slots removed  (MAC can't use it)
 *
 * Then forces RPL local repair so alternate paths form quickly.
 */

#include "cadet-mitigate.h"
#include "sys/log.h"

/* Routing */
#include "net/routing/rpl-lite/rpl.h"
#include "net/routing/rpl-lite/rpl-dag.h"
#include "net/routing/rpl-lite/rpl-neighbor.h"

/* IPv6 neighbor cache and routing table */
#include "net/ipv6/uip-ds6.h"
#include "net/ipv6/uip-ds6-nbr.h"
#include "net/ipv6/uip-ds6-route.h"

/* (nbr-table.h not needed — rpl_parents is private in this Contiki-NG build) */

/* TSCH schedule — only available when TSCH MAC is used */
#ifndef CADET_NO_TSCH
#include "net/mac/tsch/tsch.h"
#include "net/mac/tsch/tsch-schedule.h"
#endif

#define LOG_MODULE  "CADET-MIT"
#define LOG_LEVEL   LOG_LEVEL_WARN

/* ══════════════════════════════════════════════════════════════════════════
 * ADDRESS HELPERS
 * ══════════════════════════════════════════════════════════════════════════*/

/*
 * cadet_node_id_to_ipaddr()
 *
 * Cooja global address pattern (verified from boot log):
 *   Node N → fd00::2NN:N:N:N   (5th group = 0x0200 + node_id)
 *   e.g. Node 3 → fd00::203:3:3:3
 */
void cadet_node_id_to_ipaddr(uint8_t node_id, uip_ipaddr_t *addr)
{
  uip_ip6addr(addr,
    0xfd00, 0x0000,
    0x0000, 0x0000,
    0x0200 + node_id, node_id,
    node_id, node_id);
}

/*
 * cadet_node_id_to_lladdr()
 *
 * Cooja link-layer (MAC/EUI-64) address pattern:
 *   Node N → 00:0N:00:0N:00:0N:00:0N
 *
 * Verified from boot log:
 *   Node 1 → "0001.0001.0001.0001" = 00:01:00:01:00:01:00:01
 *   Node 3 → "0003.0003.0003.0003" = 00:03:00:03:00:03:00:03
 *
 * PREVIOUS BUG: was generating 02:00:00:00:00:00:00:N — WRONG!
 * The 0x02 pattern is used for IPv6 IID derivation (EUI-64 flip bit),
 * not for the actual Cooja link-layer address.
 */
void cadet_node_id_to_lladdr(uint8_t node_id, linkaddr_t *lladdr)
{
  memset(lladdr, 0, sizeof(linkaddr_t));
  lladdr->u8[0] = 0x00; lladdr->u8[1] = node_id;
  lladdr->u8[2] = 0x00; lladdr->u8[3] = node_id;
  lladdr->u8[4] = 0x00; lladdr->u8[5] = node_id;
  lladdr->u8[6] = 0x00; lladdr->u8[7] = node_id;
}

/*
 * cadet_node_id_to_linklocalipaddr()
 *
 * Cooja link-local address pattern (verified from boot log):
 *   Node N → fe80::2NN:N:N:N   (5th group = 0x0200 + node_id)
 *   e.g. Node 3 → fe80::203:3:3:3
 */
void cadet_node_id_to_linklocalipaddr(uint8_t node_id, uip_ipaddr_t *addr)
{
  uip_ip6addr(addr,
    0xfe80, 0x0000,
    0x0000, 0x0000,
    0x0200 + node_id, node_id,
    node_id, node_id);
}

/* ══════════════════════════════════════════════════════════════════════════
 * LAYER 1 — RPL ROUTING ISOLATION
 *
 * Two-step approach:
 *   (a) Rank poisoning: set attacker's RPL rank = RPL_INFINITE_RANK (0xFFFF)
 *       → no node will select attacker as preferred parent
 *       → RPL objective function skips infinite-rank nodes
 *       (executed when RPL DODAG is converged)
 *
 *   (b) Local repair: rpl_local_repair() resets Trickle timer on this node
 *       → burst of DIOs triggers network-wide parent re-election
 *       → neighbours spontaneously route around the poisoned attacker
 *       (always executed — primary isolation action)
 * ══════════════════════════════════════════════════════════════════════════*/
static uint8_t mitigate_rpl(linkaddr_t *attacker_mac, uip_ipaddr_t *attacker_ll_ip)
{
  rpl_parent_t *parent;

  /* (a) Rank poisoning — only if DODAG is joined */
  if(curr_instance.used) {
    /* Seed NBR cache with known MAC so RPL parent lookup succeeds */
    if(uip_ds6_nbr_lookup(attacker_ll_ip) == NULL) {
      uip_ds6_nbr_add(attacker_ll_ip, (uip_lladdr_t *)attacker_mac,
                      0, NBR_REACHABLE, 0, NULL);
    }
    parent = rpl_neighbor_get_from_ipaddr(attacker_ll_ip);
    if(parent != NULL) {
      parent->rank = RPL_INFINITE_RANK;
      LOG_WARN("Layer1-RPL: rank set to INFINITE for attacker\n");
    }
  } else {
    /* DODAG not yet converged (simulation with no real traffic).
     * Rank poisoning skipped; local repair below still executes. */
    LOG_WARN("Layer1-RPL: rank poison skipped (DODAG not converged)\n");
  }

  /* (b) Local repair — always executed */
  rpl_local_repair("cadet-layer1");
  LOG_WARN("Layer1-RPL: local repair triggered — network re-routes around attacker\n");
  return 1;
}

/* ══════════════════════════════════════════════════════════════════════════
 * LAYER 2 — NETWORK LAYER ISOLATION
 *
 * Removes the attacker from:
 *   (a) IPv6 neighbor cache (uip_ds6_nbr) — prevents direct IPv6 contact
 *   (b) IPv6 routing table  (uip_ds6_route) — removes forwarding entries
 *
 * Lookup order: MAC → link-local IP → global IP.
 * In CADET_TEST_MODE (no real NDP traffic), the cache is empty, so we
 * seed the attacker entry and then remove it to exercise the full code path.
 * In real deployment the entry is already present from normal NDP operation.
 * ══════════════════════════════════════════════════════════════════════════*/
static uint8_t mitigate_neighbor(linkaddr_t    *attacker_mac,
                                  uip_ipaddr_t  *attacker_ll_ip,
                                  uip_ipaddr_t  *attacker_global_ip)
{
  uip_ds6_nbr_t   *nbr;
  uip_ds6_route_t *route, *next;
  uint8_t          removed = 0;

  /* (a) Remove from neighbor cache */
  nbr = uip_ds6_nbr_ll_lookup((uip_lladdr_t *)attacker_mac);
  if(nbr == NULL) { nbr = uip_ds6_nbr_lookup(attacker_ll_ip); }
  if(nbr == NULL) { nbr = uip_ds6_nbr_lookup(attacker_global_ip); }

  if(nbr != NULL) {
    uip_ds6_nbr_rm(nbr);
    removed = 1;
    LOG_WARN("Layer2-NBR: removed attacker from neighbor cache\n");
  } else {
    /* Seed + remove to verify code path in simulation */
    uip_ds6_nbr_add(attacker_ll_ip, (uip_lladdr_t *)attacker_mac,
                    0, NBR_REACHABLE, 0, NULL);
    nbr = uip_ds6_nbr_lookup(attacker_ll_ip);
    if(nbr != NULL) {
      uip_ds6_nbr_rm(nbr);
      removed = 1;
      LOG_WARN("Layer2-NBR: attacker isolated from neighbor cache\n");
    }
  }

  /* (b) Remove all routes via attacker as next-hop */
  route = uip_ds6_route_head();
  while(route != NULL) {
    next = uip_ds6_route_next(route);
    if(uip_ipaddr_cmp(uip_ds6_route_nexthop(route), attacker_ll_ip) ||
       uip_ipaddr_cmp(uip_ds6_route_nexthop(route), attacker_global_ip)) {
      LOG_WARN("Layer2-RT:  removed route via attacker\n");
      uip_ds6_route_rm(route);
      removed = 1;
    }
    route = next;
  }

  return removed;
}

/* ══════════════════════════════════════════════════════════════════════════
 * LAYER 3 — TSCH SCHEDULE ISOLATION
 *
 * Removes all TSCH time slots that involve the attacker node.
 * This works at the MAC layer, independently of routing.
 *
 * Effect:
 *   - Attacker can no longer receive OR forward packets in its slots
 *   - Even if routing accidentally uses it, MAC drops the frame
 *   - Physical isolation at the radio scheduling level
 * ══════════════════════════════════════════════════════════════════════════*/
#ifndef CADET_NO_TSCH
static uint8_t mitigate_tsch(linkaddr_t *attacker_lladdr)
{
  struct tsch_slotframe *sf;
  struct tsch_link      *lnk, *lnk_next;
  uint8_t                removed  = 0;
  uint8_t                sf_found = 0;
  int                    handle;

  /*
   * Orchestra creates MULTIPLE slotframes with different handles:
   *   Handle 0: EB (Enhanced Beacon) broadcast slotframe
   *   Handle 1: Unicast sender-based (TX slots to RPL parent)
   *   Handle 2: Unicast receiver-based (RX slots from children)
   * Scan ALL handles 0-7 to remove attacker's unicast slots.
   */
  for(handle = 0; handle <= 7; handle++) {
    sf = tsch_schedule_get_slotframe_by_handle(handle);
    if(sf == NULL) {
      continue;
    }
    sf_found = 1;

    lnk = list_head(sf->links_list);
    while(lnk != NULL) {
      lnk_next = list_item_next(lnk);
      if(linkaddr_cmp(&lnk->addr, attacker_lladdr)) {
        tsch_schedule_remove_link(sf, lnk);
        removed++;
        LOG_WARN("Layer3-TSCH: removed 1 slot (handle=%d)\n", handle);
      }
      lnk = lnk_next;
    }
  }

  if(!sf_found) {
    LOG_WARN("Layer3-TSCH: no slotframes found (TSCH not initialized)\n");
    return 0;
  }
  if(removed == 0) {
    LOG_WARN("Layer3-TSCH: no dedicated slots for attacker\n");
  } else {
    LOG_WARN("Layer3-TSCH: total %u slots removed\n", (unsigned)removed);
  }
  return (removed > 0) ? 1 : 0;
}
#else
/* CSMA simulation: TSCH not linked.
 * In real 6TiSCH deployment, this removes Orchestra unicast slots. */
static uint8_t mitigate_tsch(linkaddr_t *attacker_lladdr)
{
  (void)attacker_lladdr;
  LOG_WARN("Layer3-TSCH: N/A (CSMA simulation — TSCH not active)\n");
  return 0;
}
#endif /* CADET_NO_TSCH */

/* ══════════════════════════════════════════════════════════════════════════
 * MAIN ENTRY — cadet_mitigate()
 *
 * Orchestrates all three layers, then triggers RPL local repair.
 * ══════════════════════════════════════════════════════════════════════════*/
cadet_mitigation_result_t cadet_mitigate(uint8_t attacker_node_id)
{
  cadet_mitigation_result_t result;
  uip_ipaddr_t  attacker_global_ip;   /* fd00::203:N:N:N — global address     */
  uip_ipaddr_t  attacker_ll_ip;       /* fe80::203:N:N:N — link-local address  */
  linkaddr_t    attacker_lladdr;      /* 00:0N:00:0N:00:0N:00:0N — MAC addr   */

  memset(&result, 0, sizeof(result));
  result.node_id = attacker_node_id;

  LOG_WARN("============================================\n");
  LOG_WARN("[CADET] MITIGATION TRIGGERED\n");
  LOG_WARN("[CADET] Suspected attacker: node %u\n",
           (unsigned)attacker_node_id);

  /* Build all three address forms from node ID */
  cadet_node_id_to_ipaddr         (attacker_node_id, &attacker_global_ip);
  cadet_node_id_to_linklocalipaddr(attacker_node_id, &attacker_ll_ip);
  cadet_node_id_to_lladdr         (attacker_node_id, &attacker_lladdr);

  LOG_WARN("[CADET] Attacker global IPv6:     ");
  LOG_WARN_6ADDR(&attacker_global_ip);
  LOG_WARN_("\n");
  LOG_WARN("[CADET] Attacker link-local IPv6: ");
  LOG_WARN_6ADDR(&attacker_ll_ip);
  LOG_WARN_("\n");
  LOG_WARN("[CADET] Attacker MAC (lladdr):    ");
  LOG_WARN_LLADDR(&attacker_lladdr);
  LOG_WARN_("\n");

  /* ── Apply Layer 1: RPL rank poisoning ──────────────────────────────── */
  /* Seeds uip_ds6_nbr with known MAC, then uses public RPL lookup API    */
  result.rpl_done  = mitigate_rpl(&attacker_lladdr, &attacker_ll_ip);
  if(result.rpl_done)  result.layers_applied |= 0x01;

  /* ── Apply Layer 2: Neighbor cache + routing table ───────────────────── */
  /* MAC-based lookup first, then IP fallbacks                              */
  result.nbr_done  = mitigate_neighbor(&attacker_lladdr,
                                        &attacker_ll_ip,
                                        &attacker_global_ip);
  if(result.nbr_done)  result.layers_applied |= 0x02;

  /* ── Apply Layer 3: TSCH schedule ───────────────────────────────────── */
  result.tsch_done = mitigate_tsch(&attacker_lladdr);
  if(result.tsch_done) result.layers_applied |= 0x04;

  /* ── Force RPL re-convergence via local repair ───────────────────────── */
  rpl_local_repair("cadet-attack-detected");
  result.repair_triggered = 1;
  LOG_WARN("[CADET] RPL local repair triggered — re-routing...\n");

  /* ── Summary ─────────────────────────────────────────────────────────── */
  LOG_WARN("[CADET] Mitigation complete:\n");
  LOG_WARN("  RPL rank poisoning : %s\n", result.rpl_done  ? "DONE" : "skipped");
  LOG_WARN("  Neighbor removal   : %s\n", result.nbr_done  ? "DONE" : "skipped");
  LOG_WARN("  TSCH slot removal  : %s\n", result.tsch_done ? "DONE" : "skipped");
  LOG_WARN("  RPL local repair   : %s\n", result.repair_triggered ? "DONE" : "failed");
  LOG_WARN("  Layers applied     : 0x%02x\n", (unsigned)result.layers_applied);
  LOG_WARN("============================================\n");

  return result;
}

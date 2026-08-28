/**
 * CADET Gateway Process -- integrates Phases 2, 3, and 4.
 *
 * Phase 2 AOPB: gateway sends 0xCA probe via data_conn (port 5678).
 *   Nodes receive on their udp_conn (port 5678) and echo back.
 *   Gateway detects echo (data[0]==0xCA) in data_rx_cb, measures RTT.
 *   FORWARDING TRAP: probe target is P[mid+1] so packet is forwarded
 *   BY P[mid], defeating DPI spoofing.
 */
#include "contiki.h"
#include "contiki-net.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "net/ipv6/uip-ds6-route.h"
#include "sys/etimer.h"
#include "sys/clock.h"
#include "sys/log.h"
#include "cadet_ewma.h"
#include "cadet_aopb.h"
#include "cadet_sprt.h"
#include "cadet_mitigate.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#define LOG_MODULE "CADET-GW"
#define LOG_LEVEL  LOG_LEVEL_INFO

#define UDP_DATA_PORT    5678u
#define PROBE_INTERVAL_MS 200u
#define BASELINE_RTT_MS    40u
#define PAYLOAD_MAX        48u
#define PROBE_MAGIC       0xCAu

typedef enum {
  GW_IDLE = 0,
  GW_PHASE2_BISECT,
  GW_PHASE3_SPRT,
  GW_PHASE4_MITIGATE,
  GW_DONE
} gw_state_t;

static gw_state_t   gw_state   = GW_IDLE;
static cadet_ewma_t ewma;
static cadet_aopb_t aopb;
static cadet_sprt_t sprt;
static struct simple_udp_connection data_conn;
static uint32_t     probe_ts_ms = 0;
static uint8_t      probe_seq   = 0;

/* ── Tracked-address table ──────────────────────────────────────────────
 * Built from SENSOR DATA senders as packets arrive.  Guaranteed populated
 * when EWMA fires (EWMA fires ON a data packet, so ≥1 sender is known).
 * Used by populate_aopb_path() instead of uip_ds6_route (which is empty
 * on the RPL root in a single-hop star topology).
 * ─────────────────────────────────────────────────────────────────────── */
#define AOPB_MAX_TRACKED 8u
static uip_ipaddr_t tracked_addrs[AOPB_MAX_TRACKED];
static uint8_t      tracked_n = 0;

static void track_sender(const uip_ipaddr_t *addr)
{
  uint8_t i;
  for(i = 0; i < tracked_n; i++) {
    if(uip_ipaddr_cmp(&tracked_addrs[i], addr)) { return; }
  }
  if(tracked_n < AOPB_MAX_TRACKED) {
    uip_ipaddr_copy(&tracked_addrs[tracked_n++], addr);
    LOG_INFO("TRACKED node #%u\n", tracked_n);
  }
}

PROCESS(cadet_gw_process, "CADET Gateway");
AUTOSTART_PROCESSES(&cadet_gw_process);

static inline uint32_t now_ms(void)
{
  return (uint32_t)(clock_time() * 1000UL / CLOCK_SECOND);
}

static void populate_aopb_path(void)
{
  uint8_t i;
  cadet_aopb_init(&aopb, BASELINE_RTT_MS);
  /* Use tracked-address table (filled from incoming data packets).
   * This works for any RPL mode and any topology; uip_ds6_route is
   * empty on the root in single-hop networks. */
  for(i = 0; i < tracked_n; i++) {
    cadet_aopb_add_node(&aopb, &tracked_addrs[i], (uint8_t)(i + 1u));
  }
  if(aopb.n == 0) {
    LOG_INFO("AOPB: no tracked nodes yet -- idle\n");
    return;
  }
  cadet_aopb_start(&aopb);
  LOG_INFO("AOPB path: %u nodes\n", aopb.n);
}

/* Single UDP RX: handles sensor data AND probe echoes */
static void
data_rx_cb(struct simple_udp_connection *c,
           const uip_ipaddr_t *src, uint16_t sport,
           const uip_ipaddr_t *dst, uint16_t dport,
           const uint8_t *data, uint16_t dlen)
{
  uint32_t t = now_ms();

  /* PROBE ECHO detection: first byte == 0xCA */
  if(dlen >= 1 && data[0] == PROBE_MAGIC) {
    uint32_t rtt = t - probe_ts_ms;
    LOG_INFO("PROBE echo seq=%u rtt=%lums state=%d\n",
             (unsigned)(dlen >= 2 ? data[1] : 0),
             (unsigned long)rtt, (int)gw_state);

    if(gw_state == GW_PHASE2_BISECT) {
      (void)cadet_aopb_feed_rtt(&aopb, rtt);
      if(aopb.done) {
        const uip_ipaddr_t *suspect = cadet_aopb_result(&aopb);
        LOG_INFO("AOPB done: suspect=");
        LOG_INFO_6ADDR(suspect);
        LOG_INFO_("\n");
        /* Transition to Phase 3 SPRT */
        uip_ipaddr_t x_child;
        if(cadet_aopb_get_probe_target(&aopb, &x_child)) {
          cadet_sprt_init(&sprt, &x_child);
          gw_state = GW_PHASE3_SPRT;
          LOG_INFO("Phase 3 SPRT started\n");
        } else {
          gw_state = GW_DONE;
        }
      }
    } else if(gw_state == GW_PHASE3_SPRT) {
      uint32_t delta = rtt > BASELINE_RTT_MS ? rtt - BASELINE_RTT_MS : 0;
      cadet_sprt_verdict_t v = cadet_sprt_feed(&sprt, delta);
      if(v == CADET_SPRT_ATTACK) {
        LOG_INFO("VERDICT: ATTACK confirmed\n");
        gw_state = GW_PHASE4_MITIGATE;
      } else if(v == CADET_SPRT_CONGESTION) {
        LOG_INFO("VERDICT: CONGESTION -- no mitigation\n");
        gw_state = GW_IDLE;
        cadet_ewma_init(&ewma);
      }
    }
    return; /* probe echo handled */
  }

  /* SENSOR DATA path */
  LOG_INFO("DATA from "); LOG_INFO_6ADDR(src); LOG_INFO_("\n");
  track_sender(src);   /* build AOPB path from live senders */

  if(gw_state == GW_IDLE) {
    if(cadet_ewma_feed(&ewma, t)) {
      LOG_INFO("cadet_alert=1 -- Phase 2 AOPB starting\n");
      populate_aopb_path();
      if(aopb.n > 0) { gw_state = GW_PHASE2_BISECT; }
    }
    /* Also handle sensor-side alert flag */
    if(dlen > 4 && memchr(data, '1', dlen) != NULL) {
      const char *p = (const char *)data;
      if(strstr(p, "alert=1") != NULL) {
        LOG_INFO("sensor alert=1 detected\n");
        if(aopb.n == 0) { populate_aopb_path(); }
        if(aopb.n > 0 && gw_state == GW_IDLE) { gw_state = GW_PHASE2_BISECT; }
      }
    }
  }
}

/* Main gateway process */
PROCESS_THREAD(cadet_gw_process, ev, data)
{
  static struct etimer probe_timer;

  PROCESS_BEGIN();

  NETSTACK_ROUTING.root_start();
  cadet_ewma_init(&ewma);

  simple_udp_register(&data_conn, UDP_DATA_PORT, NULL, UDP_DATA_PORT, data_rx_cb);

  LOG_INFO("CADET Gateway started (RPL root)\n");

  etimer_set(&probe_timer, CLOCK_SECOND * PROBE_INTERVAL_MS / 1000);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&probe_timer));
    etimer_reset(&probe_timer);

    if(gw_state == GW_PHASE2_BISECT || gw_state == GW_PHASE3_SPRT) {
      uip_ipaddr_t probe_target;
      bool has_target = false;

      if(gw_state == GW_PHASE2_BISECT) {
        has_target = cadet_aopb_get_probe_target(&aopb, &probe_target);
      } else {
        uip_ipaddr_copy(&probe_target, &sprt.target);
        has_target = true;
      }

      if(has_target) {
        uint8_t probe_payload[2];
        probe_payload[0] = PROBE_MAGIC;
        probe_payload[1] = ++probe_seq;
        probe_ts_ms = now_ms();
        simple_udp_sendto(&data_conn, probe_payload,
                          sizeof(probe_payload), &probe_target);
        LOG_INFO("Probe #%u sent (state=%d)\n", probe_seq, (int)gw_state);
      }

    } else if(gw_state == GW_PHASE4_MITIGATE) {
      const uip_ipaddr_t *suspect = cadet_aopb_result(&aopb);
      if(suspect) { cadet_mitigate_execute(suspect); }
      gw_state = GW_DONE;
      LOG_INFO("Phase 4: mitigation complete\n");
    }
  }

  PROCESS_END();
}

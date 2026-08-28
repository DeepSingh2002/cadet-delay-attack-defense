/**
 * CADET Phase 1/2 — Sensor Node Process
 *
 * Topology (Cooja, 6 motes):
 *   Mote 1  — RPL root (runs cadet-gateway.c)
 *   Motes 2-5 — sensor nodes (this file)
 *   Mote 6  — attacker (this file, floods network)
 *
 * Phase 2 probe-echo (Option B, Active Oracle):
 *   Gateway sends 0xCA probe via port 5678.
 *   Node echoes it back so gateway can measure RTT for bisection.
 *   FORWARDING TRAP: gateway targets P[mid+1]; P[mid] must forward
 *   the packet, defeating DPI-based spoofing of the reply.
 */
#include "contiki.h"
#include "contiki-net.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "sys/clock.h"
#include "sys/etimer.h"
#include "sys/log.h"
#include "cadet_ewma.h"
#include <stdio.h>
#include <string.h>

#define LOG_MODULE "CADET-NODE"
#define LOG_LEVEL  LOG_LEVEL_INFO

#define UDP_PORT        5678u
#define SEND_INTERVAL_S    5u
#define PAYLOAD_MAX       48u

static volatile uint8_t  cadet_alert = 0;
static cadet_ewma_t      ewma;
static struct simple_udp_connection udp_conn;

PROCESS(cadet_p1_process, "CADET Phase 1");
AUTOSTART_PROCESSES(&cadet_p1_process);

static void udp_rx_cb(struct simple_udp_connection *c,
                      const uip_ipaddr_t *src, uint16_t src_port,
                      const uip_ipaddr_t *dst, uint16_t dst_port,
                      const uint8_t *data, uint16_t datalen)
{
  /* ── CADET Phase 2 Option-B probe-echo (Active Oracle) ──────────────
   * First byte 0xCA => this is an AOPB probe from the gateway.
   * Echo it back immediately so gateway can measure RTT.
   * Forwarding Trap: gateway targets P[mid+1] so P[mid] must forward,
   * preventing P[mid] from spoofing the echo via DPI.               */
  if(datalen >= 1 && ((const uint8_t *)data)[0] == 0xCAu) {
    simple_udp_sendto(c, data, datalen, src);
    printf("[CADET-NODE] PROBE echo seq=%u\n",
           (unsigned)((const uint8_t *)data)[1]);
    return;
  }

  /* ── Normal gateway ACK/data path ── */
  uint32_t now_ms = (uint32_t)(clock_time() * 1000UL / CLOCK_SECOND);
  LOG_INFO("RX ts=%lums\n", (unsigned long)now_ms);

  if(cadet_ewma_feed(&ewma, now_ms)) {
    cadet_alert = 1;
    LOG_INFO("*** cadet_alert=1  Phase 2 AOPB triggered ***\n");
  }

  /* Echo ACK with alert status */
  char reply[PAYLOAD_MAX];
  int rlen = snprintf(reply, sizeof(reply), "ACK cadet_alert=%u", cadet_alert);
  simple_udp_sendto(&udp_conn, reply, (uint16_t)rlen, src);
  cadet_alert = 0;
}

PROCESS_THREAD(cadet_p1_process, ev, data)
{
  static struct etimer t;
  static uint32_t seq = 0;
  char payload[PAYLOAD_MAX];

  PROCESS_BEGIN();
  cadet_ewma_init(&ewma);
  simple_udp_register(&udp_conn, UDP_PORT, NULL, UDP_PORT, udp_rx_cb);
  LOG_INFO("CADET Node started\n");

  /* Wait 30 s for RPL DAG to form */
  etimer_set(&t, CLOCK_SECOND * 30);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&t));
  LOG_INFO("RPL ready -- monitoring started\n");

  etimer_set(&t, CLOCK_SECOND * SEND_INTERVAL_S);
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&t));
    etimer_reset(&t);

    if(!NETSTACK_ROUTING.node_is_root()) {
      uip_ipaddr_t root_addr;
      if(NETSTACK_ROUTING.get_root_ipaddr(&root_addr)) {
        seq++;
        int plen = snprintf(payload, sizeof(payload),
                            "D%lu alert=%u",
                            (unsigned long)seq, cadet_alert);
        simple_udp_sendto(&udp_conn, payload, (uint16_t)plen, &root_addr);
        LOG_INFO("TX seq=%lu cadet_alert=%u\n",
                 (unsigned long)seq, (unsigned)cadet_alert);
        cadet_alert = 0;
      }
    }
  }
  PROCESS_END();
}

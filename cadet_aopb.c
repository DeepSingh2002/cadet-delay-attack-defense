/**
 * CADET Phase 2 — Active-Oracle Probabilistic Bisection Implementation
 *
 * Oracle construction (mini-SPRT per bisection step):
 *
 *   H_0: RTT ~ N(μ_0, σ²)           — node is NOT under attack
 *   H_1: RTT ~ N(μ_1, σ²),  μ_1 = 3μ_0 — node IS under attack
 *
 * LLR update for Gaussian sequential test:
 *   ΔLLR = (rtt - μ_0)(μ_1 - μ_0)/σ² - (μ_1² - μ_0²)/(2σ²)
 *        = (rtt - μ_0)(μ_1 - μ_0)/σ² - (μ_1 + μ_0)(μ_1 - μ_0)/(2σ²)
 *        = (μ_1 - μ_0)/σ² × [rtt - (μ_0 + μ_1)/2]
 *
 * With μ_0 = baseline, μ_1 = 3·baseline, δ = μ_1-μ_0 = 2·baseline:
 *   ΔLLR = (2·baseline/σ²) × [rtt - 2·baseline]
 *
 * σ² ≈ baseline² (Poisson-style noise floor for TSCH).
 * All arithmetic in fixed-point (× 1000).
 */
#include "cadet_aopb.h"
#include "sys/log.h"
#include <string.h>

#define LOG_MODULE "CADET-P2"
#define LOG_LEVEL  LOG_LEVEL_INFO

void
cadet_aopb_init(cadet_aopb_t *s, uint32_t baseline_rtt_ms)
{
  memset(s, 0, sizeof(*s));
  s->baseline_rtt_ms = baseline_rtt_ms ? baseline_rtt_ms : 40; /* 40ms default */
}

void
cadet_aopb_add_node(cadet_aopb_t *s, const uip_ipaddr_t *addr, uint8_t hop)
{
  if(s->n >= CADET_AOPB_MAX_PATH) { return; }
  uip_ipaddr_copy(&s->path[s->n].addr, addr);
  s->path[s->n].hop = hop;
  s->n++;
}

void
cadet_aopb_start(cadet_aopb_t *s)
{
  s->lo         = 0;
  s->hi         = s->n > 0 ? s->n - 1 : 0;
  s->mid        = (s->lo + s->hi) / 2;
  s->llr_fp     = 0;
  s->done       = false;
  s->probe_count = 0;
  LOG_INFO("AOPB start: %u nodes, lo=%u hi=%u mid=%u\n",
           s->n, s->lo, s->hi, s->mid);
}

cadet_oracle_verdict_t
cadet_aopb_feed_rtt(cadet_aopb_t *s, uint32_t rtt_ms)
{
  if(s->done) { return CADET_ORACLE_ANOMALOUS; }

  uint32_t mu0 = s->baseline_rtt_ms;           /* H_0 mean              */
  uint32_t mu1 = 3 * mu0;                       /* H_1 mean = 3×baseline */

  /* ΔLLR = (mu1 - mu0)/sigma² × [rtt - (mu0+mu1)/2]
   * sigma² = mu0² (noise model)
   * All × 1000 for fixed-point                                        */
  int64_t delta_mu  = (int64_t)(mu1 - mu0);           /* = 2*mu0        */
  int64_t mid_mu    = (int64_t)((mu0 + mu1) / 2);     /* = 2*mu0        */
  int64_t sigma_sq  = (int64_t)(mu0 * mu0);
  int64_t x_minus_m = (int64_t)rtt_ms - mid_mu;
  int64_t delta_llr = (delta_mu * x_minus_m * 1000) / sigma_sq; /* × 1000 */

  s->llr_fp += (int32_t)delta_llr;
  s->probe_count++;

  LOG_INFO("probe #%u rtt=%lums llr=%ld/1000 (A=%d B=%d)\n",
           s->probe_count, (unsigned long)rtt_ms,
           (long)s->llr_fp, CADET_AOPB_LOGA_FP, CADET_AOPB_LOGB_FP);

  /* Check SPRT boundaries */
  if(s->llr_fp >= CADET_AOPB_LOGA_FP) {
    LOG_INFO("Oracle H_1: mid=%u IS anomalous\n", s->mid);
    /* Attacked node is in [lo..mid] → hi = mid */
    s->hi         = s->mid;
    s->llr_fp     = 0;
    s->probe_count = 0;
    if(s->hi - s->lo <= 1) {
      s->done       = true;
      s->result_idx = s->lo;
      LOG_INFO("AOPB done: suspect idx=%u\n", s->result_idx);
      return CADET_ORACLE_ANOMALOUS;
    }
    s->mid = (s->lo + s->hi) / 2;
    LOG_INFO("Bisect → mid=%u\n", s->mid);
    return CADET_ORACLE_ANOMALOUS;

  } else if(s->llr_fp <= CADET_AOPB_LOGB_FP) {
    LOG_INFO("Oracle H_0: mid=%u is normal\n", s->mid);
    /* Attacked node is in [mid..hi] → lo = mid */
    s->lo         = s->mid;
    s->llr_fp     = 0;
    s->probe_count = 0;
    if(s->hi - s->lo <= 1) {
      s->done       = true;
      s->result_idx = s->hi;
      LOG_INFO("AOPB done: suspect idx=%u\n", s->result_idx);
      return CADET_ORACLE_NORMAL;
    }
    s->mid = (s->lo + s->hi) / 2;
    LOG_INFO("Bisect → mid=%u\n", s->mid);
    return CADET_ORACLE_NORMAL;
  }

  return CADET_ORACLE_UNKNOWN; /* keep probing */
}

bool
cadet_aopb_get_probe_target(const cadet_aopb_t *s, uip_ipaddr_t *out_child)
{
  /* FORWARDING TRAP: probe P[mid-1] so the packet must be
   * forwarded BY P[mid], preventing a smart attacker at P[mid]
   * from spoofing the reply via DPI (Directive §3). */

  /* Forwarding Trap fix: probe the CHILD of mid (mid+1 in path),
   * routing the probe THROUGH mid as forwarder. This exposes mid's
   * MAC-layer buffer congestion regardless of DPI/payload inspection. */
  if(s->mid + 1 >= s->n) {
    /* mid IS the leaf — probe mid directly */
    if(s->n > 0) {
      uip_ipaddr_copy(out_child, &s->path[(s->mid > 0 ? s->mid - 1 : 0)].addr);
      return true;
    }
    return false;
  }
  uip_ipaddr_copy(out_child, &s->path[s->mid + 1].addr);
  return true;
}

const uip_ipaddr_t *
cadet_aopb_result(const cadet_aopb_t *s)
{
  if(!s->done || s->result_idx >= s->n) { return NULL; }
  return &s->path[s->result_idx].addr;
}

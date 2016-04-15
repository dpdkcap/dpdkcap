#include <stdbool.h>
#include <signal.h>
#include <string.h>

#include <rte_log.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>

#include "core_capture.h"

#define RTE_LOGTYPE_DPDKCAP RTE_LOGTYPE_USER1

/*
 * Capture the traffic from the given port/queue tuple
 */
int capture_core(const struct core_capture_config * config) {
  RTE_LOG(INFO, DPDKCAP, "Core %u is capturing packets for port %u\n",
    rte_lcore_id(), config->port);

  /* Run until the application is quit or killed. */
  for (;;) {
    struct rte_mbuf *bufs[DPDKCAP_CAPTURE_BURST_SIZE];
    const uint16_t nb_rx =
        rte_eth_rx_burst(config->port, config->queue,
            bufs, DPDKCAP_CAPTURE_BURST_SIZE);
    if (unlikely(*(config->stop_condition))) {
      break;
    }
    if (likely(nb_rx > 0)) {
      int retval = rte_ring_enqueue_burst(config->ring, (void*) bufs,
          nb_rx);

      //Free whatever we can't put in the write ring
      for (; retval < nb_rx; retval++) {
        rte_pktmbuf_free(bufs[retval]);
      }
    }
  }
  RTE_LOG(INFO, DPDKCAP, "Closed capture core %d (port %d)\n",
    rte_lcore_id(), config->port);
  return 0;
}

#ifndef DPDKCAP_CORE_CAPTURE_H
#define DPDKCAP_CORE_CAPTURE_H

#include <stdint.h>

#define DPDKCAP_CAPTURE_BURST_SIZE 256

/* Core configuration structures */
struct core_capture_config {
  struct rte_ring * ring;
  bool * stop_condition;
  uint8_t port;
  uint8_t queue;
};

/* Launches a capture task */
int capture_core(const struct core_capture_config * config);

#endif

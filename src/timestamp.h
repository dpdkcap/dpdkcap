#ifndef DPDKCAP_TIMESTAMP_H
#define DPDKCAP_TIMESTAMP_H

#include <sys/time.h>

#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>
#include <rte_time.h>

uint64_t *timestamp_field(struct rte_mbuf *mbuf);

void register_timestamp_dynfield();

#endif

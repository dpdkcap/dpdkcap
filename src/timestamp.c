
#include "timestamp.h"

static int timestamp_dynfield_offset = -1;
static uint64_t timestamp_dynfield_flag = 0;

inline uint64_t *timestamp_field(struct rte_mbuf *mbuf)
{
	return RTE_MBUF_DYNFIELD(mbuf, timestamp_dynfield_offset,
				 rte_mbuf_timestamp_t *);
}

void register_timestamp_dynfield()
{
	rte_mbuf_dyn_rx_timestamp_register(&timestamp_dynfield_offset,
					   &timestamp_dynfield_flag);
	if (timestamp_dynfield_offset < 0) {
		printf("ERROR: Failed to register timestamp field\n");
		rte_exit(1, "dynfield register failed");
	}
}

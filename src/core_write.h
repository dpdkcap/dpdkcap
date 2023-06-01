#ifndef DPDKCAP_CORE_WRITE_H
#define DPDKCAP_CORE_WRITE_H

#include <stdbool.h>
#include <stdint.h>
#include "tasks.h"

#define DPDKCAP_OUTPUT_FILENAME_LENGTH 100
#define DPDKCAP_WRITE_BURST_SIZE 256

/* Writing core configuration */
struct core_write_config {
	struct rte_ring *ring;
	bool volatile *stop_condition;
	struct core_write_stats *stats;
	struct taskdir *taskdir;
};

/* Statistics structure */
struct core_write_stats {
	int core_id;
	char output_file[DPDKCAP_OUTPUT_FILENAME_LENGTH];
	uint64_t current_file_packets;
	uint64_t current_file_bytes;
	uint64_t current_file_compressed_bytes;
	uint64_t packets;
	uint64_t bytes;
	uint64_t compressed_bytes;
};

/* Launches a write task */
int write_core(const struct core_write_config *config);

#endif

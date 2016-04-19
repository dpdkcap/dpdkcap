#ifndef DPDKCAP_CORE_WRITE_H
#define DPDKCAP_CORE_WRITE_H

#include <stdbool.h>

#define DPDKCAP_OUTPUT_FILENAME_LENGTH 100
#define DPDKCAP_WRITE_BURST_SIZE 256

/* Writing core configuration */
struct core_write_config {
  struct rte_ring * ring;
  bool volatile * stop_condition;
  char * output_file_template;
  struct core_write_stats * stats;
  unsigned int snaplen;
  unsigned long rotate_seconds;
  unsigned long file_size_limit;
};

/* Statistics structure */
struct core_write_stats {
  int core_id;
  char output_file[DPDKCAP_OUTPUT_FILENAME_LENGTH];
  unsigned long current_file_packets;
  unsigned long current_file_bytes;
  unsigned long current_file_compressed_bytes;
  unsigned long packets;
  unsigned long bytes;
  unsigned long compressed_bytes;
};

/* Launches a write task */
int write_core(const struct core_write_config * config);

#endif

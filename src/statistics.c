#include "statistics.h"

#include <signal.h>

#include <rte_ethdev.h>
#include <rte_timer.h>
#include <rte_ring.h>
#include <rte_log.h>

#include "utils.h"


#define RTE_LOGTYPE_DPDKCAP RTE_LOGTYPE_USER1

#define STATS_PERIOD_MS 500
#define ROTATING_CHAR "-\\|/"

/*
 * Prints a set of stats
 */
static int print_stats(
    __attribute__((unused))struct rte_timer * timer,
    struct stats_data * data) {
  static unsigned int nb_stat_update = 0;
  static struct rte_eth_stats port_statistics;

  uint64_t total_packets = 0;
  uint64_t total_bytes = 0;
  uint64_t total_compressedbytes = 0;
  unsigned int i, j;

  nb_stat_update ++;

  for (i=0; i<data->cores_write_stats_list_size; i++) {
    total_packets += data->cores_stats_write_list[i].packets;
    total_bytes += data->cores_stats_write_list[i].bytes;
    total_compressedbytes += data->cores_stats_write_list[i].compressed_bytes;
  }

  printf("\e[1;1H\e[2J");
  printf("=== Packet capture statistics %c ===\n",
      ROTATING_CHAR[nb_stat_update%4]);

  printf("-- GLOBAL --\n");
  printf("Entries free on ring: %u\n", rte_ring_free_count(data->ring));
  printf("Total packets written: %lu\n", total_packets);
  printf("Total bytes written: %s ", bytes_format(total_bytes));
  printf("compressed to %s\n", bytes_format(total_compressedbytes));
  printf("Compressed/uncompressed size ratio: 1 / %.2f\n",
      total_compressedbytes?
      (float)total_bytes/(float)total_compressedbytes:0.0f);

  printf("-- PER WRITING CORE --\n");
  for (i=0; i<data->cores_write_stats_list_size; i++) {
    printf("Writing core %d: %s ",
        data->cores_stats_write_list[i].core_id,
        data->cores_stats_write_list[i].output_file);
    printf("(%s)\n", bytes_format(
          data->cores_stats_write_list[i].current_file_compressed_bytes));
  }

  printf("-- PER PORT --\n");
  for (i=0; i<data->port_list_size; i++) {
    rte_eth_stats_get(data->port_list[i], &port_statistics);
    printf("- PORT %d -\n", data->port_list[i]);
    printf("Built-in counters:\n" \
        "  RX Successful packets: %lu\n" \
        "  RX Successful bytes: %s (avg: %d bytes/pkt)\n" \
        "  RX Unsuccessful packets: %lu\n" \
        "  RX Missed packets: %lu\n  No MBUF: %lu\n",
        port_statistics.ipackets,
        bytes_format(port_statistics.ibytes),
        port_statistics.ipackets?
        (int)((float)port_statistics.ibytes/(float)port_statistics.ipackets):0,
        port_statistics.ierrors,
        port_statistics.imissed, port_statistics.rx_nombuf);
    printf("Per queue:\n");
    for (j=0; j<data->queue_per_port; j++) {
      printf("  Queue %d RX: %lu RX-Error: %lu\n", j,
          port_statistics.q_ipackets[j], port_statistics.q_errors[j]);
    }
    printf("  (%d queues hidden)\n",
        RTE_ETHDEV_QUEUE_STAT_CNTRS - data->queue_per_port);
  }

  printf("===================================\n");
  return 0;
}

/*
 * Handles signals
 */
static bool should_stop = false;
static void signal_handler(int sig) {
  RTE_LOG(NOTICE, DPDKCAP, "Caught signal %s on core %u%s\n",
      strsignal(sig), rte_lcore_id(),
      rte_get_master_lcore()==rte_lcore_id()?" (MASTER CORE)":"");
  should_stop = true;
}

static struct rte_timer stats_timer;

void start_stats_display(struct stats_data * data) {
  signal(SIGINT,signal_handler);
  //Initialize timers
  rte_timer_subsystem_init();
  //Timer launch
  rte_timer_init (&(stats_timer));
  rte_timer_reset(&(stats_timer), 2000000ULL * STATS_PERIOD_MS, PERIODICAL,
      rte_lcore_id(), (void*) print_stats, data);
  //Wait for ctrl+c
  for (;;) {
    if (unlikely(should_stop)) {
      break;
    }
    rte_timer_manage();
  }
  rte_timer_stop(&(stats_timer));
  signal(SIGINT,SIG_DFL);
}

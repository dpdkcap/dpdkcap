/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <argp.h>
#include <inttypes.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_atomic.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_timer.h>
#include <rte_mbuf.h>
#include <sys/time.h>

#include "lzo/lzowrite.h"
#include "lzo/minilzo.h"
#include "pcap.h"

#define MIN(a,b) (((a)<(b))?(a):(b))

#define RX_RING_SIZE 1024 //256
#define TX_RING_SIZE 512 //512

#define NUM_MBUFS 65536 //2048
#define MBUF_CACHE_SIZE 256 //0
#define BURST_SIZE 256 //128
#define WRITE_RING_SIZE NUM_MBUFS


/* ARGP */
const char *argp_program_version = "dpdkcap 0.1";
const char *argp_program_bug_address = "w.b.devries@utwente.nl";
static char doc[] = "A DPDK-based packet capture tool";
static char args_doc[] = "";
static struct argp_option options[] = {
                { "output", 'o', "FILE", 0, "Output to FILE (don't add the extension) (default: output)", 0 },
                { "statistics", 'S', 0, 0, "Print statistics every few seconds", 0 },
                { "num_c_cores", 'c', "NUM", 0, "Number of cores used for capture (default: 1)", 0 },
                { "portmask", 'p', "PORTMASK", 0, "Ethernet ports mask (default: 0x1)", 0 },
                { "num_w_cores", 'w', "NUM", 0, "Number of cores used for writing (default: 1)", 0 },
                { "snaplen", 's', "LENGTH", 0, "Snap the capture to snaplen bytes (default: 65535).", 0 },
		{ 0 } };
struct arguments {
	char* args[2];
	const char* output;
	uint64_t portmask;
	int statistics;
	unsigned int num_c_cores;
	unsigned int num_w_cores;
        unsigned int snaplen;
};

static error_t parse_opt(int key, char* arg, struct argp_state *state) {
	struct arguments* arguments = state->input;
        char *end;

	switch (key) {
	case 'p':
		/* parse hexadecimal string */
        	arguments->portmask = strtoul(arg, &end, 16);
    		if (errno != 0 || *end != '\0' || (arguments->portmask == ULONG_MAX && errno == ERANGE)) {
        		fprintf(stderr, "Invalid portmask '%s' (could not convert to unsigned long)\n", arg);
			return EINVAL;
                }
        	if (arguments->portmask == 0) {
        		fprintf(stderr, "Invalid portmask '%s', no port used\n", arg);
                	return EINVAL;
                }
		break;
	case 'o':
		arguments->output = arg;
		break;
	case 'S':
		arguments->statistics = 1;
		break;
	case 'c':
		arguments->num_c_cores = atoi(arg);
		break;
	case 'w':
		arguments->num_w_cores = atoi(arg);
		break;
	case 's':
		arguments->snaplen = atoi(arg);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}
static struct argp argp = { options, parse_opt, args_doc, doc, 0, 0, 0 };
/* END OF ARGP */

static volatile bool ctrlc_caught = 0;

static struct rte_ring *write_ring;
static struct rte_eth_stats *port_statistics;

static unsigned long buffer_to_ring_failed = 0;

struct arguments arguments;

/* Statistics related structures */
struct core_stats_write {
  int packets;
};

static struct core_stats_write * cores_stats_write_list;

/* Core configuration structures */
struct core_config_capture {
  uint8_t port;
  uint8_t queue;
};

struct core_config_write {
  const char* output;
  struct core_stats_write * stats;
};

static const struct rte_eth_conf port_conf_default = { .rxmode = {
		.max_rx_pkt_len = ETHER_MAX_LEN } };





/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static int port_init(uint8_t port, struct rte_mempool *mbuf_pool) {
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = arguments.num_c_cores, tx_rings = 1;
	int retval;
	uint16_t q;

	//Configure multiqueue
	if (arguments.num_c_cores > 1) {
		port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS; //Activate Receive Side Scaling
		port_conf.rx_adv_conf.rss_conf.rss_key = NULL; //Random hash key
		port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_UDP | ETH_RSS_TCP; //Applies hash on UDP/TDP packets
	}

	if (port >= rte_eth_dev_count())
		return -1;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		printf("Creating queue %d\n", q);
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct ether_addr addr;
	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
	" %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n", (unsigned) port,
			addr.addr_bytes[0], addr.addr_bytes[1], addr.addr_bytes[2],
			addr.addr_bytes[3], addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);

	return 0;
}

static void signal_handler(int dummy) {
	printf("Caught signal %d on core %u\n", dummy, rte_lcore_id());
	if (rte_lcore_index(rte_lcore_id()) == 0) { //Master core
		ctrlc_caught = 1;
	}
}

static int capture_core(struct core_config_capture * config) {
	uint8_t port = config->port;
	uint8_t queue = config->queue; //rte_lcore_index(rte_lcore_id()) - 1;

	signal(SIGINT, signal_handler);
	printf("Core %u is capturing packets for port %u\n", rte_lcore_id(), port);

	/* Run until the application is quit or killed. */
	for (;;) {
		struct rte_mbuf *bufs[BURST_SIZE];
		const uint16_t nb_rx = rte_eth_rx_burst(port, queue, bufs, BURST_SIZE);
		if (unlikely(ctrlc_caught == 1)) {
			break;
		}
		if (likely(nb_rx > 0)) {
			int retval = rte_ring_enqueue_burst(write_ring, (void*) bufs,
					nb_rx);

			//Free whatever we can't put in the write ring
			for (; retval < nb_rx; retval++) {
				rte_pktmbuf_free(bufs[retval]);
			}
		}
	}
        free(config);
	printf("Closed capture core %d\n",rte_lcore_id());
	return 0;
}

static int write_core(struct core_config_write * config) {
	//Setup write buffer
	struct lzowrite_buffer* write_buffer = lzowrite_init(config->output);
	if (!write_buffer) return -1;
        signal(SIGINT, signal_handler);
	printf("Core %d is writing in file : %s.\n", rte_lcore_id(), config->output);

        //Write pcap header
	struct pcap_header* pcp = pcap_header_create(arguments.snaplen);
	lzowrite32(write_buffer, pcp->magic_number);
	lzowrite16(write_buffer, pcp->version_major);
	lzowrite16(write_buffer, pcp->version_minor);
	lzowrite32(write_buffer, pcp->thiszone);
	lzowrite32(write_buffer, pcp->sigfigs);
	lzowrite32(write_buffer, pcp->snaplen);
	lzowrite32(write_buffer, pcp->network);
	free(pcp);

	unsigned char* eth;
	unsigned int packet_length, wire_packet_length;
	int result;
	void* dequeued[BURST_SIZE];
	struct rte_mbuf* bufptr;
	struct pcap_packet_header header;
	struct timeval tv;

	for (;;) {
		if (unlikely(ctrlc_caught == 1)) {
			break;
		}
		//Get packets from the ring
		result = rte_ring_dequeue_burst(write_ring, dequeued, BURST_SIZE);
		if (result == 0) {
			continue;
		}

		//Increase the packet counter
		config->stats->packets += result;

		int i;
		for (i = 0; i < result; i++) {
			//Cast to packet
			bufptr = dequeued[i];
			eth = rte_pktmbuf_mtod(bufptr, unsigned char*);
			wire_packet_length = rte_pktmbuf_pkt_len(bufptr);
                        /* Truncate packet if needed */
			packet_length = MIN(arguments.snaplen,wire_packet_length);

			//Write block header
			gettimeofday(&tv, NULL);
			header.timestamp = (int32_t) tv.tv_sec;
			header.microseconds = (int32_t) tv.tv_usec;
                        header.packet_length = packet_length;
                        header.packet_length_wire = wire_packet_length;
			lzowrite(write_buffer, &header, sizeof(struct pcap_packet_header));

			//Write content
			lzowrite(write_buffer, eth, sizeof(char) * packet_length);

			//Free buffer
			rte_pktmbuf_free(bufptr);
		}
	}
	//Close pcap file
	lzowrite_free(write_buffer);
        free(config);
	printf("Closed writing core %d\n",rte_lcore_id());
	return 0;
}


static int print_stats(void) {
	unsigned int i;
	rte_eth_stats_get(0, port_statistics);

	long total_packets = 0;
	for (i = 0; i<arguments.num_w_cores; i++) {
	      total_packets += cores_stats_write_list[i].packets;
	}

	printf("\e[1;1H\e[2J");
	printf("===Packet capture statistics====\n");
	printf(
			"--Built-in counters--\nRX Successful packets: %lu\nRX Unsuccessful packets: %lu\nRX Missed packets: %lu\nNo MBUF: %lu\n",
			port_statistics->ipackets, port_statistics->ierrors,
			port_statistics->imissed, port_statistics->rx_nombuf);
	for (i = 0; i < RTE_ETHDEV_QUEUE_STAT_CNTRS; i++) {
		printf("Queue %d RX: %lu RX-Error: %lu\n", i,
				port_statistics->q_ipackets[i], port_statistics->q_errors[i]);
	}
	printf("--Other counters--\n");
	printf("Entries free on ring: %u\n", rte_ring_free_count(write_ring));
	printf("Total packets in master: %lu\n", total_packets);
	printf("Put buffer into ring failures: %lu\n", buffer_to_ring_failed);
	if (total_packets > 0) {
		printf("Total percentage captured: %.2f%%\n",
				((float) total_packets) / port_statistics->ipackets
						* 100.0);
	}
	printf("================================\n");
	return 0;
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int main(int argc, char *argv[]) {
	signal(SIGINT, signal_handler);
	unsigned int portlist[64];
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint8_t portid;
	unsigned int i;


	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	/* Parse arguments */
	arguments.statistics = 0;
	arguments.output = "output";
	arguments.num_c_cores = 1;
	arguments.num_w_cores = 1;
	arguments.snaplen = PCAP_SNAPLEN_DEFAULT;
	arguments.portmask = 0x1;
        argp_parse(&argp, argc, argv, 0, 0, &arguments);

	/* Creates the port list */
	nb_ports = 0;
	for (i = 0; i < (unsigned)RTE_MIN(64, rte_eth_dev_count()); i++) {
		if (! ((uint64_t)(1ULL << i) & arguments.portmask))
			continue;
		portlist[nb_ports++] = i;
	}
	printf("Using %u ports to listen on\n", nb_ports);

	if (nb_ports > rte_lcore_count() - 1)
		rte_exit(EXIT_FAILURE,
				"Error: Atleast one core is required per port\n");

	unsigned int required_cores = ((arguments.num_c_cores
			+ arguments.num_w_cores) + 1);
	if (rte_lcore_count() < required_cores) {
		rte_exit(EXIT_FAILURE, "Assign at least %d cores to dpdkcap\n",
				required_cores);
	}

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
	MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize all ports. */
	for (portid = 0; portid < nb_ports; portid++) {
		int8_t retval = port_init(portid, mbuf_pool);
		if (retval != 0) {
			printf("Error: %d\n", retval);
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n", portid);
		}
	}

	//Initialize buffer for writing to disk
	write_ring = rte_ring_create("Ring for writing",
			rte_align32pow2 (WRITE_RING_SIZE), rte_socket_id(), 0);

	//Initialize statistics timer
	rte_timer_subsystem_init();
	struct rte_timer stats_timer;
	rte_timer_init(&stats_timer);
	if (arguments.statistics == 1) {
		rte_timer_reset(&stats_timer, 2000000ULL * 2000, PERIODICAL,
				rte_lcore_id(), (void*) print_stats, NULL);
	}

	//Prepare core configuration
        /* Writing cores */
        unsigned int core_index = rte_get_next_lcore(-1, 1, 0);
        cores_stats_write_list = malloc(sizeof(struct core_stats_write) * arguments.num_w_cores);
        for (i=0; i<arguments.num_w_cores; i++) {
                //Configure writing core
                struct core_config_write * config = malloc(sizeof(struct core_config_write));
		config->stats = &(cores_stats_write_list[i]);
                config->stats->packets = 0;
                char* outputstring = malloc(sizeof(char)*50);
		sprintf(outputstring, "%s_%d.pcap.lzo", arguments.output, core_index);
		config->output = outputstring;
                //Launch writing core
                if (rte_eal_remote_launch((lcore_function_t *) write_core, config, core_index) < 0)
                      rte_exit(EXIT_FAILURE, "Could not launch writing process on lcore %d.\n",core_index);
                core_index = rte_get_next_lcore(core_index, 1, 0);
        }
        /* Capturing cores */
        for (i=0; i<arguments.num_c_cores; i++) {
	        //Configure capture core
                struct core_config_capture * config = malloc(sizeof(struct core_config_capture));
                config->port = portlist[i%nb_ports];
                config->queue = i;
                //Launch capture core
                if (rte_eal_remote_launch((lcore_function_t *) capture_core, config, core_index) < 0)
                      rte_exit(EXIT_FAILURE, "Could not launch capture process on lcore %d.\n",core_index);
                core_index = rte_get_next_lcore(core_index, 1, 0);
	}

	//Setup statistics
	port_statistics = malloc(sizeof(struct rte_eth_stats));

	//Loop until ctrl+c
	for (;;) {
		if (unlikely(ctrlc_caught == 1)) {
			break;
		}
		rte_timer_manage();
	}

	//Finalize
	free(port_statistics);
        free(cores_stats_write_list);

        printf("Waiting for all cores to exit\n");
	//Wait for all the cores to complete and exit
	rte_eal_mp_wait_lcore();

	return 0;
}

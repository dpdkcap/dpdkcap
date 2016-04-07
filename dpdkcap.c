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
                { "num_w_cores", 'w', "NUM", 0, "Number of cores used for writing (default: 1)", 0 },
                { "snaplen", 's', "NUM", 0, "Snap the capture to snaplen bytes (default: 65535).", 0 },
		{ 0 } };
struct arguments {
	char* args[2];
	const char* output;
	int statistics;
	unsigned int num_c_cores;
	unsigned int num_w_cores;
        unsigned int snaplen;
};
static error_t parse_opt(int key, char* arg, struct argp_state *state) {
	struct arguments* arguments = state->input;

	switch (key) {
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

struct core_config {
	enum {
		CORE_CONFIG_NONE, CORE_CONFIG_CAPTURE, CORE_CONFIG_WRITE
	} mode;
	pthread_t pthread;
	const char* output;
	long packets;
};
static struct core_config* core_config;

static const struct rte_eth_conf port_conf_default = { .rxmode = {
		.max_rx_pkt_len = ETHER_MAX_LEN } };

/* basicfwd.c: Basic DPDK skeleton forwarding example. */

static unsigned long upper_power_of_two(unsigned long v) {
	v--;
	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	v++;
	return v;
}

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int port_init(uint8_t port, struct rte_mempool *mbuf_pool) {
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


static int capture_core(void) {
	uint8_t port;
	uint8_t queue;
	port = 0;
	queue = rte_lcore_index(rte_lcore_id()) - 1;

	printf("Core %u is capturing packets for port %u\n", rte_lcore_id(), port);

	/* Run until the application is quit or killed. */
	for (;;) {
		struct rte_mbuf *bufs[BURST_SIZE];
		const uint16_t nb_rx = rte_eth_rx_burst(port, queue, bufs, BURST_SIZE);
		if (likely(nb_rx > 0)) {
			int retval = rte_ring_enqueue_burst(write_ring, (void*) bufs,
					nb_rx);

			//Free whatever we can't put in the write ring
			for (; retval < nb_rx; retval++) {
				rte_pktmbuf_free(bufs[retval]);
			}
		}
	}
	printf("Closed core C\n");
	return 0;
}

static int write_core(void) {
	struct core_config* config = &core_config[rte_lcore_index(rte_lcore_id())];
	//Setup write buffer
	struct lzowrite_buffer* write_buffer = lzowrite_init(config->output);
	printf("Corew %s\n", config->output);
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
		config->packets += result;

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
                        lzowrite(write_buffer, &header.timestamp, sizeof(uint32_t));
			lzowrite(write_buffer, &header.microseconds, sizeof(uint32_t));
			lzowrite(write_buffer, &header.packet_length, sizeof(uint32_t));
			lzowrite(write_buffer, &header.packet_length_wire, sizeof(uint32_t));

			//Write content
			lzowrite(write_buffer, eth, sizeof(char) * packet_length);

			//Free buffer
			rte_pktmbuf_free(bufptr);
		}
	}
	//Close pcap file
	lzowrite_free(write_buffer);
	printf("Closed core W\n");
	return 0;
}

static void signal_handler(int dummy) {
	printf("Caught signal %d on core %u\n", dummy, rte_lcore_id());
	if (rte_lcore_index(rte_lcore_id()) == 0) { //Master core
		ctrlc_caught = 1;
	} else { //Other cores
		//All cores except for the writing ones can exit
		if (core_config[rte_lcore_index(rte_lcore_id())].mode != CORE_CONFIG_WRITE) {
			//pthread_exit();
		}
	}
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
static void lcore_main(void) {
	signal(SIGINT, signal_handler);
	struct core_config config = core_config[rte_lcore_index(rte_lcore_id())];
	config.pthread = pthread_self();
	if (config.mode == CORE_CONFIG_CAPTURE) {
		printf("Core %d is capturing.\n", rte_lcore_id());
		capture_core();
	} else if (config.mode == CORE_CONFIG_WRITE) {
		printf("Core %d is writing.\n", rte_lcore_id());
		write_core();
	} else {
		printf("Core %d has not been assigned a task.\n", rte_lcore_id());
	}
}

static int launch_one_lcore(__attribute__((unused)) void *dummy) {
	lcore_main();
	return 0;
}

static int print_stats(void) {
	unsigned int i;
	rte_eth_stats_get(0, port_statistics);

	long total_packets = 0;
	for (i = 0; i<rte_lcore_count(); i++) {
		total_packets += core_config[i].packets;
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
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint8_t portid;
	unsigned lcore_id;

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
        argp_parse(&argp, argc, argv, 0, 0, &arguments);

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count();
	printf("Found %u ports to listen on\n", nb_ports);

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
			upper_power_of_two(WRITE_RING_SIZE), rte_socket_id(), 0);

	//Initialize statistics timer
	rte_timer_subsystem_init();
	struct rte_timer stats_timer;
	rte_timer_init(&stats_timer);
	if (arguments.statistics == 1) {
		rte_timer_reset(&stats_timer, 2000000ULL * 2000, PERIODICAL,
				rte_lcore_id(), (void*) print_stats, NULL);
	}

	//Prepare core configuration
	core_config = malloc(sizeof(struct core_config) * rte_lcore_count());
	unsigned int core_index = 1, i;
	for (i = 0; i < rte_lcore_count(); i++) {
		core_config[i].mode = CORE_CONFIG_NONE;
		core_config[i].packets = 0;
	}
	for (i = 0; i < arguments.num_c_cores; i++) {
		core_config[core_index].mode = CORE_CONFIG_CAPTURE;
		core_index++;
	}
	for (i = 0; i < arguments.num_w_cores; i++) {
		core_config[core_index].mode = CORE_CONFIG_WRITE;
		char* outputstring = malloc(sizeof(char)*50);
		sprintf(outputstring, "%s_%d.pcap.lzo", arguments.output, core_index);
		core_config[core_index].output = outputstring;
		core_index++;
	}

	core_config[rte_lcore_index(rte_lcore_id())].pthread = pthread_self();

	//Launch the cores
	rte_eal_mp_remote_launch(launch_one_lcore, NULL, SKIP_MASTER);

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

	for (i = 1; i < rte_lcore_count(); i++) {
		pthread_kill(core_config[i].pthread, SIGINT);
	}

	free(core_config);

	printf("Waiting for all cores to exit\n");
	//Wait for all the cores to complete and exit
	RTE_LCORE_FOREACH_SLAVE(lcore_id)
	{
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return -1;
	}

	return 0;
}

#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <argp.h>
#include <inttypes.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memcpy.h>
#include <rte_ethdev.h>

#include "pcap.h"
#include "core_write.h"
#include "core_capture.h"
#include "statistics.h"

#define RX_RING_SIZE 1024 //256
#define TX_RING_SIZE 512 //512

#define NUM_MBUFS 2048
#define MBUF_CACHE_SIZE 256 //0
#define WRITE_RING_SIZE NUM_MBUFS

#define MAX_LCORES 1000

#define DPDKCAP_OUTPUT_TEMPLATE_LENGTH 2 * DPDKCAP_OUTPUT_FILENAME_LENGTH

#define RTE_LOGTYPE_DPDKCAP RTE_LOGTYPE_USER1

/* ARGP */
const char *argp_program_version = "dpdkcap 1.0";
const char *argp_program_bug_address = "w.b.devries@utwente.nl";
static char doc[] = "A DPDK-based packet capture tool";
static char args_doc[] = "";
static struct argp_option options[] = {
  { "output", 'o', "FILE", 0, "Output FILE template (don't add the "\
    "extension). Use \"\%COREID\" for inserting the lcore id into the file " \
      "name (automatically added if not used). (default: output_\%COREID)"
      , 0 },
  { "statistics", 'S', 0, 0, "Print statistics every few seconds.", 0 },
  { "per_port_c_cores", 'c', "NB_CORES_PER_PORT", 0, "Number of cores per " \
    "port used for capture (default: 1)", 0 },
  { "num_w_cores", 'w', "NB_CORES", 0, "Total number of cores used for "\
    "writing (default: 1).", 0 },
  { "rotate_seconds", 'G', "T", 0, "Create a new set of files every T "\
    "seconds. Use strftime formats within the output file template to rename "\
      "each file accordingly.", 0},
  { "limit_file_size", 'C', "SIZE", 0, "Before writing a packet, check "\
    "whether the target file excess SIZE bytes. If so, creates a new file. " \
      "Use \"\%FCOUNT\" within the output file template to index each new "\
      "file.", 0},
  { "portmask", 'p', "PORTMASK", 0, "Ethernet ports mask (default: 0x1).", 0 },
  { "snaplen", 's', "LENGTH", 0, "Snap the capture to snaplen bytes "\
    "(default: 65535).", 0 },
  { "logs", 700, "FILE", 0, "Writes the logs into FILE instead of "\
    "stderr.", 0 },
  { "no-compression", 701, 0, 0, "Do not compress capture files.", 0 },
  { 0 } };

struct arguments {
  char* args[2];
  char output_file_template[DPDKCAP_OUTPUT_FILENAME_LENGTH];
  uint64_t portmask;
  int statistics;
  unsigned int per_port_c_cores;
  unsigned int num_w_cores;
  int no_compression;
  unsigned int snaplen;
  unsigned int rotate_seconds;
  unsigned int file_size_limit;
  char * log_file;
};

static error_t parse_opt(int key, char* arg, struct argp_state *state) {
  struct arguments* arguments = state->input;
  char *end;

  switch (key) {
    case 'p':
      /* parse hexadecimal string */
      errno = 0; // strtoul does not fix errno to 0 on success
      arguments->portmask = strtoul(arg, &end, 16);
      if (errno != 0 || *end != '\0' ||
          (arguments->portmask == ULONG_MAX && errno == ERANGE)) {
        RTE_LOG(ERR, DPDKCAP, "Invalid portmask '%s' (could not convert to "\
            "unsigned long)\n", arg);
        return EINVAL;
      }
      if (arguments->portmask == 0) {
        RTE_LOG(ERR, DPDKCAP, "Invalid portmask '%s', no port used\n", arg);
        return EINVAL;
      }
      break;
    case 'o':
      strncpy(arguments->output_file_template,arg,
          DPDKCAP_OUTPUT_FILENAME_LENGTH);
      break;
    case 'S':
      arguments->statistics = 1;
      break;
    case 'c':
      arguments->per_port_c_cores = atoi(arg);
      break;
    case 'w':
      arguments->num_w_cores = atoi(arg);
      break;
    case 's':
      arguments->snaplen = atoi(arg);
      break;
    case 'G':
      arguments->rotate_seconds = atoi(arg);
      break;
    case 'C':
      arguments->file_size_limit = atoi(arg);
      break;
    case 700:
      arguments->log_file = arg;
      break;
    case 701:
      arguments->no_compression = 1;
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}
static struct argp argp = { options, parse_opt, args_doc, doc, 0, 0, 0 };
/* END OF ARGP */

static struct rte_ring *write_ring;

struct arguments arguments;

static unsigned int portlist[64];
static unsigned int nb_ports;

static struct core_write_stats * cores_stats_write_list;
static struct core_capture_stats* cores_stats_capture_list;

static const struct rte_eth_conf port_conf_default = {
  .rxmode = {
    .mq_mode = ETH_MQ_RX_NONE,
    .max_rx_pkt_len = ETHER_MAX_LEN,
  }
};

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static int port_init(
    uint8_t port,
    const uint16_t rx_rings,
    struct rte_mempool *mbuf_pool) {

  struct rte_eth_conf port_conf = port_conf_default;
  int retval;
  uint16_t q;

  /* Configure multiqueue (Activate Receive Side Scaling on UDP/TCP fields) */
  if (rx_rings > 1) {
    port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
    port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
    port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_PROTO_MASK;
  }

  if (port >= rte_eth_dev_count()) {
    RTE_LOG(ERR, DPDKCAP, "Port identifier %d over the limit (max:%d)\n", port,
       rte_eth_dev_count()-1);
    return -1;
  }

  /* Configure the Ethernet device. */
  retval = rte_eth_dev_configure(port, rx_rings, 1, &port_conf);
  if (retval != 0) {
    RTE_LOG(ERR, DPDKCAP, "rte_eth_dev_configure(...) returned with error "\
        "code %d\n", retval);
    return retval;
  }

  /* Allocate and set up RX queues. */
  for (q = 0; q < rx_rings; q++) {
    retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
        rte_eth_dev_socket_id(port), NULL, mbuf_pool);
    if (retval < 0) {
      RTE_LOG(ERR, DPDKCAP, "rte_eth_rx_queue_setup(...) returned with error "\
          "code %d\n", retval);
      return retval;
    }
    //Stats bindings
    retval = rte_eth_dev_set_rx_queue_stats_mapping (port, q, q);
    if (retval != 0) {
      RTE_LOG(WARNING, DPDKCAP, "rte_eth_dev_set_rx_queue_stats_mapping(...) "\
          "returned with error code %d\n", retval);
      RTE_LOG(WARNING, DPDKCAP, "The queues statistics mapping failed. The "\
         "displayed queue statistics are thus unreliable.\n");
    }
  }

  /* Allocate one TX queue (unused) */
  retval = rte_eth_tx_queue_setup(port, 0, TX_RING_SIZE,
      rte_eth_dev_socket_id(port),NULL);
  if (retval < 0) {
      RTE_LOG(ERR, DPDKCAP, "rte_eth_tx_queue_setup(...) "\
          "returned with error code %d\n", retval);
    return retval;
  }
  /* Enable RX in promiscuous mode for the Ethernet device. */
  rte_eth_promiscuous_enable(port);

  /* Display the port MAC address. */
  struct ether_addr addr;
  rte_eth_macaddr_get(port, &addr);
  RTE_LOG(INFO, DPDKCAP, "Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
      " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n", (unsigned) port,
      addr.addr_bytes[0], addr.addr_bytes[1], addr.addr_bytes[2],
      addr.addr_bytes[3], addr.addr_bytes[4], addr.addr_bytes[5]);

  return 0;
}

/*
 * Starts given port
 */
static int port_start(uint8_t port) {
  int retval = 0;
  /* Start the Ethernet port. */
  retval = rte_eth_dev_start(port);
  return retval;
}


/*
 * Handles signals
 */
static volatile bool should_stop = false;
static void signal_handler(int sig) {
  RTE_LOG(NOTICE, DPDKCAP, "Caught signal %s on core %u%s\n",
      strsignal(sig), rte_lcore_id(),
      rte_get_master_lcore()==rte_lcore_id()?" (MASTER CORE)":"");
  should_stop = true;
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int main(int argc, char *argv[]) {
  signal(SIGINT, signal_handler);
  struct core_capture_config * cores_config_capture_list;
  struct core_write_config   * cores_config_write_list;
  unsigned int lcoreid_list[MAX_LCORES];
  unsigned int nb_lcores;
  struct rte_mempool *mbuf_pool;
  unsigned int port_id;
  unsigned int i,j;
  unsigned int required_cores;
  unsigned int core_index;
  int result;
  FILE * log_file;

  /* Initialize the Environment Abstraction Layer (EAL). */
  int ret = rte_eal_init(argc, argv);
  if (ret < 0)
    rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

  argc -= ret;
  argv += ret;

  /* Parse arguments */
  arguments = (struct arguments) {
    .statistics = 0,
      .per_port_c_cores = 1,
      .num_w_cores = 1,
      .no_compression = 0,
      .snaplen = PCAP_SNAPLEN_DEFAULT,
      .portmask = 0x1,
      .rotate_seconds = 0,
      .file_size_limit = 0,
      .log_file=NULL,
  };
  strncpy(arguments.output_file_template,"output_\%COREID",
      DPDKCAP_OUTPUT_FILENAME_LENGTH);
  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  /* Set log level */
  rte_set_log_type(RTE_LOGTYPE_DPDKCAP, 1);
  rte_set_log_level(RTE_LOG_DEBUG);

  /* Change log stream if needed */
  if(arguments.log_file) {
    log_file = fopen(arguments.log_file, "w");
    if(!log_file) {
    rte_exit(EXIT_FAILURE, "Error: Could not open log file: (%d) %s\n",
        errno, strerror(errno));
    }
    result=rte_openlog_stream(log_file);
    if(result) {
    rte_exit(EXIT_FAILURE, "Error: Could not change log stream: (%d) %s\n",
        errno, strerror(errno));
    }
  }

  /* Add suffixes to output if needed */
  if (!strstr(arguments.output_file_template,"\%COREID"))
    strcat(arguments.output_file_template,"_\%COREID");
  if (arguments.file_size_limit &&
      !strstr(arguments.output_file_template,"\%FCOUNT"))
    strcat(arguments.output_file_template,"_\%FCOUNT");

  strcat(arguments.output_file_template, ".pcap");

  if(!arguments.no_compression)
    strcat(arguments.output_file_template, ".lzo");



  /* Check if one port is available */
  if (rte_eth_dev_count() == 0)
    rte_exit(EXIT_FAILURE, "Error: No port available.\n");

  /* Creates the port list */
  nb_ports = 0;
  for (i = 0; i < 64; i++) {
    if (! ((uint64_t)(1ULL << i) & arguments.portmask))
      continue;
    if (i<rte_eth_dev_count())
      portlist[nb_ports++] = i;
    else
      RTE_LOG(WARNING, DPDKCAP, "Warning: port %d is in portmask, " \
          "but not enough ports are available. Ignoring...\n", i);
  }
  if (nb_ports == 0)
    rte_exit(EXIT_FAILURE, "Error: Found no usable port. Check portmask "\
        "option.\n");

  RTE_LOG(INFO,DPDKCAP,"Using %u ports to listen on\n", nb_ports);

  /* Checks core number */
  required_cores=(1+nb_ports*arguments.per_port_c_cores+arguments.num_w_cores);
  if (rte_lcore_count() < required_cores) {
    rte_exit(EXIT_FAILURE, "Assign at least %d cores to dpdkcap.\n",
        required_cores);
  }
  RTE_LOG(INFO,DPDKCAP,"Using %u cores out of %d allocated\n",
      required_cores, rte_lcore_count());


  /* Creates a new mempool in memory to hold the mbufs. */
  mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
      MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

  if (mbuf_pool == NULL)
    rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");


  //Initialize buffer for writing to disk
  write_ring = rte_ring_create("Ring for writing",
      rte_align32pow2 (WRITE_RING_SIZE), rte_socket_id(), 0);

  /* Core index */
  core_index = rte_get_next_lcore(-1, 1, 0);

  /* Init stats list */
  cores_stats_write_list=
    malloc(sizeof(struct core_write_stats)*arguments.num_w_cores);
  cores_stats_capture_list=
    malloc(sizeof(struct core_capture_stats)*arguments.per_port_c_cores
        *nb_ports);

  /* Init config lists */
  cores_config_write_list=
    malloc(sizeof(struct core_write_config)*arguments.num_w_cores);
  cores_config_capture_list=
    malloc(sizeof(struct core_capture_config)*arguments.per_port_c_cores
        *nb_ports);

  nb_lcores = 0;
  /* Writing cores */
  for (i=0; i<arguments.num_w_cores; i++) {

    //Configure writing core
    struct core_write_config * config = &(cores_config_write_list[i]);
    config->ring = write_ring;
    config->stop_condition = &should_stop;
    config->stats = &(cores_stats_write_list[i]);
    config->output_file_template = arguments.output_file_template;
    config->no_compression = arguments.no_compression;
    config->snaplen = arguments.snaplen;
    config->rotate_seconds = arguments.rotate_seconds;
    config->file_size_limit = arguments.file_size_limit;

    //Launch writing core
    if (rte_eal_remote_launch((lcore_function_t *) write_core,
          config, core_index) < 0)
      rte_exit(EXIT_FAILURE, "Could not launch writing process on lcore %d.\n",
          core_index);

    //Add the core to the list
    lcoreid_list[nb_lcores] = core_index;
    nb_lcores++;

    core_index = rte_get_next_lcore(core_index, SKIP_MASTER, 0);
  }

  /* For each port */
  for (i = 0; i < nb_ports; i++) {
    port_id = portlist[i];

    /* Port init */
    int retval = port_init(port_id, arguments.per_port_c_cores, mbuf_pool);
    if (retval != 0) {
      rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n", port_id);
    }

    /* Capturing cores */
    for (j=0; j<arguments.per_port_c_cores; j++) {
      //Configure capture core
      struct core_capture_config * config =
        &(cores_config_capture_list[i*arguments.per_port_c_cores+j]);
      config->ring = write_ring;
      config->stop_condition = &should_stop;
      config->stats =
        &(cores_stats_capture_list[i*arguments.per_port_c_cores+j]);
      config->port = port_id;
      config->queue = j;
      //Launch capture core
      if (rte_eal_remote_launch((lcore_function_t *) capture_core,
            config, core_index) < 0)
        rte_exit(EXIT_FAILURE, "Could not launch capture process on lcore "\
            "%d.\n",core_index);

      //Add the core to the list
      lcoreid_list[nb_lcores] = core_index;
      nb_lcores++;

      core_index = rte_get_next_lcore(core_index, SKIP_MASTER, 0);
    }

    /* Start the port once everything is ready to capture */
    retval = port_start(port_id);
    if (retval != 0) {
      rte_exit(EXIT_FAILURE, "Cannot start port %"PRIu8 "\n", port_id);
    }
  }

  //Initialize statistics timer
  struct stats_data sd = {
    .ring = write_ring,
    .cores_stats_write_list = cores_stats_write_list,
    .cores_write_stats_list_size = arguments.num_w_cores,
    .cores_stats_capture_list = cores_stats_capture_list,
    .cores_capture_stats_list_size = arguments.per_port_c_cores*nb_ports,
    .port_list=portlist,
    .port_list_size=nb_ports,
    .queue_per_port=arguments.per_port_c_cores,
    .log_file=arguments.log_file,
  };

  if (arguments.statistics && !should_stop) {
    signal(SIGINT, SIG_DFL);
    //End the capture when the interface returns
    start_stats_display(&sd);
    should_stop=true;
  }

  //Wait for all the cores to complete and exit
  RTE_LOG(NOTICE, DPDKCAP, "Waiting for all cores to exit\n");
  for(i=0;i<nb_lcores;i++) {
    result = rte_eal_wait_lcore(lcoreid_list[i]);
    if (result < 0) {
      RTE_LOG(ERR, DPDKCAP, "Core %d did not stop correctly.\n",
          lcoreid_list[i]);
    }
  }

  //Finalize
  free(cores_stats_write_list);

  return 0;
}

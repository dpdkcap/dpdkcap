#include <stdbool.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>

#include <rte_ring.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_branch_prediction.h>

#include "lzo/lzowrite.h"
#include "pcap.h"
#include "utils.h"

#include "core_write.h"

#define MIN(a,b) (((a)<(b))?(a):(b))

#define RTE_LOGTYPE_DPDKCAP RTE_LOGTYPE_USER1

/*
 * Change file name from template
 */
static void format_from_template(
    char * filename,
    const char * template,
    const int core_id,
    const int file_count,
    const struct timeval * file_start
    ) {
  char str_buf[DPDKCAP_OUTPUT_FILENAME_LENGTH];
  //Change file name
  strncpy(filename, template,
      DPDKCAP_OUTPUT_FILENAME_LENGTH);
  snprintf(str_buf, 50, "%02d", core_id);
  while(str_replace(filename,"\%COREID",str_buf));
  snprintf(str_buf, 50, "%03d", file_count);
  while(str_replace(filename,"\%FCOUNT",str_buf));
  strncpy(str_buf, filename, DPDKCAP_OUTPUT_FILENAME_LENGTH);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
  strftime(filename, DPDKCAP_OUTPUT_FILENAME_LENGTH, str_buf,
      localtime(&(file_start->tv_sec)));
#pragma GCC diagnostic pop
}

/*
 * Allocates a new lzowrite_buffer from the given file
 */
static struct lzowrite_buffer * open_lzo_pcap(char * output_file) {
  struct lzowrite_buffer * buffer;
  FILE * file;

  //Open file
  file = fopen(output_file,"w");
  if (unlikely(!file)) {
    RTE_LOG(ERR, DPDKCAP, "Core %d could not open %s in write mode: %d (%s)\n",
        rte_lcore_id(), output_file, errno, strerror(errno));
    goto cleanup;
  }

  //Init lzo file
  buffer = lzowrite_init(file);
  if(unlikely(!buffer)) {
    RTE_LOG(ERR, DPDKCAP, "Core %d could not init lzo in file: %s\n",
        rte_lcore_id(), output_file);
    goto cleanup_file;
  }

  return buffer;
cleanup_file:
  fclose(file);
cleanup:
  return NULL;
}

/*
 * Free a lzowrite_buffer
 */
static int close_lzo_pcap(struct lzowrite_buffer * buffer) {
  FILE * file = buffer->output;
  int retval = 0;

  /* Closes the lzo buffer */
  retval = lzowrite_close(buffer);
  if (unlikely(retval)) {
    retval = -1;
    RTE_LOG(ERR, DPDKCAP, "Could not close lzowrite_buffer.\n");
  }

  /* Flush stream */
  retval = fflush(file);
  if (unlikely(retval)) {
    retval = -1;
    RTE_LOG(ERR, DPDKCAP, "Could not flush file: %d (%s)\n",
        errno, strerror(errno));
  }

  /* Close file */
  retval = fclose(file);
  if (unlikely(retval)) {
    retval = -1;
    RTE_LOG(ERR, DPDKCAP, "Could not close file: %d (%s)\n",
        errno, strerror(errno));
  }
  return retval;
}

/*
 * Write the packets form the write ring into a pcap compressed file
 */
int write_core(const struct core_write_config * config) {
  void * write_buffer;
  unsigned char* eth;
  unsigned int packet_length, wire_packet_length;
  int result;
  void* dequeued[DPDKCAP_WRITE_BURST_SIZE];
  struct rte_mbuf* bufptr;
  struct pcap_packet_header header;
  struct timeval tv;
  struct pcap_header pcp;
  int retval = 0;
  int written;
  void * (*file_open_func)(char*) = (void*(*)(char*)) open_lzo_pcap;
  int (*file_write_func)(void*, void*, int) =
    (int (*)(void*, void*, int)) lzowrite;
  int (*file_close_func)(void*) = (int (*)(void*)) close_lzo_pcap;


  char file_name[DPDKCAP_OUTPUT_FILENAME_LENGTH];
  unsigned int file_count = 0;
  unsigned int file_size = 0;
  struct timeval file_start;

  gettimeofday(&file_start, NULL);

  //Update filename
  format_from_template(file_name, config->output_file_template,
      rte_lcore_id(), file_count, &file_start);

  //Init stats
  *(config->stats) = (struct core_write_stats) {
    .core_id=rte_lcore_id(),
      .current_file_packets=0,
      .current_file_bytes=0,
      .current_file_compressed_bytes=0,
      .packets = 0,
      .bytes = 0,
      .compressed_bytes = 0,
  };
  memcpy(config->stats->output_file, file_name,
      DPDKCAP_OUTPUT_FILENAME_LENGTH);

  //Init the common pcap header
  pcap_header_init(&pcp, config->snaplen);

  //Open new file
  write_buffer = file_open_func(file_name);
  if(unlikely(!write_buffer)) {
    retval = -1;
    goto cleanup;
  }

  //Write pcap header
  written = file_write_func(write_buffer, &pcp, sizeof(struct pcap_header));
  if(unlikely(written<0)) {
    retval = -1;
    goto cleanup;
  }

  //Log
  RTE_LOG(INFO, DPDKCAP, "Core %d is writing using file template: %s.\n",
      rte_lcore_id(), config->output_file_template);

  for (;;) {
    if (unlikely(*(config->stop_condition))) {
      break;
    }

    //Get packets from the ring
    result = (rte_ring_dequeue_bulk(config->ring,
        dequeued, DPDKCAP_WRITE_BURST_SIZE)<0)?0:DPDKCAP_WRITE_BURST_SIZE;
    if (result <= 0) {
      continue;
    }

    //Update stats
    config->stats->packets += result;

    int i;
    bool file_changed;
    for (i = 0; i < result; i++) {
      //Cast to packet
      bufptr = dequeued[i];
      eth = rte_pktmbuf_mtod(bufptr, unsigned char*);
      wire_packet_length = rte_pktmbuf_pkt_len(bufptr);
      //Truncate packet if needed
      packet_length = MIN(config->snaplen,wire_packet_length);

      //Get time
      gettimeofday(&tv, NULL);

      //Create a new file according to limits
      file_changed = 0;
      if(config->rotate_seconds &&
          (uint32_t)(tv.tv_sec-file_start.tv_sec) >= config->rotate_seconds) {
        file_count=0;
        gettimeofday(&file_start, NULL);
        file_changed=1;
      }
      if(config->file_size_limit && file_size >= config->file_size_limit) {
        file_count++;
        file_changed=1;
      }

      //Open new file
      if(file_changed) {
        //Update data
        file_size=0;

        //Change file name
        format_from_template(file_name, config->output_file_template,
            rte_lcore_id(), file_count, &file_start);

        //Update stats
        config->stats->current_file_packets = 0;
        config->stats->current_file_bytes = 0;
        memcpy(config->stats->output_file, file_name,
            DPDKCAP_OUTPUT_FILENAME_LENGTH);

        //Close pcap file and open new one
        file_close_func(write_buffer);

        //Reopen a file
        write_buffer = file_open_func(file_name);
        if(unlikely(!write_buffer)) {
          retval = -1;
          goto cleanup;
        }

        //Write pcap header
        written = file_write_func(write_buffer, &pcp,
            sizeof(struct pcap_header));
        if(unlikely(written<0)) {
          retval = -1;
          goto cleanup;
        }
      }

      //Write block header
      header.timestamp = (int32_t) tv.tv_sec;
      header.microseconds = (int32_t) tv.tv_usec;
      header.packet_length = packet_length;
      header.packet_length_wire = wire_packet_length;
      written = file_write_func(write_buffer, &header,
          sizeof(struct pcap_packet_header));
      if (unlikely(written<0)) {
         retval = -1;
        goto cleanup;
      }

      //Write content
      written = file_write_func(write_buffer, eth, sizeof(char) * packet_length);
      if (unlikely(written<0)) {
         retval = -1;
        goto cleanup;
      }

      file_size += written;

      //Update stats
      config->stats->bytes += packet_length;
      config->stats->compressed_bytes += written;
      config->stats->current_file_packets ++;
      config->stats->current_file_bytes += packet_length;
      config->stats->current_file_compressed_bytes = file_size;

      //Free buffer
      rte_pktmbuf_free(bufptr);
    }
  }

cleanup:
  //Close pcap file
  file_close_func(write_buffer);

  RTE_LOG(INFO, DPDKCAP, "Closed writing core %d\n", rte_lcore_id());

  return retval;
}

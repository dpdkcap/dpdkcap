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
#include <rte_version.h>

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
 * Open pcap file for writing
 */
static FILE * open_pcap(char * output_file) {
  FILE * file;
  //Open file
  file = fopen(output_file,"w");
  if (unlikely(!file)) {
    RTE_LOG(ERR, DPDKCAP, "Core %d could not open %s in write mode: %d (%s)\n",
        rte_lcore_id(), output_file, errno, strerror(errno));
  }

  return file;
}

/*
 * Write into a pcap file
 */
static int write_pcap(FILE * file, void * src, size_t len) {
  size_t retval;
  // Write file
  retval = fwrite(src, 1, len, file);
  if (unlikely(retval != len)) {
    RTE_LOG(ERR, DPDKCAP, "Could not write into file: %d (%s)\n",
        errno, strerror(errno));
    return -1;
  }
  return retval;
}

/*
 * Close and free a pcap file
 */
static int close_pcap(FILE * file) {
  int retval;
  // Close file
  retval = fclose(file);
  if (unlikely(retval)) {
    RTE_LOG(ERR, DPDKCAP, "Could not close file: %d (%s)\n",
        errno, strerror(errno));
  }
  return retval;
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
  int retval;

  /* Closes the lzo buffer */
  retval = lzowrite_close(buffer);
  if (unlikely(retval)) {
    RTE_LOG(ERR, DPDKCAP, "Could not close lzowrite_buffer.\n");
    return retval;
  }

  /* Close file */
  retval = fclose(file);
  if (unlikely(retval)) {
    RTE_LOG(ERR, DPDKCAP, "Could not close file: %d (%s)\n",
        errno, strerror(errno));
    return retval;
  }

  return 0;
}

/*
 * Write the packets form the write ring into a pcap compressed file
 */
int write_core(const struct core_write_config * config) {
  void * write_buffer;
  unsigned int packet_length, wire_packet_length, compressed_length;
  unsigned int remaining_bytes;
  int to_write;
  int bytes_to_write;
  struct rte_mbuf * dequeued[DPDKCAP_WRITE_BURST_SIZE];
  struct rte_mbuf * bufptr;
  struct pcap_packet_header header;
  struct timeval tv;
  struct pcap_header pcp;
  int retval = 0;
  int written;
  void * (*file_open_func)(char*);
  int (*file_write_func)(void*, void *, int);
  int (*file_close_func)(void*);

  char file_name[DPDKCAP_OUTPUT_FILENAME_LENGTH];
  unsigned int file_count = 0;
  uint64_t file_size = 0;
  struct timeval file_start;

  if(config->no_compression) {
    file_open_func  = (void*(*)(char*)) open_pcap;
    file_write_func = (int (*)(void*, void*, int)) write_pcap;
    file_close_func = (int (*)(void*)) close_pcap;
  } else {
    file_open_func  = (void*(*)(char*)) open_lzo_pcap;
    file_write_func = (int (*)(void*, void*, int)) lzowrite;
    file_close_func = (int (*)(void*)) close_lzo_pcap;
  }
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
  written = file_write_func(write_buffer, (unsigned char *) &pcp, sizeof(struct pcap_header));
  if(unlikely(written<0)) {
    retval = -1;
    goto cleanup;
  }
  file_size = written;

  //Log
  RTE_LOG(INFO, DPDKCAP, "Core %d is writing using file template: %s.\n",
      rte_lcore_id(), config->output_file_template);

  for (;;) {
    if (unlikely(*(config->stop_condition) && rte_ring_empty(config->ring))) {
      break;
    }

    //Get packets from the ring
#if RTE_VERSION >= RTE_VERSION_NUM(17,5,0,16)
      to_write = rte_ring_dequeue_burst(config->ring, (void*)dequeued,
          DPDKCAP_WRITE_BURST_SIZE, NULL);
#else
      to_write = rte_ring_dequeue_burst(config->ring, (void*)dequeued,
          DPDKCAP_WRITE_BURST_SIZE);
#endif

    if (unlikely(to_write == 0)) {
      rte_delay_us(2);
      continue;
    }

    //Update stats
    config->stats->packets += to_write;

    int i;
    bool file_changed;
    for (i = 0; i < to_write; i++) {
      //Cast to packet
      bufptr = dequeued[i];
      wire_packet_length = rte_pktmbuf_pkt_len(bufptr);

      //Truncate packet if needed
      packet_length = MIN(config->snaplen, wire_packet_length);

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
        //Reset file size
        file_size = written;
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
      file_size += written;

      //Write content
      remaining_bytes = packet_length;
      compressed_length = 0;
      while (bufptr != NULL && remaining_bytes > 0) {
        bytes_to_write = MIN(rte_pktmbuf_data_len(bufptr), remaining_bytes);
        written = file_write_func(write_buffer,
            rte_pktmbuf_mtod(bufptr, void*),
            bytes_to_write);
        if (unlikely(written<0)) {
          retval = -1;
          goto cleanup;
        }
        bufptr = bufptr->next;
        remaining_bytes -= bytes_to_write;
        compressed_length += written;
        file_size += written;
      }

      //Free buffer
      rte_pktmbuf_free(dequeued[i]);

      //Update stats
      config->stats->bytes += packet_length;
      config->stats->compressed_bytes += compressed_length;
      config->stats->current_file_packets ++;
      config->stats->current_file_bytes += packet_length;
      config->stats->current_file_compressed_bytes = file_size;

    }
  }

cleanup:
  //Close pcap file
  file_close_func(write_buffer);

  RTE_LOG(INFO, DPDKCAP, "Closed writing core %d\n", rte_lcore_id());

    return retval;
  }

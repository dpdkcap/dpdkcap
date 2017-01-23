#include "lzowrite.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <errno.h>
#include <byteswap.h>

#include <rte_branch_prediction.h>
#include <rte_log.h>

#include "minilzo/minilzo.h"

#define RTE_LOGTYPE_LZO RTE_LOGTYPE_USER2

#define HEAP_ALLOC(var,size) \
  lzo_align_t __LZO_MMODEL var \
 [ ((size) + (sizeof(lzo_align_t) - 1)) / sizeof(lzo_align_t) ]

static int lzowrite_wbuf(struct lzowrite_buffer* lzowrite_buffer) {
  struct __attribute__((__packed__)) {
    uint32_t len;
    uint32_t out_length;
  } block_header;
  unsigned char out_buffer[LZOWRITE_OUT_BUFFER_SIZE];
  uint32_t out_length;
  int to_be_written;
  int retval;

  if(lzowrite_buffer->length == 0) return 0;

  lzo1x_1_compress(
      lzowrite_buffer->buffer, lzowrite_buffer->length,
      out_buffer, (lzo_uintp)&(out_length),
      lzowrite_buffer->workmemory);

  //Write block_header header
  block_header.len = __bswap_32(lzowrite_buffer->length);
  if(lzowrite_buffer->length <= out_length) {
    block_header.out_length = __bswap_32(lzowrite_buffer->length);
  } else {
    block_header.out_length = __bswap_32(out_length);
  }
  retval = fwrite(&block_header, sizeof(block_header), 1, lzowrite_buffer->output);
  //Check if no write error occured
  if (unlikely(retval != 1)) {
    RTE_LOG(ERR, LZO, "Could not write lzo block header in file: %d (%s)\n",
        errno, strerror(errno));
    retval=-1;
  }

  //Write data
  if(lzowrite_buffer->length <= out_length) {
    to_be_written = lzowrite_buffer->length;
    retval = fwrite(lzowrite_buffer->buffer, sizeof(unsigned char),
                    to_be_written, lzowrite_buffer->output);
  } else {
    to_be_written = out_length;
    retval = fwrite(out_buffer, sizeof(unsigned char),
                    to_be_written, lzowrite_buffer->output);
  }
  //Check if no write error occured
  if (unlikely(retval != to_be_written)) {
    RTE_LOG(ERR, LZO, "Could not write lzo block data in file: %d (%s)\n",
        errno, strerror(errno));
    retval=-1;
  }

  //Reset buffer
  lzowrite_buffer->length = 0;

  return sizeof(block_header) + to_be_written ;
}

struct lzowrite_buffer * lzowrite_init(FILE* file) {
  static int initialized = 0;
  int status;

  /* To be written */
  struct __attribute__((__packed__)) {
    const char magic[LZOWRITE_LZO_MAGIC_LEN];
    struct lzowrite_file_header lzoheader;
  } fheader = {
    .magic = LZOWRITE_LZO_MAGIC,
  };
  struct lzowrite_buffer * buffer = NULL;
  int written;

  //Initialize minilzo if needed
  if(!initialized) {
    status = lzo_init();
    if (status) {
      RTE_LOG(ERR, LZO, "Could not initialize minilzo: %d\n",
          status);
      return NULL;
    }
    initialized = 1;
  }

  //Prepare the buffers
  if (unlikely(!file || !__fwritable(file))) {
    RTE_LOG(ERR, LZO, "Could not write into stream (NULL or unwritable)\n");
    goto cleanup;
  }
  buffer = (struct lzowrite_buffer *) malloc (sizeof(struct lzowrite_buffer));
  buffer->output = file;
  buffer->length = 0;

  //Allocate workmemory
  HEAP_ALLOC(wrkmem, LZO1X_1_MEM_COMPRESS);
  buffer->workmemory = wrkmem;

  //Init header
  fheader.lzoheader = (struct lzowrite_file_header) {
      .version = LZOWRITE_LZO_VERSION,
      .library_version = lzo_version(),
      .needed_version = LZOWRITE_LZO_VERSION_NEEDED_TO_EXTRACT,
      .compression_method = LZOWRITE_LZO_METHOD,
      .compression_level = LZOWRITE_LZO_COMPRESSION_LEVEL,
      .compression_flags = LZOWRITE_LZO_FLAGS,
      .mode = LZOWRITE_LZO_MODE,
      .file_mtime_low = 0,
      .file_mtime_high = 0,
      .file_name_length = 0,
      .file_header_checksum = 1,
  };
  //Calculate checksum
  fheader.lzoheader.file_header_checksum =
    __bswap_32(lzo_adler32(fheader.lzoheader.file_header_checksum,
          (lzo_bytep)(&fheader.lzoheader),
          sizeof(struct lzowrite_file_header) - sizeof(uint32_t)));

  //Write file header
  written = fwrite(&fheader, sizeof(fheader), 1, buffer->output);
  if (unlikely(written != 1)) {
     RTE_LOG(ERR, LZO, "Could not write lzo file header in file: %d (%s)\n",
        errno, strerror(errno));
    goto cleanup;
  }

  return buffer;

cleanup:
  free(buffer);
  return NULL;
}

int lzowrite(struct lzowrite_buffer* lzowrite_buffer, void * src, size_t len) {
  int retval = 0;

  if (len > LZOWRITE_BUFFER_SIZE) {
    RTE_LOG(ERR, LZO, "Data bigger than buffer!\n");
    retval = -1;
    goto cleanup;
  }

  if (lzowrite_buffer->length + len >= LZOWRITE_BUFFER_SIZE) {
    retval=lzowrite_wbuf(lzowrite_buffer);
    if (unlikely(retval < 0)) {
      retval= -1;
    }
  }

  memcpy(&(lzowrite_buffer->buffer[lzowrite_buffer->length]), src, len);
  lzowrite_buffer->length += len;
cleanup:
  return retval;
}

int lzowrite_close(struct lzowrite_buffer* lzowrite_buffer) {
  unsigned char zeros[4] = {0};
  int retval = 0;
  int written;

  /* Write remaining data */
  written = lzowrite_wbuf(lzowrite_buffer);
  if(written < 0) {
    RTE_LOG(ERR, LZO, "Could not write remaining data.\n");
    retval = -1;
    goto cleanup;
  }

  /* Write 4 zero bytes */
  written = fwrite(zeros, sizeof(unsigned char), 4, lzowrite_buffer->output);
  if (unlikely(written != 4)) {
    RTE_LOG(ERR, LZO, "Could not write 4 zeros in file: %d (%s)\n",
        errno, strerror(errno));
    retval = -1;
    goto cleanup;
  }

cleanup:
  free(lzowrite_buffer);
  return retval;
}

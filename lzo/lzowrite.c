#include "lzowrite.h"

#include <rte_branch_prediction.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <byteswap.h>

#include "minilzo/minilzo.h"

#define HEAP_ALLOC(var,size) \
  lzo_align_t __LZO_MMODEL var \
 [ ((size) + (sizeof(lzo_align_t) - 1)) / sizeof(lzo_align_t) ]

int lzowrite_init(struct lzowrite_buffer * buffer, const char* filename) {
  struct __attribute__((__packed__)) {
    const char magic[LZOWRITE_LZO_MAGIC_LEN];
    struct lzowrite_file_header lzoheader;
  } fheader = {
    .magic = LZOWRITE_LZO_MAGIC,
  };
  int retval;

  //Prepare the buffers
  buffer->output = fopen(filename, "w");
  if (unlikely(!buffer->output)) {
    retval = errno;
    printf("LZO: Could not open for writing %s: %d (%s)\n",
        filename, retval, strerror(retval));
    return -retval;
  }
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
  retval = fwrite(&fheader, sizeof(fheader), 1, buffer->output);
  if (unlikely(retval != 1)) {
    retval=errno;
    printf("LZO: Could not write lzo file header in file: %d (%s)\n",
        retval, strerror(retval));
    return -retval;
  }

  return 0;
}

static int lzowrite_wbuf(struct lzowrite_buffer* lzowrite_buffer) {
  struct __attribute__((__packed__)) {
    uint32_t len;
    uint32_t out_length;
    unsigned char out_buffer[LZOWRITE_OUT_BUFFER_SIZE];
  } block;
  uint32_t out_length;
  int to_be_written;
  int retval = 0;

  lzo1x_1_compress(
      lzowrite_buffer->buffer, lzowrite_buffer->length,
      block.out_buffer, (lzo_uintp)&(out_length),
      lzowrite_buffer->workmemory);

  //Write block header
  block.len = __bswap_32(lzowrite_buffer->length);
  block.out_length = __bswap_32(out_length);

  //Write content
  to_be_written = 2 * sizeof(uint32_t) + out_length;
  retval = fwrite(&block, sizeof(unsigned char),
            to_be_written, lzowrite_buffer->output);

  //Check if no write error occured
  if (unlikely(retval != to_be_written)) {
    retval=errno;
    printf("LZO: Could not write lzo block in file: %d (%s)\n",
        retval, strerror(retval));
    return -retval;
  }

  //Reset buffer
  lzowrite_buffer->length = 0;

  return retval;
}

int lzowrite(struct lzowrite_buffer* lzowrite_buffer, void* src, size_t len) {
  int retval = 0;

  if (len > LZOWRITE_BUFFER_SIZE)
    printf("Data bigger than buffer!\n");

  if (lzowrite_buffer->length + len > LZOWRITE_BUFFER_SIZE) {
    retval=lzowrite_wbuf(lzowrite_buffer);
    if (unlikely(retval < 0)) {
      return retval;
    }
  }

  memcpy(&lzowrite_buffer->buffer[lzowrite_buffer->length], src, len);
  lzowrite_buffer->length += len;

  return retval;
}

int lzowrite_free(struct lzowrite_buffer* lzowrite_buffer) {
  unsigned char zeros[4] = {0};
  int retval = 0;

  /* Write remaining data */
  retval = lzowrite_wbuf(lzowrite_buffer);
  if(retval < 0) {
    return retval;
  }

  /* Write 4 zero bytes */
  retval = fwrite(zeros, sizeof(unsigned char), 4, lzowrite_buffer->output);
  if (unlikely(retval != 4)) {
    retval = errno;
    printf("LZO: Could not write 4 zeros in file: %d (%s)\n",
        retval, strerror(retval));
    return retval;
  }

  /* Flush file */
  retval = fflush(lzowrite_buffer->output);
  if (unlikely(retval)) {
    retval = errno;
    printf("LZO: Could not flush file: %d (%s)\n",
        retval, strerror(retval));
    return retval;
  }

  /* Close file */
  retval = fclose(lzowrite_buffer->output);
  if (unlikely(retval)) {
    retval = errno;
    printf("LZO: Could not close file: %d (%s)\n",
        retval, strerror(retval));
    return retval;
  }

  return retval;
}

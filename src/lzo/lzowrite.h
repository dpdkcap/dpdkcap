#include <stdio.h>
#include <stdint.h>

#include "minilzo/minilzo.h"

#define LZOWRITE_BUFFER_SIZE 32 * 1024
#define LZOWRITE_OUT_BUFFER_SIZE (LZOWRITE_BUFFER_SIZE + LZOWRITE_BUFFER_SIZE / 16 + 64 + 3)
#define LZOWRITE_LZO_MAGIC {0x89,0x4c,0x5a,0x4f,0x00,0x0d,0x0a,0x1a,0x0a}
#define LZOWRITE_LZO_MAGIC_LEN 9
#define LZOWRITE_LZO_VERSION 0x3010 // as in LZOP 1.03
#define LZOWRITE_LZO_LIB_VERSION (lzo_version() & 0xffff)
#define LZOWRITE_LZO_VERSION_NEEDED_TO_EXTRACT 0x4009 // not using filters, otherwise 0x0950
#define LZOWRITE_LZO_METHOD 1 // LZO1X
#define LZOWRITE_LZO_COMPRESSION_LEVEL 1 // with lzo, we have compression level = 1.
#define LZOWRITE_LZO_FLAGS 0 // no checksums on data!!
#define LZOWRITE_LZO_MODE 0xa481 // 100644 oct

void fwrite_int32_be(void* ptr, FILE* out);


struct lzowrite_buffer {
	unsigned char buffer[LZOWRITE_BUFFER_SIZE];
	uint32_t length;
	FILE* output;
	lzo_align_t* workmemory;
};

struct __attribute__((__packed__)) lzowrite_file_header {
	uint16_t version;
	uint16_t library_version;
	uint16_t needed_version;
	uint8_t compression_method;
	uint8_t compression_level;
	uint32_t compression_flags;
	uint32_t mode;
	uint32_t file_mtime_low;
	uint32_t file_mtime_high;
	uint8_t file_name_length;
	uint32_t file_header_checksum;
};

struct __attribute__((__packed__)) lzowrite_block_header {
	uint32_t uncompressed_size;
	uint32_t compressed_size;
	uint32_t uncompressed_adler32;
	uint32_t uncompressed_crc32;
	uint32_t compressed_adler32;
	uint32_t compressed_crc32;
};

/*
 * Inits an lzo buffer with the given output file
 * Returns the buffer on success, NULL on error
 */
struct lzowrite_buffer * lzowrite_init(FILE *);

/*
 * Writes len bytes from src into the given lzowrite_buffer
 * Returns the number of written bytes on success (might be 0),
 * -1 on failure.
 */
int lzowrite(struct lzowrite_buffer* lzowrite_buffer, void * src,
    size_t len);

/*
 * Flushes the buffer by writting the last bytes into the output stream, then
 * close it. lzowrite_buffer should be freed at the end.
 * Returns 0 on success, -1 on failure.
 */
int lzowrite_close(struct lzowrite_buffer* lzowrite_buffer);

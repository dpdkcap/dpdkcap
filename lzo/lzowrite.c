#include "lzowrite.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "minilzo.h"

#define HEAP_ALLOC(var,size) \
    lzo_align_t __LZO_MMODEL var [ ((size) + (sizeof(lzo_align_t) - 1)) / sizeof(lzo_align_t) ]

void fwrite_int32_be(void* ptr, FILE* out) {
	fwrite(&((uint8_t*)(ptr))[3], sizeof(uint8_t), 1, out);
	fwrite(&((uint8_t*)(ptr))[2], sizeof(uint8_t), 1, out);
	fwrite(&((uint8_t*)(ptr))[1], sizeof(uint8_t), 1, out);
	fwrite(&((uint8_t*)(ptr))[0], sizeof(uint8_t), 1, out);
}

void* lzowrite_init(const char* filename) {
	//Prepare the buffers
	struct lzowrite_buffer* buffer = malloc(sizeof(struct lzowrite_buffer));
        buffer->output = fopen(filename, "w");
        if (buffer->output == NULL) {
          printf("LZO: Could not open %s : %d (%s)\n", filename, errno, strerror(errno));
          return NULL;
        }
        buffer->length = 0;

	//Allocate workmemory
	HEAP_ALLOC(wrkmem, LZO1X_1_MEM_COMPRESS);
	buffer->workmemory = wrkmem;

	//Write LZO fileformat
	unsigned char magic[LZOWRITE_LZO_MAGIC_LEN] = LZOWRITE_LZO_MAGIC;
	fwrite(magic, sizeof(unsigned char), LZOWRITE_LZO_MAGIC_LEN, buffer->output);

	//Init header
	struct lzowrite_file_header* fheader = malloc(sizeof(struct lzowrite_file_header));
	fheader->version = LZOWRITE_LZO_VERSION;
	fheader->library_version = lzo_version();
	fheader->needed_version = LZOWRITE_LZO_VERSION_NEEDED_TO_EXTRACT;
	fheader->compression_method = LZOWRITE_LZO_METHOD;
	fheader->compression_level = LZOWRITE_LZO_COMPRESSION_LEVEL;
	fheader->compression_flags = LZOWRITE_LZO_FLAGS;
	fheader->mode = LZOWRITE_LZO_MODE;
	fheader->file_name_length = 0;
	fheader->file_header_checksum = 1;
	fheader->file_mtime_high = 0;
	fheader->file_mtime_low = 0;

	fwrite(&fheader->version, sizeof(uint16_t), 1, buffer->output);
	fwrite(&fheader->library_version, sizeof(uint16_t), 1, buffer->output);
	fwrite(&fheader->needed_version, sizeof(uint16_t), 1, buffer->output);
	fwrite(&fheader->compression_method, sizeof(uint8_t), 1, buffer->output);
	fwrite(&fheader->compression_level, sizeof(uint8_t), 1, buffer->output);
	fwrite(&fheader->compression_flags, sizeof(uint32_t), 1, buffer->output);
	fwrite(&fheader->mode, sizeof(uint32_t), 1, buffer->output);
	fwrite(&fheader->file_mtime_low, sizeof(uint32_t), 1, buffer->output);
	fwrite(&fheader->file_mtime_high, sizeof(uint32_t), 1, buffer->output);
	fwrite(&fheader->file_name_length, sizeof(uint8_t), 1, buffer->output);

	//Calculate checksum
	fheader->file_header_checksum = lzo_adler32(fheader->file_header_checksum, (lzo_bytep)&fheader->version, 2);
	fheader->file_header_checksum = lzo_adler32(fheader->file_header_checksum, (lzo_bytep)&fheader->library_version, 2);
	fheader->file_header_checksum = lzo_adler32(fheader->file_header_checksum, (lzo_bytep)&fheader->needed_version, 2);
	fheader->file_header_checksum = lzo_adler32(fheader->file_header_checksum, (lzo_bytep)&fheader->compression_method, 1);
	fheader->file_header_checksum = lzo_adler32(fheader->file_header_checksum, (lzo_bytep)&fheader->compression_level, 1);
	fheader->file_header_checksum = lzo_adler32(fheader->file_header_checksum, (lzo_bytep)&fheader->compression_flags, 4);
	fheader->file_header_checksum = lzo_adler32(fheader->file_header_checksum, (lzo_bytep)&fheader->mode, 4);
	fheader->file_header_checksum = lzo_adler32(fheader->file_header_checksum, (lzo_bytep)&fheader->file_mtime_low, 4);
	fheader->file_header_checksum = lzo_adler32(fheader->file_header_checksum, (lzo_bytep)&fheader->file_mtime_high, 4);
	fheader->file_header_checksum = lzo_adler32(fheader->file_header_checksum, (lzo_bytep)&fheader->file_name_length, 1);


	fwrite(&((uint8_t*)(&fheader->file_header_checksum))[3], sizeof(uint8_t), 1, buffer->output);
	fwrite(&((uint8_t*)(&fheader->file_header_checksum))[2], sizeof(uint8_t), 1, buffer->output);
	fwrite(&((uint8_t*)(&fheader->file_header_checksum))[1], sizeof(uint8_t), 1, buffer->output);
	fwrite(&((uint8_t*)(&fheader->file_header_checksum))[0], sizeof(uint8_t), 1, buffer->output);

	free(fheader);

	return buffer;
}

void lzowrite_wbuf(struct lzowrite_buffer* lzowrite_buffer) {
	lzo1x_1_compress(lzowrite_buffer->buffer, lzowrite_buffer->length, lzowrite_buffer->out_buffer, (lzo_uintp)&lzowrite_buffer->out_length, lzowrite_buffer->workmemory);

	//Write block header
	fwrite_int32_be(&lzowrite_buffer->length, lzowrite_buffer->output);
	fwrite_int32_be(&lzowrite_buffer->out_length, lzowrite_buffer->output);

	//Write content
	fwrite(lzowrite_buffer->out_buffer, sizeof(unsigned char), lzowrite_buffer->out_length, lzowrite_buffer->output);

	//Reset buffer
	lzowrite_buffer->length = 0;
}

void lzowrite(struct lzowrite_buffer* lzowrite_buffer, void* src, size_t len) {
	if (len > LZOWRITE_BUFFER_SIZE) {
		printf("Data bigger than buffer!\n");
	}

        lzowrite_buffer->out_length = 0;
	if (lzowrite_buffer->length + len > LZOWRITE_BUFFER_SIZE) {
		lzowrite_wbuf(lzowrite_buffer);
	}

	memcpy(&lzowrite_buffer->buffer[lzowrite_buffer->length], src, len);
	lzowrite_buffer->length += len;
}

void lzowrite32(struct lzowrite_buffer* lzowrite_buffer, uint32_t data) {
	uint32_t res;
	uint8_t* out = (uint8_t*)&res;
	uint8_t* in = (uint8_t*)&data;
	out[0] = in[3];
	out[1] = in[2];
	out[2] = in[1];
	out[3] = in[0];
	lzowrite(lzowrite_buffer, &res, sizeof(uint32_t));
}

void lzowrite16(struct lzowrite_buffer* lzowrite_buffer, uint16_t data) {
	uint16_t res;
	uint8_t* out = (uint8_t*)&res;
	uint8_t* in = (uint8_t*)&data;
	out[0] = in[1];
	out[1] = in[0];
	lzowrite(lzowrite_buffer, &res, sizeof(uint16_t));
}

void lzowrite_free(struct lzowrite_buffer* lzowrite_buffer) {
	//Write remaining data
	lzowrite_wbuf(lzowrite_buffer);
	//Write 4 zero bytes to close the LZO file
	unsigned char zeros[4] = {0, 0, 0, 0};
	fwrite(zeros, sizeof(unsigned char), 4, lzowrite_buffer->output);
	fflush(lzowrite_buffer->output);
	fclose(lzowrite_buffer->output);
	free(lzowrite_buffer);
}

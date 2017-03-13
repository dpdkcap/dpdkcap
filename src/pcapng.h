#ifndef DPDKCAP_PCAPNG_H
#define DPDKCAP_PCAPNG_H

#include <stdint.h>

#define PCAPNG_BYTEORDER_MAGIC_NUMBER           0x1A2B3C4D

#define PCAPNG_SHB_BLOCK_TYPE                   0x0A0D0D0A
#define PCAPNG_INTERFACE_DESCRIPTION_BLOCK_TYPE 0x00000001
#define PCAPNG_SIMPLE_PACKET_BLOCK_TYPE         0x00000003
#define PCAPNG_NAME_RESOLUTION_BLOCK_TYPE       0x00000004
#define PCAPNG_INTERFACE_STATISTICS_BLOCK_TYPE  0x00000005
#define PCAPNG_ENHANCED_PACKET_BLOCK_TYPE       0x00000006
#define PCAPNG_CUSTOM_BLOCK_TYPE                0x00000BAD
#define PCAPNG_CUSTOM_BLOCK_TYPE_NOCOPY         0x40000BAD

struct __attribute__((__packed__)) pcapng_block_header {
  uint32_t type;
  uint32_t block_length;
};

struct __attribute__((__packed__)) pcapng_custom_option {
  uint16_t code;                      /* custom option code */
  uint16_t length;                    /* option length */
  uint32_t private_enterprise_number; /* private enterprise number */
};

struct __attribute__((__packed__)) pcapng_section_header_block {
  struct pcapng_block_header header; /* common block header */
  uint32_t byte_order_magic;         /* byte order magic number */
  uint16_t version_major;            /* major version number */
  uint16_t version_minor;            /* minor version number */
  uint64_t section_length;           /* section length */
};

struct __attribute__((__packed__)) pcapng_interface_description_block {
  struct pcapng_block_header header; /* common block header */
  uint16_t link_type;                /* link type */
  uint16_t reserved;                 /* reserved */
  uint32_t snaplen;                  /* SnapLen */
};

struct __attribute__((__packed__)) pcapng_enhanced_packet_block {
  struct pcapng_block_header header; /* common block header */
  uint32_t interface_id;             /* interface ID */
  uint32_t timestamp_high;           /* upper 32 bits of a 64 bits timestamp */
  uint32_t timestamp_low;            /* lower 32 bits of a 64 bits timestamp */
  uint32_t captured_packet_len;      /* captured packet length */
  uint32_t original_packet_len;      /* original packet length */
};

struct __attribute__((__packed__)) pcapng_simple_packet_block {
  struct pcapng_block_header header; /* common block header */
  uint32_t original_packet_len;      /* original packet length */
};

struct __attribute__((__packed__)) pcacng_name_resolution_record {
  uint16_t type;   /* record type */
  uint16_t length; /* record length */
};

struct __attribute__((__packed__)) pcacng_name_resolution_block {
  struct pcapng_block_header header; /* common block header */
};

struct __attribute__((__packed__)) pcapng_interface_statistics_block {
  struct pcapng_block_header header; /* common block header */
  uint32_t interface_id;             /* interface ID */
  uint32_t timestamp_high;           /* upper 32 bits of a 64 bits timestamp */
  uint32_t timestamp_low;            /* lower 32 bits of a 64 bits timestamp */
};

struct __attribute__((__packed__)) pcapng_custom_block {
  struct pcapng_block_header header;  /* common block header */
  uint32_t private_enterprise_number; /* private enterprise number */
};

#endif

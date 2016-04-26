#ifndef DPDKCAP_PCAP_H
#define DPDKCAP_PCAP_H

#include <stdint.h>

#define PCAP_SNAPLEN_DEFAULT 65535

struct __attribute__((__packed__)) pcap_header {
	uint32_t magic_number;  /* magic number */
	uint16_t version_major; /* major version number */
	uint16_t version_minor; /* minor version number */
	int32_t  thiszone;      /* GMT to local correction */
	uint32_t sigfigs;       /* accuracy of timestamps */
	uint32_t snaplen;       /* max length of captured packets, in octets */
	uint32_t network;       /* data link type */
};

struct pcap_packet_header {
	uint32_t timestamp;
	uint32_t microseconds;
	uint32_t packet_length;
	uint32_t packet_length_wire;
};

void pcap_header_init(struct pcap_header * header, unsigned int snaplen);

#endif

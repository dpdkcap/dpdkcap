#include <stdlib.h>
#include "pcap.h"

void* pcap_header_create(void) {
	struct pcap_header* header = malloc(sizeof(struct pcap_header));
	header->magic_number = 0xd4c3b2a1;
	header->version_major = 0x0200;
	header->version_minor = 0x0400;
	header->thiszone = 0;
	header->sigfigs = 0;
	header->snaplen = 0xffff0000;
	header->network = 0x01000000;
	return header;
}

#include <stdlib.h>
#include "pcap.h"

void pcap_header_init(struct pcap_header * header, unsigned int snaplen) {
  header->magic_number = 0xa1b2c3d4;
  header->version_major = 0x0002;
  header->version_minor = 0x0004;
  header->thiszone = 0;
  header->sigfigs = 0;
  header->snaplen = snaplen;
  header->network = 0x00000001;
}

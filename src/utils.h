#ifndef DPDKCAP_UTILS_H
#define DPDKCAP_UTILS_H

#include <stdint.h>

char * bytes_format(uint64_t);
char * ul_format(uint64_t);
char * str_replace(const char * src, const char * find, const char * replace);

#endif

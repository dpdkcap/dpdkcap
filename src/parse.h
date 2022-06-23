#ifndef DPDKCAP_PARSE_H
#define DPDKCAP_PARSE_H


int parse_config(int fd, ssize_t size, void (*cb)(char*,char*,void*), void*);



#endif

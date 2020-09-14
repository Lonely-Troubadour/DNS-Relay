#include "dnsutils.h"
#include "dnsrelay.h"
#ifndef _UTILS_H_
#define _UTILS_H_

void print_debug(int debug);
void print_dns_server(char *DNS_server);
void print_db_path();
void print_send_recv(char *send_recv, struct sockaddr_in *addr, unsigned char *buf, int buf_len);
void print_buf_header(const unsigned char *buf);
void buf2header(const unsigned char *buf, struct header *header);
void print_header(const struct header *header);
void usage();
#endif

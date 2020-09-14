/**
 * This file is the header file for dns relay main program. 
 * -------------------------------------------------------
 * The header file defined some constants related to socket communication, 
 * such as port to communicate, DNS server address, etc. 
 * 
 * Some important functions are defined here.
 *     init_socket: Initialize and create a socket.
 *     gen_in_addr: Initialize dns server addrs and local server address.
 *     gen_in6_addr: Initialize IPv6 address.
 * 
 * The header file includes different system header files based on different OS.
 * -----------------------------------------------------------------------------
 * Authors: Yongjian Hu, Zhihao Song, Yutong Si
 * License: GPLv3
 * Date: 15-07-2020
 */
#ifndef _DNSRELAY_H_
#define _DNSRELAY_H_

#if defined(_WIN32) || defined(_WIN64)
#include <winsock2.h>
typedef int socklen_t;
#define close closesocket
#pragma comment (lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#endif

#define PORT 53
#define DNS_SERVER "114.114.114.114"
#define LOCAL_SERVER "127.0.0.1"

int init_socket();
int gen_in_addr(struct sockaddr_in *dns_addr, unsigned int *dns_addr_len, \
struct sockaddr_in * server_addr, unsigned int *server_addr_size, \
char *dns_server);
int gen_in6_addr();
int parse_opt(int argc, const char **argv, int *debug, char **dns_server, char **db);
void usage();

#endif

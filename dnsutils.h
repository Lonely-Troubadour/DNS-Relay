/**
 * This file is the header file for dns utils, that contains some useful utils
 * for DNS relay service.  
 * -----------------------------------------------------------------------------
 * The header file defined some constants related to DNS request, such as max 
 * string length, max buffer size, types, classes, etc. 
 * 
 * Some important structers are defined here.
 *     header: 12 bytes header for DNS query.
 *     address: Address for either IPv4 address or IPv6 address
 *     ip_addr: IP address.
 * 
 * Some important functions are defined here.
 *     gen_header: Generates DNS query header.
 *     parse_query: Parse received request.
 * 
 * The header file includes different system header files based on different OS.
 * -----------------------------------------------------------------------------
 * Authors: Yongjian Hu, Zhihao Song, Yutong Si
 * License: GPLv3
 * Date: 15-07-2020
 */
#ifndef _DNSUTILS_H_
#define _DNSUTILS_H_

#if defined(_WIN32) || defined(_WIN64)
#include <winsock.h>
#include <stdint.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#define SIZEOF_ARR(arr) (sizeof(arr)/sizeof(arr[0]))

#define MAX_LENGTH 255
#define BUF_SIZE 512
#define TYPE_A 1
#define TYPE_AAAA 28
#define CLASS_IN 1

/*
 *   DNS Header structer
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                     ID                        |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |QR| Opcode    |AA|TC|RD|RA| Z      |  RCODE    |  flags_row
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                   QDCOUNT                     |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                   ANCOUNT                     |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                   NSCOUNT                     |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                   ARCOUNT                     |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
struct header {
    uint16_t id;
    uint16_t flags;
    uint16_t qd_count;
    uint16_t an_count;
    uint16_t ns_count;
    uint16_t ar_count;
};

/*
 *   DNS Queries structer
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                     qname                     |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |         qtype        |         qclass         |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
struct query
{
    char name[MAX_LENGTH];
    uint16_t qtype;
    uint16_t qclass;
};

/*
union address {
    struct in_addr ipv4;
    struct in6_addr ipv6;
};

struct ip_addr {
    int type;
    union address addr;
};
*/

uint16_t gen_id();
struct header * gen_header();
int gen_dns_request(unsigned char *request, int *request_len, char *name);
int parse_query(unsigned char *msg, int msg_size, struct query *dnsquery);
int dns_parse_domain(unsigned char *dns, int offset, char *domain, \
int *domain_len);
int gen_response(unsigned char *response, unsigned char *request, \
int request_size, char *ip_addr);
int check_type(uint16_t qtype);
#endif

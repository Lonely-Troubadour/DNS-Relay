#if defined(_WIN32) || defined(_WIN64)
#include <winsock.h>
#include <stdint.h>
#include <malloc.h>
#else
#include <netinet/in.h>
#include <malloc/malloc.h>
#endif

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

uint16_t gen_id();
struct header * gen_header();
int gen_dns_request(unsigned char *request, int *request_len, char *name);

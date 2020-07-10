#include <netinet/in.h>

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

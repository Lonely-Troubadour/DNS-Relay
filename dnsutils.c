#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dnsutils.h"

/**
 * Generates DNS query ID.
 * ID is a 16 bits random number.
 * ------------------------------
 * Parameters: None
 * Returns: id.
 */
uint16_t gen_id() {
    // 1234 -> 0x04d2
    // 65535 -> 0xFFFF
    return rand() % 65535;
}

/**
 * Generate DNS rt header
 * Header is 12 bytes.
 * -------------------------
 * Parameters: None
 * Returns: Pointer to the header.
 */
struct header * gen_header() {
    struct header* ptr_header = NULL;

    /* Allocate memory space */
    ptr_header = (struct header*) malloc (sizeof(struct header));
    if (ptr_header == NULL) {
        perror("Generate header failed!\n");
        exit(1);
    }
    /* Initialize memory space */
    memset(ptr_header, 0, sizeof(struct header));

    /* Generate header */
    (*ptr_header).id = htons(gen_id());
    (*ptr_header).flags = htons(0x0100); // Standard query
    (*ptr_header).qd_count = htons(1);

    return ptr_header;
}

/**
 * Generates DNS rt
 * Rt contains header, queries, 
 * type and class sections.
 * --------------------------------
 * Parameters:
 *     rt: pointer to the rt.
 *     name: constant char pointer. Points to the name string.
 * Returns:
 *     0 if success. 1 if failed.
 */
int gen_dns_rt(unsigned char *rt, int *rt_len, char *name) {
    int pos = 0;
    int len = 0;
    char *token;
    uint16_t q_type = htons(TYPE_A);
    uint16_t q_class = htons(CLASS_IN);

    /* Generates DNS header, copy the header to rt header field */
    struct header *dns_header = gen_header();
    memcpy(rt, dns_header, sizeof(struct header));
    pos += sizeof(struct header);

    /* Generate DNS query section */
    token = strtok(name, ".");
    while(token != NULL) {
        len = strlen(token);
        if ((pos + len + 1) > BUF_SIZE) return 1;
        rt[pos++] = len;
        memcpy(rt + pos, token, len);
        pos += len;
        token = strtok(NULL, ".");
    }
    if ((pos + 1) > BUF_SIZE) return 1;
    rt[pos++] = '\0';

    /* Generate Type section */
    if ((pos + sizeof(q_type)) > BUF_SIZE) return 1;
    memcpy(rt + pos, &q_type, sizeof(q_type));
    pos += sizeof(q_type);

    /* Generate Class section */
    if ((pos + sizeof(q_class)) > BUF_SIZE) return 1;
    memcpy(rt + pos, &q_class, sizeof(q_class));
    pos += sizeof(q_class);

    /* Update rt length */
    *rt_len = pos;

    return 0;
}

/**
 * Generates DNS request
 * Request contains header, queries, 
 * type and class sections.
 * --------------------------------
 * Parameters:
 *     request: pointer to the request.
 *     name: constant char pointer. Points to the name string.
 * Returns:
 *     0 if success. 1 if failed.
 */
int gen_dns_request(unsigned char *request, int *request_len, char *name)
{
    int pos = 0;
    int len = 0;
    char *token;
    uint16_t q_type = htons(TYPE_A);
    uint16_t q_class = htons(CLASS_IN);

    /* Generates DNS header, copy the header to request header field */
    struct header *dns_header = gen_header();
    memcpy(request, dns_header, sizeof(struct header));
    pos += sizeof(struct header);

    /* Generate DNS query section */
    token = strtok(name, ".");
    while (token != NULL)
    {
        len = strlen(token);
        if ((pos + len + 1) > BUF_SIZE)
            return 1;
        request[pos++] = len;
        memcpy(request + pos, token, len);
        pos += len;
        token = strtok(NULL, ".");
    }
    if ((pos + 1) > BUF_SIZE)
        return 1;
    request[pos++] = '\0';

    /* Generate Type section */
    if ((pos + sizeof(q_type)) > BUF_SIZE)
        return 1;
    memcpy(request + pos, &q_type, sizeof(q_type));
    pos += sizeof(q_type);

    /* Generate Class section */
    if ((pos + sizeof(q_class)) > BUF_SIZE)
        return 1;
    memcpy(request + pos, &q_class, sizeof(q_class));
    pos += sizeof(q_class);

    /* Update request length */
    *request_len = pos;

    return 0;
}

/**
 * Parse dns name form received buffer.
 * ------------------------------
 * Parameters:
 *     dns: The DNS buffer.
 *     offset: Offset to current query filed.
 *     domain: Query domain name.
 *     domain_len: Length of domain.
 * Returns:
 *     0 if success.
 */
int dns_parse_domain(unsigned char *dns, int offset, unsigned char *domain, int *domain_len);

/**
 * Parse the received DNS request.
 * ------------------------------
 * Parameters:
 *     msg: The DNS request message.
 *     msg_size: Size of the message.
 *     dnsquery: The queries to parse for.
 * Returns:
 *     0 if success.
 */
int parse_query(unsigned char *msg, int msg_size, struct query *dnsquery)
{
    /* Skip the header, starts from the end of the header */
    int header_len = sizeof(struct header);
    int parse_res = 0;
    int step = 0;
    int domain_step = 0;
    int parse_domain_res;

    // if message is shorter than header length, return failed
    if (msg_size < header_len)
    {
        return 1;
    }

    // query domain name
    parse_domain_res = dns_parse_domain(msg, header_len, dnsquery->name, &domain_step);
    if (parse_domain_res != 0)
    {
        return parse_domain_res;
    }

    // if no buffer data for query type(short) and query class(short), return failed
    if (msg_size < (header_len + domain_step + 4))
    {
        return 2;
    }

    (*dnsquery).qtype = *(unsigned short *)(msg + header_len + domain_step);
    (*dnsquery).qtype = ntohs((*dnsquery).qtype);

    (*dnsquery).qclass = *(unsigned short *)(msg + header_len + domain_step + 2);
    (*dnsquery).qclass = ntohs((*dnsquery).qclass);

    return 0;
}


int dns_parse_domain(unsigned char *dns, int offset, unsigned char *domain, int *domain_step)
{
    // temporary buffer value
    unsigned char val;
    // length for pure domain filed
    int tmp_domain_len;

    tmp_domain_len = 0;
    // loop until '\0' occured
    while (1)
    {
        val = *(unsigned char *)(dns + offset);
        // if '\0', break loop
        if (val == 0)
        {
            domain[tmp_domain_len - 1] = 0;
            tmp_domain_len--;
            break;
        }
        else
        {
            // if not '\0', copy specified count chars
            memcpy(domain + tmp_domain_len, dns + offset + 1, val);
            tmp_domain_len += val;
            domain[tmp_domain_len] = '.';
            tmp_domain_len++;

            offset += (val + 1);
        }
    }

    // first count char + domain + '\0'
    *domain_step = 1 + tmp_domain_len + 1;
    return 0;
}

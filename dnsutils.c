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
 * Generate DNS request header
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
int gen_dns_request(unsigned char *request, int *request_len, char *name) {
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
    while(token != NULL) {
        len = strlen(token);
        if ((pos + len + 1) > BUF_SIZE) return 1;
        request[pos++] = len;
        memcpy(request + pos, token, len);
        pos += len;
        token = strtok(NULL, ".");
    }
    if ((pos + 1) > BUF_SIZE) return 1;
    request[pos++] = '\0';

    /* Generate Type section */
    if ((pos + sizeof(q_type)) > BUF_SIZE) return 1;
    memcpy(request + pos, &q_type, sizeof(q_type));
    pos += sizeof(q_type);

    /* Generate Class section */
    if ((pos + sizeof(q_class)) > BUF_SIZE) return 1;
    memcpy(request + pos, &q_class, sizeof(q_class));
    pos += sizeof(q_class);

    /* Update request length */
    *request_len = pos;

    return 0;
}

int dns_parse_domain(unsigned char *dns, int offset, unsigned char *domain, int *domain_len);
int dns_parse_query(unsigned char *dns, int left, int offset, struct query *queries, int *query_len);

/**
 * Parse the received DNS request.
 * ------------------------------
 * Parameters:
 *     msg: The DNS request message.
 *     msg_size: Size of the message.
 *     queries: The queries to parse for.
 *     queries_len: The length of queries.
 * Returns:
 *     0 if success.
 */
int parse_query(unsigned char *msg, int msg_size, struct query *queries, int queries_len)
{
    /* Skip the header, starts from the end of the header */
    int offset = sizeof(struct header);
    int parse_res = 0;
    int left = msg_size - offset;
    int step = 0;

    // assert we only process one query, not multiple quries.
    for (int i = 0; i< 1; i++)
    {
        if (left < 0)
        {
            return 1;
        }

        parse_res = dns_parse_query(msg, left, offset, &queries[i], &step);
        if (parse_res != 0) 
        {
            return parse_res;
        }
        left -= step;
        offset += step;
    }

    return 0;
}

int dns_parse_query(unsigned char *dns, int left, int offset, struct query *queries, int *step)
{
    int domain_step = 0;
    int parse_domain_res = 0;

    parse_domain_res = dns_parse_domain(dns, offset, queries[0].name, &domain_step);
    if (parse_domain_res != 0)
    {
        return parse_domain_res;
    }
    if (left < (offset + domain_step + 4))
    {
        return 2;
    }

    queries[0].ques.qtype = *(unsigned short *)(dns + offset + domain_step);
    queries[0].ques.qtype = ntohs(queries[0].ques.qtype);

    queries[0].ques.qclass = *(unsigned short *)(dns + offset + domain_step + 2);
    queries[0].ques.qclass = ntohs(queries[0].ques.qclass);

    *step = domain_step + 4;

    return 0;
}

int dns_parse_domain(unsigned char *dns, int offset, unsigned char *domain, int *domain_step)
{
    unsigned char val, *pval;
    unsigned short len;
    int tmp_domain_len;

    tmp_domain_len = 0;
    while (1)
    {
        pval = (unsigned char *)(dns + offset);
        val = *pval;

        if (val == 0)
        {
            domain[tmp_domain_len - 1] = 0;
            tmp_domain_len--;
            break;
        }
        else if (val <= 63)
        {
            memcpy(domain + tmp_domain_len, dns + offset + 1, val);
            tmp_domain_len += val;
            domain[tmp_domain_len] = '.';
            tmp_domain_len++;

            offset += (val + 1);
        }
        else
        {
            // len = *(unsigned short *)(dns + offset);
            // len = ntohs(len);
            // len = len & (~0xc000);
            // offset = len;

            offset = (int)(*(dns + offset));
        }
    }

    // first count + domain + '\0'
    *domain_step = 1 + tmp_domain_len + 1;
    return 0;
}

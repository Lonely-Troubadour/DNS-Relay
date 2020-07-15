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

/**
 * Parse the received DNS request.
 * ------------------------------
 * Parameters:
 *     msg: The DNS request message.
 *     size: Size of the message.
 *     name: The name to parse for.
 * Returns:
 *     0 if success.
 */
int parse_query(unsigned char *msg, int size, char *name) {
    /* Length of the field */ 
    uint8_t len = 0;
    /* Skip the header, starts from the end of the header */
    int pos = sizeof(struct header); 
    int name_pos = 0;

    if (size < sizeof(struct header)) return 1;

    /* Read name */
    while(msg[pos] != '\0') {
        len = msg[pos++];
        memcpy((name+name_pos), (msg+pos), len);
        name_pos += len;
        pos += len;
        /* Add period '.' to name */
        name[name_pos++] = '.';
    }

    return 0;
}

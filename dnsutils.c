#include <stdio.h>
#include "dnsutils.h"

uint16_t gen_id() {
    return 1234;
}

struct header * gen_header() {
    struct header* ptr_header;

    /* Allocate memory space */
    ptr_header = (struct header*) malloc (sizeof(struct header));
    if (ptr_header == NULL) {
        fprintf(stderr, "Generate header failed!");
        exit(1);
    }
    /* Initialize memory space */
    memset(ptr_header, 0, sizeof(struct header));

    /* Generate header */
    (*ptr_header).id = htons(gen_id());
    (*ptr_header).flags = htons(0x0100); // Standard query
    (*ptr_header).qd_count = htons(1);
    
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dnsrelay.h"
#include "dnsutils.h"

int main(int argc, char const *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: dnstest name");
        exit(1);
    }

    char name[MAX_LENGTH];
    unsigned char request[BUF_SIZE];

    memset(name, 0, MAX_LENGTH);
    memset(request, 0, BUF_SIZE);

    strncpy(name, argv[1], MAX_LENGTH);
    // printf("%s\n", name);

    gen_dns_request(request, name);

    // FILE *fp = NULL;
    // fp = fopen("./data/dnsrelay.txt", "r");
    // int sock = init_socket();
    
    return 0;
}


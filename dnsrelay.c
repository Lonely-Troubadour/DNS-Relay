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
    int request_len = 0;
    int result = 0;
    struct sockaddr_in *addr;
    int addr_size = 0;

    memset(name, 0, MAX_LENGTH);
    memset(request, 0, BUF_SIZE);
    addr = (struct sockaddr_in*) malloc(sizeof(struct sockaddr_in));

    strcpy(name, argv[1]);
    // printf("%s\n", name);

    gen_dns_request(request, &request_len, name);
    addr_size = gen_in_addr(addr);

    // FILE *fp = NULL;
    // fp = fopen("./data/dnsrelay.txt", "r");
    int sock = init_socket();
    result = sendto(sock, request, request_len, 0, (struct sockaddr*)addr, \
    addr_size);

    printf("Send result: \n");
    printf("%d\n", result);

    return 0;
}

/** 
 * Creates a socket.
 * This methods initialize a socket.
 * ----------------------------------
 * Arguments: None.
 * Returns: Socket Id. 
 */
int init_socket() {
    /** 
     * Parameters specification:
     * PF_INET: IPv4 protocols, Internet addresses.
     * SOCK_DGRAM: UDP, connectionless, messages of max length.
     * 0: Default protocol.
     */
    int sock_id = socket (PF_INET, SOCK_DGRAM, 0);
    if (sock_id < 0) {
        fprintf(stderr, "ERROR! Creating socket failed.\n");
        exit(1);
    }

    return sock_id;
}

/**
 * Generates inet ipv4 address
 * Socket address that request sends to
 * ------------------------------------
 * Parameters:
 *     addr: Pointer to socket in address struct.
 * Returns:
 *     Size of the address.
 */
int gen_in_addr(struct sockaddr_in *addr) {
    // For differences between sockaddr_in and sockaddr, goto:
    // https://stackoverflow.com/questions/21099041/
    // why-do-we-cast-sockaddr-in-to-sockaddr-when-calling-bind
    
    memset(addr, 0, sizeof(struct sockaddr_in));
    (*addr).sin_family = PF_INET;
    (*addr).sin_addr.s_addr = inet_addr(PUBLIC_DNS_SERVER);
    (*addr).sin_port = htons(PORT);

    return sizeof(*addr);
}

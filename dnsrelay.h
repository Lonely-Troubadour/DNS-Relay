#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
// #include <netinet/in.h>

#define PORT 53
#define WIDTH 16
#define PUBLIC_DNS_SERVER "114.114.114.114"

int init_socket();

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

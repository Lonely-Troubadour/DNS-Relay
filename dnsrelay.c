#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "dnsrelay.h"
#include "dnsutils.h"
#include "dbutils.h"

int main(int argc, char const *argv[])
{
    struct query queries[MAX_QUERIES];
    char name[MAX_LENGTH];
    unsigned char request[BUF_SIZE];
    unsigned char recv[BUF_SIZE];

    struct sockaddr_in *dns_addr;
    struct sockaddr_in *server_addr;
    struct sockaddr_in client_addr;

    int request_len = 0;
    int send_len = 0;
    int recv_len = 0;
    socklen_t dns_addr_size = 0;
    socklen_t server_addr_size = 0;
    socklen_t client_addr_size = sizeof(client_addr);
    int sock = 0;
    int parse_query_res = 0;
    
    /* Initialize variables */
    memset(name, 0, MAX_LENGTH);
    memset(request, 0, BUF_SIZE);
    memset(recv, 0, BUF_SIZE);
    dns_addr = (struct sockaddr_in*) malloc(sizeof(struct sockaddr_in));
    server_addr = (struct sockaddr_in*) malloc(sizeof(struct sockaddr_in));

    // if (argc < 2) {
    //     perror("Usage: dnsrelay data\n");
    //     exit(1);
    // }

    // strcpy(name, argv[1]);
    // strcpy(name, "www.bupt.edu.cn");
    // if (gen_dns_request(request, &request_len, name)) {
    //     perror("ERROR: Generate DNS request failed.\n");
    //     exit(1);
    // }

    /* Create socket */
    sock = init_socket();

    /* Generate DNS server address and local server address */
    if (gen_in_addr(dns_addr, &dns_addr_size, server_addr, &server_addr_size)) {
        perror("ERROR: Generate addresses failed.\n");
        exit(1);
    }

    /* Bind server socket for listening */
    if (bind(sock, (struct sockaddr*)server_addr, server_addr_size) < 0) {
        perror("ERROR: bind failed.\n");
        exit(1);
    }
    
    /* Keeps listening on port 53 */
    while(1) {
        memset(recv, 0, BUF_SIZE);
        client_addr_size = sizeof(client_addr);

        printf("Listening...\n");

        recv_len = recvfrom(sock, recv, BUF_SIZE, 0, \
        (struct sockaddr*)&client_addr, &client_addr_size);
        printf("Received request: %d\n", recv_len);
        if (recv_len == -1) {
            perror("ERROR: Receive failed.");
            exit(1);
        }
        
        // TODO: parse dns request
        parse_query_res = parse_query(recv, recv_len, queries, SIZEOF_ARR(queries));
        if (parse_query_res == 0)
        {
            // printf("%s", name);
            printf("success to parse query info {name: %s, type: %d, class: %d}\n", queries[0].name, queries[0].ques.qtype, queries[0].ques.qclass);
        }
        else
        {
            printf("failed to parse query info, return %d\n", parse_query_res);
        }

        break;
    }

    /* Send DNS request */
    memcpy(request, recv, recv_len);
    request_len = recv_len;

    send_len = sendto(sock, request, request_len, 0, \
    (struct sockaddr*)dns_addr, dns_addr_size);
    if (send_len < 0) {
        perror("ERROR: Send DNS request failed.\n");
        exit(1);
    }
    printf("Send success, packet length: \n");
    printf("%d\n", send_len);

    /* Receive response */
    memset(recv, 0, BUF_SIZE);
    recv_len = recvfrom(sock, recv, sizeof(recv), 0, \
    (struct sockaddr*)dns_addr, &dns_addr_size);
    if (recv_len < 0) {
        perror("ERROR: receive packet failed.\n");
        exit(1);
    }
    printf("Receive success, packet length: \n");
    printf("%d\n", recv_len);
    

    /* Send back */
    memcpy(request, recv, recv_len);
    request_len = recv_len;

    send_len = sendto(sock, request, request_len, 0, \
    (struct sockaddr*)&client_addr, client_addr_size);
    if (send_len < 0) {
        perror("ERROR: Send DNS request failed.\n");
        exit(1);
    }
    printf("Send back success, packet length: \n");
    printf("%d\n", send_len);

    /* Close socket and clean up memory */
    close(sock);
    if (dns_addr) free(dns_addr);
    if (server_addr) free(server_addr);

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
     *     PF_INET: IPv4 protocols, Internet addresses.
     *     SOCK_DGRAM: UDP, connectionless, messages of max length.
     *     0: Default protocol.
     */
    int sock_id = socket (AF_INET, SOCK_DGRAM, 0);
    if (sock_id < 0) {
        perror("ERROR: Create socket failed.\n");
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
int gen_in_addr(struct sockaddr_in *dns_addr, unsigned int *dns_addr_size, \
struct sockaddr_in * server_addr, unsigned int *server_addr_size) {
    // For differences between sockaddr_in and sockaddr, goto:
    // https://stackoverflow.com/questions/21099041/
    // why-do-we-cast-sockaddr-in-to-sockaddr-when-calling-bind
    
    memset(dns_addr, 0, sizeof(struct sockaddr_in));
    (*dns_addr).sin_family = AF_INET;
    (*dns_addr).sin_addr.s_addr = inet_addr(DNS_SERVER);
    (*dns_addr).sin_port = htons(PORT);
    *dns_addr_size = sizeof(*dns_addr);

    memset(server_addr, 0, sizeof(struct sockaddr_in));
    (*server_addr).sin_family = AF_INET;
    (*server_addr).sin_addr.s_addr = htonl(INADDR_ANY);
    // inet_addr(LOCAL_SERVER); 
    (*server_addr).sin_port = htons(PORT);
    *server_addr_size = sizeof(*server_addr);

    return 0;
}

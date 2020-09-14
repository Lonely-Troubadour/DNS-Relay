#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "dnsrelay.h"
#include "dnsutils.h"
#include "dbutils.h"
#include "utils.h"

int main(int argc, char const *argv[])
{
    struct query dnsquery;
    int parse_count = 0;

    /* Buffers */
    unsigned char request[BUF_SIZE];
    unsigned char response[BUF_SIZE];
    unsigned char recv[BUF_SIZE];
    unsigned short id;
    
    /* Exec options */
    char *db = NULL;
    char *dns_server = NULL;
    int debug = 0;
    int op = 0;

    /* Socket address */
    struct sockaddr_in *dns_addr = NULL;
    struct sockaddr_in *server_addr = NULL;
    struct sockaddr_in client_addr;

    /* Socket relevant vars */
    char ip_addr[MAX_LENGTH];
    int request_len = 0;
    int response_len = 0;
    int send_len = 0;
    int recv_len = 0;
    socklen_t dns_addr_size = 0;
    socklen_t server_addr_size = 0;
    socklen_t client_addr_size = sizeof(client_addr);
    int sock_recv = 0;
    int sock_send = 0;

    time_t tm_now = time(0);
    char tm_str[64];

    /* Initialize variables */
    memset(request, 0, BUF_SIZE);
    memset(recv, 0, BUF_SIZE);
    memset(response, 0, BUF_SIZE);
    dns_addr = (struct sockaddr_in*) malloc(sizeof(struct sockaddr_in)); 
    server_addr = (struct sockaddr_in*) malloc(sizeof(struct sockaddr_in));
    if (!dns_addr || !server_addr) {
        perror("Initialize DNS address failed.");
        exit(1);
    }

    /* Windows initialization */
#if defined(_WIN32) || defined(_WIN64)
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		printf("WSAStartup failed\n");
		return -1;
	}
#endif

    /* Usage */
    usage();

    /* Parse exec options */
    parse_opt(argc, argv, &debug, &dns_server, &db);
    print_debug(debug);
    print_dns_server(dns_server);
    print_db_path(db);

    if (debug == 2) {
        print_db(db);
    }

    /* Create socket */
    if (init_socket(&sock_recv, &sock_send)) {
        exit(1);
    }

    /* Generate DNS server address and local server address */
    if (gen_in_addr(dns_addr, &dns_addr_size, server_addr, &server_addr_size, \
    dns_server)) {
        perror("ERROR: Generate addresses failed.\n");
        exit(1);
    }

    /* Bind server socket for listening */
    if (bind(sock_recv, (struct sockaddr*)server_addr, server_addr_size) < 0) {
        perror("ERROR: bind failed.");
        exit(1);
    }
    printf("Bind port 53...OK\n");
    printf("Running...\n-----------------\n");
    
    /* Keeps listening on port 53 */
    while(1) {
        memset(recv, 0, BUF_SIZE);
        client_addr_size = sizeof(client_addr);
        op = 0;

        if (debug == 1 || debug == 2)
            printf("Listening...\n");

        recv_len = recvfrom(sock_recv, recv, BUF_SIZE, 0, \
        (struct sockaddr*)&client_addr, &client_addr_size);
        // printf("Received request: %d\n", recv_len);
        if (recv_len == -1) {
            perror("ERROR: Receive failed.");
            exit(1);
        }

        if (debug == 2) {
            print_send_recv("RECV from", &client_addr, recv, recv_len);
        }

        if (recv_len > sizeof(struct header)) {
            if (debug == 2) {
                print_buf_header(recv);
            }
        }
        
        /* Parse received DNS query */ 
        if (parse_query(recv, recv_len, &dnsquery)) {
            perror("ERROR: parse query failed.");
            exit(1);
        }

        parse_count += 1;
        if (debug == 1) {
            char *ip = NULL;
#if defined(_WIN32) || defined(_WIN64) 
            ip = inet_ntoa(client_addr.sin_addr);
#else 
            struct in_addr in = client_addr.sin_addr;
            /*INET_ADDRSTRLEN = 16 */
            char ip_str[INET_ADDRSTRLEN]; 
            /* Store the IP addr in the string. */
            inet_ntop(AF_INET, &in, ip_str, sizeof(ip_str));
            ip = ip_str;
#endif
            tm_now = time(0);
            strftime(tm_str, sizeof(tm_str), "%Y-%m-%d %H:%M:%S", localtime(&tm_now));
            printf(
                "  %d:  %s  Client %s\t%s, TYPE %d, CLASS %d\n",
                parse_count, tm_str, ip, dnsquery.name, dnsquery.qtype, dnsquery.qclass);
        }
        else if (debug == 2) {
            printf(
                "Parse query sucess, {name: \"%s\", type: %d, class: %d}\n",
                dnsquery.name, dnsquery.qtype, dnsquery.qclass);
        }

        memset(request, 0, BUF_SIZE);
        memcpy(request, recv, recv_len);
        request_len = recv_len;

        /* Check query type */
        if (check_type(dnsquery.qtype) == 0) 
            if (lookup(dnsquery.name, &db, ip_addr) == 0)
                op = 1;

        switch(op) {
            case 0:
                memcpy(&id , request, 2);
                id++;
                memcpy(request , &id, 2);
                 /* Send DNS request to dns server*/   
                send_len = sendto(sock_send, request, request_len, 0, \
                (struct sockaddr*)dns_addr, dns_addr_size);
                if (send_len < 0) {
                    perror("ERROR: Send DNS request failed.\n");
                    exit(1);
                }
                // printf("Send success, packet length: %d\n", send_len);

                if (debug == 2) {
                    print_send_recv("Send to", dns_addr, request, send_len);
                }

                /* Receive response from dns server*/
                memset(recv, 0, BUF_SIZE);
                recv_len = recvfrom(sock_send, recv, sizeof(recv), 0, \
                (struct sockaddr*)dns_addr, &dns_addr_size);
                if (recv_len < 0) {
                    perror("ERROR: receive packet failed.\n");
                    exit(1);
                }
                // printf("Receive success, packet length: %d\n", recv_len);

                if (debug == 2) {
                    print_send_recv("RECV from", dns_addr, recv, recv_len);
                }

                /* Send response back to client*/
                memset(response, 0, BUF_SIZE);
                memcpy(response, recv, recv_len);
                response_len = recv_len;
                memcpy(&id , response, 2);
                id--;
                memcpy(response , &id, 2);

                send_len = sendto(sock_recv, response, response_len, 0, \
                (struct sockaddr*)&client_addr, client_addr_size);
                if (send_len < 0) {
                    perror("ERROR: Send DNS request failed.\n");
                    exit(1);
                }
                // printf("Send back success, packet length: %d\n", send_len);

                if (debug == 2) {
                    print_send_recv("Send to", &client_addr, response, send_len);
                }

                break;
            case 1:
                memset(response, 0, BUF_SIZE);
                response_len = gen_response(response, request, request_len, ip_addr);
                send_len = sendto(sock_recv, response, response_len, 0, \
                (struct sockaddr*)&client_addr, client_addr_size);
                if (send_len < 0) {
                    perror("ERROR: Send DNS request failed.\n");
                    exit(1);
                }
                // printf("Send back success, packet length: %d\n", send_len);

                if (debug == 2) {
                    print_send_recv("Send to", &client_addr, response, send_len);
                }

                break;
            default:
                printf("Wrong query, try again!\n");
                break;
        }
    }

    /* Close socket and clean up memory */
    close(sock_recv);
    close(sock_send);
    if (dns_addr) free(dns_addr);
    if (server_addr) free(server_addr);
    if (dns_server) free(dns_server);
    if (db) free(db);

    return 0;
}

/** 
 * Creates a socket.
 * This methods initialize a socket.
 * ----------------------------------
 * Parameters: None.
 * Returns: Socket Id. 
 */
int init_socket(int *sock_recv, int *sock_send) {
    /** 
     * Parameters specification:
     *     PF_INET: IPv4 protocols, Internet addresses.
     *     SOCK_DGRAM: UDP, connectionless, messages of max length.
     *     0: Default protocol.
     */
    *sock_recv = socket (AF_INET, SOCK_DGRAM, 0);
    *sock_send =  socket (AF_INET, SOCK_DGRAM, 0);
    if (*sock_recv < 0 || *sock_send < 0) {
        perror("ERROR: Create socket failed.\n");
        exit(1);
    }

    return 0;
}

/**
 * Generates inet ipv4 address
 * Socket address that request sends to and current server addr.
 * ------------------------------------
 * Parameters:
 *     dns_addr: pointer to socket in address struct.
 *     dns_addr_size: size of sock addr.
 *     server_ader: pointer to current server addr.
 *     server_addr_size: size of sock addr.
 * Returns:
 *     0 if success.
 */
int gen_in_addr(struct sockaddr_in *dns_addr, unsigned int *dns_addr_size, \
struct sockaddr_in *server_addr, unsigned int *server_addr_size, \
char *dns_server) {
    // For differences between sockaddr_in and sockaddr, goto:
    // https://stackoverflow.com/questions/21099041/
    // why-do-we-cast-sockaddr-in-to-sockaddr-when-calling-bind
    
    if (dns_server == NULL) dns_server = DNS_SERVER;

    memset(dns_addr, 0, sizeof(struct sockaddr_in));
    (*dns_addr).sin_family = AF_INET;
    (*dns_addr).sin_addr.s_addr = inet_addr(dns_server);
    (*dns_addr).sin_port = htons(PORT);
    *dns_addr_size = sizeof(*dns_addr);

    memset(server_addr, 0, sizeof(struct sockaddr_in));
    (*server_addr).sin_family = AF_INET;
    (*server_addr).sin_addr.s_addr = inet_addr(LOCAL_SERVER);; 
    // htonl(INADDR_ANY);
    // inet_addr(LOCAL_SERVER); 
    (*server_addr).sin_port = htons(PORT);
    *server_addr_size = sizeof(*server_addr);

    return 0;
}

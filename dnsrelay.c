#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "dnsrelay.h"
#include "dnsutils.h"
#include "dbutils.h"

int main(int argc, char const *argv[])
{
    struct query dnsquery;

    /* Buffers */
    unsigned char request[BUF_SIZE];
    unsigned char response[BUF_SIZE];
    unsigned char recv[BUF_SIZE];
    
    /* Exec options */
    char *db = NULL;
    char *dns_server = NULL;
    int debug = 0;

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
    int sock = 0;
    int op = 0;
    
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

    /* Parse exec options */
    parse_opt(argc, argv, &debug, &dns_server, &db);

    /* Create socket */
    sock = init_socket();

    /* Generate DNS server address and local server address */
    if (gen_in_addr(dns_addr, &dns_addr_size, server_addr, &server_addr_size, \
    dns_server)) {
        perror("ERROR: Generate addresses failed.\n");
        exit(1);
    }

    /* Bind server socket for listening */
    if (bind(sock, (struct sockaddr*)server_addr, server_addr_size) < 0) {
        perror("ERROR: bind failed.");
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
        if (debug == 2)
        {
            print_send_recv("RECV from", &client_addr, recv, recv_len);
        }

        if (debug == 2 && recv_len > sizeof(struct header))
        {
            print_buf_header(recv);
        }
        
        /* Parse received DNS query */ 
        if (parse_query(recv, recv_len, &dnsquery)) {
            perror("ERROR: parse query failed.");
            exit(1);
        }
        printf(
            "Parse query sucess, {name: \"%s\", type: %d, class: %d}\n",
            dnsquery.name, dnsquery.qtype, dnsquery.qclass);

        memset(request, 0, BUF_SIZE);
        memcpy(request, recv, recv_len);
        request_len = recv_len;

        /* Check query type */
        if (check_type(dnsquery.qtype) == 0) 
            if (lookup(dnsquery.name, &db, ip_addr) == 0)
                op = 1;

        switch(op) {
            case 0:
                 /* Send DNS request to dns server*/   
                send_len = sendto(sock, request, request_len, 0, \
                (struct sockaddr*)dns_addr, dns_addr_size);
                if (send_len < 0) {
                    perror("ERROR: Send DNS request failed.\n");
                    exit(1);
                }
                printf("Send success, packet length: \n");
                printf("%d\n", send_len);

                if (debug == 2)
                {
                    print_send_recv("Send to", dns_addr, request, send_len);
                }

                /* Receive response from dns server*/
                memset(recv, 0, BUF_SIZE);
                recv_len = recvfrom(sock, recv, sizeof(recv), 0, \
                (struct sockaddr*)dns_addr, &dns_addr_size);
                if (recv_len < 0) {
                    perror("ERROR: receive packet failed.\n");
                    exit(1);
                }
                printf("Receive success, packet length: \n");
                printf("%d\n", recv_len);

                if (debug == 2)
                {
                    print_send_recv("RECV from", dns_addr, recv, recv_len);
                }

                /* Send response back to client*/
                memset(response, 0, BUF_SIZE);
                memcpy(response, recv, recv_len);
                response_len = recv_len;

                send_len = sendto(sock, response, response_len, 0, \
                (struct sockaddr*)&client_addr, client_addr_size);
                if (send_len < 0) {
                    perror("ERROR: Send DNS request failed.\n");
                    exit(1);
                }
                printf("Send back success, packet length: \n");
                printf("%d\n", send_len);

                if (debug == 2)
                {
                    print_send_recv("Send to", &client_addr, response, send_len);
                }

                break;
            case 1:
                memset(response, 0, BUF_SIZE);
                response_len = gen_response(response, request, request_len, ip_addr);
                send_len = sendto(sock, response, response_len, 0, \
                (struct sockaddr*)&client_addr, client_addr_size);
                if (send_len < 0) {
                    perror("ERROR: Send DNS request failed.\n");
                    exit(1);
                }
                printf("Send back success, packet length: \n");
                printf("%d\n", send_len);

                if (debug == 2)
                {
                    print_send_recv("Send to", &client_addr, response, send_len);
                }

                break;
            default:
                printf("Wrong query, try again!\n");
                break;
        }
    }

    /* Close socket and clean up memory */
    close(sock);
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
    (*server_addr).sin_addr.s_addr = htonl(INADDR_ANY);
    // inet_addr(LOCAL_SERVER); 
    (*server_addr).sin_port = htons(PORT);
    *server_addr_size = sizeof(*server_addr);

    return 0;
}

/** Parse the exec options.
 * --------------------------
 * Parameters:
 *     argc: arg numbers.
 *     argv: arguments
 *     debug: debug opt.
 *     dns_server: dns server address.
 *     db: database path.
 * Returns:
 *     0 if success.
 */
int parse_opt(int argc, char **argv, int *debug, char **dns_server, char **db) {
    char *token;
    int i = 1;
    while (i < argc) {
        if (!strcmp(argv[i], "-d")) *debug = 1;
        else if (!strcmp(argv[i], "-dd")) *debug = 2;
        else if (!strcmp(argv[i], "-s")) {
            i++;
            *dns_server = (char *) malloc(sizeof(char) * MAX_LENGTH);
            if (*dns_server == NULL) {
                fprintf(stderr, "ERROR: DNS server addr initilization failed.");
                exit(1);
            }
            strcpy(*dns_server, argv[i]);
        } else if (!strcmp(argv[i], "-p")) {
            i++;
            *db = (char *) malloc(sizeof(char) * MAX_LENGTH);
            if (*db == NULL) {
                fprintf(stderr, "ERROR: database path initilization failed.");
                exit(1);
            }
            strcpy(*db, argv[i]);
        } else {
            fprintf(stderr, "ERROR: Unrecognized opt %s\n", argv[i]);
            usage();
            exit(1);
        }
        i++;
    }

    return 0;
}

/** Pirnt usage info */
void usage() {
    printf("---------helper---------\n");
    printf("dns relay 1.0\n");
    printf("Usage: [commands] [options]\n");
    printf("Commands:\n");
    printf("\t[-d|-dd], debug mode\n");
    printf("\t-s [dns_server_addres]\n");
    printf("\t-p [path_to_db_file]\n");
}

void print_send_recv(char *send_recv, struct sockaddr_in *addr, char *buf, int buf_len)
{
    int port = ntohs(addr->sin_port);
    char* ip = NULL;
#ifdef __MINGW32__  //windows上打印方式
    ip = inet_ntoa(addr->sin_addr);
#else //linux上打印方式
    struct in_addr in = addr->sin_addr;
    char ip_str[INET_ADDRSTRLEN]; //INET_ADDRSTRLEN这个宏系统默认定义 16
    //成功的话此时IP地址保存在str字符串中。
    inet_ntop(AF_INET, &in, ip_str, sizeof(ip_str));
    ip = ip_str;
#endif
    printf("%s %s:%d  (%d bytes) ", send_recv, ip, port);
    for (int i=0; i<buf_len; ++i)
    {
        printf(" %x", buf[i]);
    }
    printf("\n");
}

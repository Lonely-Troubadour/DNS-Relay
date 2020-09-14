#include "dnsrelay.h"
#include "dnsutils.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

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
int parse_opt(int argc, const char **argv, int *debug, char **dns_server, char **db) {
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

/**
 * Print debug level 2 info.
 * Parameters:
 * Returns:
 */
void print_send_recv(char *send_recv, struct sockaddr_in *addr, unsigned char *buf, int buf_len)
{
    int port = ntohs(addr->sin_port);
    char* ip = NULL;
#if defined(_WIN32) || defined(_WIN64) 
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

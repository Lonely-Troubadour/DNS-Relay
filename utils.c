#include "utils.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/** Pirnt usage info */
void usage() {
    printf("-------------------------------------------------------\n");
    printf("DNSRELAY, Version 1.0\n");
    printf("Copyright(c) Yongjian Hu, Song Zhihao, Si Yutong\n\n");
    printf("Usage: [commands] [options]\n");
    printf("Commands:\n");
    printf("\t[-d|-dd], debug mode\n");
    printf("\t[-s] <dns_server_addres>\n");
    printf("\t[-p] <path_to_db_file>\n\n");
    printf("Example: ./dnsrelay -d -s 219.141.136.10 -p ./data/dnsrelay.txt\n");
    printf("-------------------------------------------------------\n");
}

void print_debug(int debug) {
    if (-1 < debug && debug < 3)
        printf("Debug level: %d\n", debug);
}

void print_dns_server(char *DNS_server) {
    if (DNS_server)
        printf("Name server: %s\n", DNS_server);
}

void print_db_path(char *path) {
    if (path)
        printf("DB file path: \"%s\"\n", path);
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

    if (*dns_server == NULL) {
        *dns_server = (char *) malloc(sizeof(char) * MAX_LENGTH);
        if (*dns_server == NULL) {
            fprintf(stderr, "ERROR: DNS server addr initilization failed.");
            exit(1);
        }
        strcpy(*dns_server, DNS_SERVER);
    }

    if (*db == NULL) {
        *db = (char *) malloc(sizeof(char) * MAX_LENGTH);
        if (*db == NULL) {
            fprintf(stderr, "ERROR: database path initilization failed.");
            exit(1);
        }
        strcpy(*db, DB);
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


void print_buf_header(const unsigned char *buf)
{
    struct header header;
    buf2header(buf, &header);
    print_header(&header);
}

void buf2header(const unsigned char *buf, struct header *header)
{
    memcpy(header, buf, sizeof(struct header));
    header->id = ntohs(header->id);
    header->qd_count = ntohs(header->qd_count);
    header->an_count = ntohs(header->an_count);
    header->ns_count = ntohs(header->ns_count);
    header->ar_count = ntohs(header->ar_count);
}

void print_header(const struct header *header)
{
    struct {
        uint8_t QR : 1;
        uint8_t opcode : 4;
        uint8_t AA : 1;
        uint8_t TC : 1;
        uint8_t RD : 1;
        uint8_t RA : 1;
        uint8_t zero : 3;
        uint8_t rcode : 4; 
    } flags;
    memcpy(&flags, &header->flags, sizeof(flags));
    printf("\tID %x%x, QR %d, OPCODE %d, AA %d, TC %d, RD %d, RA %d, Z: 0, RCODE: %d\n", header->id, flags.QR, flags.opcode, flags.AA, flags.TC, flags.RD, flags.RA, flags.rcode);
    printf("\tQDCOUNT %d, ANCOUNT %d, NSCOUNT %d, ARCOUNT %d\n", header->qd_count, header->an_count, header->ns_count, header->ar_count);
}

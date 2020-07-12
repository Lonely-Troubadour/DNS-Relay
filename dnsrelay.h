#include <sys/socket.h>
#include <sys/types.h>

#if defined(_WIN32) || defined(_WIN64)
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#define PORT 53
#define WIDTH 16
#define DNS_SERVER "114.114.114.114"
#define LOCAL_SERVER "127.0.0.1"

int init_socket();
int gen_in_addr(struct sockaddr_in *dns_addr, unsigned int *dns_addr_len, \
struct sockaddr_in * server_addr, unsigned int *server_addr_size);
int gen_in6_addr();

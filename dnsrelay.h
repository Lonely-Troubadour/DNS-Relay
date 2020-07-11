#include <sys/socket.h>
#include <sys/types.h>

#if defined(_WIN32) || defined(_WIN64)
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#define PORT 53
#define WIDTH 16
#define PUBLIC_DNS_SERVER "114.114.114.114"

int init_socket();
int gen_in_addr();
int gen_in6_addr();

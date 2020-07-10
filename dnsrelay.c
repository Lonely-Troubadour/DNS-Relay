#include "dnsrelay.h"

int main(int argc, char const *argv[])
{
    FILE *fp = NULL;
    fp = fopen("./data/dnsrelay.txt", "r");
    int sock = init_socket();
    
    return 0;
}


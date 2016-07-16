#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "nat_type.h"

static char* STUN_SERVER = "stun.ideasip.com";

int main(int argc, char** argv)
{
    char* stun_server = STUN_SERVER;
    char* local_host = "0.0.0.0";
    uint16_t stun_port = DEFAULT_STUN_SERVER_PORT;
    uint16_t local_port = DEFAULT_LOCAL_PORT;

    static char* usage = "usage: [-h] [-H STUN_HOST] [-P STUN_PORT] [-i SOURCE_IP] [-p SOURCE_PORT]\n";
    int opt;
    while ((opt = getopt (argc, argv, "H:h:P:p:i")) != -1)
    {
        switch (opt)
        {
            case 'h':
                printf("%s", usage);
                break;
            case 'H':
                stun_server = optarg;
                break;
            case 'P':
                stun_port = atoi(optarg);
                break;
            case 'p':
                local_port = atoi(optarg);
                break;
            case 'i':
                local_host = optarg;
                break;
            case '?':
            default:
                printf("invalid option: %c\n", opt);
                printf("%s", usage);

                return -1;
        }
    }

    char ext_ip[16] = {0};
    uint16_t ext_port = 0;

	nat_type type = detect_nat_type(stun_server, stun_port, local_host, local_port, ext_ip, &ext_port);

	printf("NAT type: %s\n", get_nat_desc(type));
    if (ext_port) {
        printf("external address: %s:%d\n", ext_ip, ext_port);
    } else {
        return -1;
    }

	return 0;
}
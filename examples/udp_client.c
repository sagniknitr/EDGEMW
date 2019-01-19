#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <edgeos_datetime.h>
#include <edgeos_netapi.h>

int main(int argc, char **argv)
{
    int fd;

    if (argc != 3) {
        fprintf(stderr, "%s <ip> <port>\n", argv[0]);
        return -1;
    }

    fd = edge_os_create_udp_client();
    if (fd < 0) {
        return -1;
    }

    while (1) {

        edge_os_nanosleep(1000 * 1000 * 1000);

        char msg[] = "Hello from udp client";

        edge_os_udp_sendto(
                    fd, msg, strlen(msg), argv[1], atoi(argv[2]));
    }

    return 0;
}


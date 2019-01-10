#include <stdlib.h>
#include <stdio.h>
#include <edgeos_netapi.h>

int main(int argc, char **argv)
{
    int fd;

    if (argc != 3) {
        fprintf(stderr, "%s <ip> <port>\n", argv[0]);
        return -1;
    }

    fd = edge_os_create_udp_server(argv[1], atoi(argv[2]));
    if (fd < 0) {
        return -1;
    }

    while (1) {
        int ret;
        char rxbuf[100];

        ret = edge_os_udp_recvfrom(
                        fd, rxbuf, sizeof(rxbuf), NULL, NULL);
        if (ret < 0) {
            break;
        }

        printf("rxmsg : %s\n", rxbuf);
    }

    edge_os_del_udp_socket(fd);
    return 0;
}


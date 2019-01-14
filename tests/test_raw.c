#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <edgeos_datetime.h>
#include <edgeos_netapi.h>
#include <edgeos_evtloop.h>

void listener(int fd, void *priv)
{
    struct edge_os_raw_sock_rx_params rx;
    uint8_t msg[2048];
    int ret;

    printf("recvfrom called\n");
    ret = edge_os_raw_recvfrom(fd, msg, sizeof(msg), &rx);
    if (ret < 0) {
        perror("recvfrom");
        return;
    }

    printf("Recv %d\n", ret);
    printf("rx->protocol %d \n", rx.protocol);
    printf("rx->ifindex %d\n", rx.ifindex);
    printf("rx->pkttype %d\n", rx.pkt_type);
}

int rawsock_test(int argc, char **argv)
{
    void *raw_priv;
    int count = 1000;

    if (!strcmp(argv[1], "sender")) {
        raw_priv = edge_os_raw_socket_create(EDGEOS_RAW_SOCK_ETH, "wlp68s0", 2048);
        if (!raw_priv) {
            return -1;
        }

        while (1) {
            uint8_t srcmac[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
            uint8_t dstmac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
            char *msg = "Hello ..";

            edge_os_raw_socket_send_eth_frame(raw_priv, srcmac, dstmac, 0x0800, (uint8_t *)msg, strlen(msg));

            edge_os_nanosleep(1000 * 1000);

            count --;
            if (count <= 0) {
                break;
            }
        }
    } else if (!strcmp(argv[1], "listener")) {
        struct edge_os_evtloop_base base;
        int fd;
        
        raw_priv = edge_os_raw_socket_create(EDGEOS_RAW_SOCK_SNIFFER, "wlp68s0", 4096);

        fd = edge_os_raw_socket_get_fd(raw_priv);

        printf("fd %d\n", fd);
        edge_os_evtloop_init(&base, NULL);

        edge_os_evtloop_register_socket(&base, NULL, fd, listener);

        edge_os_evtloop_run(&base);
    } else {
        return -1;
    }

    edge_os_raw_socket_delete(raw_priv);
    return 0;
}


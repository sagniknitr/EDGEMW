#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <edgeos_datetime.h>
#include <edgeos_netapi.h>

int rawsock_test(int argc, char **argv)
{
    void *raw_priv;

    raw_priv = edge_os_raw_socket_create(EDGEOS_RAW_SOCK_ETH, "wlp68s0", 2048);
    if (!raw_priv) {
        return -1;
    }

    int count = 1000;

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

    return 0;
}


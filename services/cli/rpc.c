#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <edge_os.h>
#include <rpc.h>

int edge_os_cli_rpc_send_show_version(int fd)
{
    struct edge_os_cli_rpc rpc;
    int ret;

    rpc.command = EDGE_OS_CLI_RPC_CLI_VERSION_REQ;

    ret = edge_os_tcp_send(fd, &rpc, sizeof(struct edge_os_cli_rpc));
    if (ret < 0) {
        return -1;
    }

    return 0;
}

int edge_os_cli_rpc_recv_show_version(int fd, char *buf, int buflen)
{
    char rxbuf[4096];
    struct edge_os_cli_rpc *rpc;
    int final_len;
    int ret;

    rpc = (struct edge_os_cli_rpc *)rxbuf;
    ret = edge_os_tcp_recv(fd, rpc, sizeof(rxbuf));
    if (ret < 0) {
        return -1;
    }

    if (rpc->command != EDGE_OS_CLI_RPC_CLI_VERSION_RESP) {
        return -1;
    }

    final_len = ret - sizeof(struct edge_os_cli_rpc);

    memcpy(buf, rpc->value, final_len);

    return final_len;
}


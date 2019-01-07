#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <edge_os.h>
#include <backend.h>

#define CLI_SERVER_ADDR "/tmp/edge_os_cli.service"

int edge_os_cli_cmdargs_parse(int argc, char **argv, struct edge_os_cli_service_priv *priv)
{
    int ret;

    while ((ret = getopt(argc, argv, "")) != -1) {
    }

    return 0;
}

static int edge_os_cli_setup_server(struct edge_os_cli_service_priv *priv)
{
    priv->fd = edge_os_create_tcp_unix_server(CLI_SERVER_ADDR, 2);
    if (priv->fd < 0) {
        return -1;
    }

    return 0;
}

static void edge_os_cli_server_read_conn(int sock, void *app_priv)
{
    int ret;
    char msg[1024];

    ret = edge_os_tcp_recv(sock, msg, sizeof(msg));
    if (ret <= 0) {
        return;
    }
}

static void edge_os_cli_server_accept_conn(int sock, void *app_priv)
{
    struct edge_os_cli_service_priv *cli_priv = app_priv;
    int cli_fd;
    char ip[140];
    int port;

    cli_fd = edge_os_accept_conn(sock, ip, &port);
    if (cli_fd < 0) {
        return;
    }

    edge_os_evtloop_register_socket(&cli_priv->base, cli_priv, cli_fd,
                                    edge_os_cli_server_read_conn);
}

int main(int argc, char **argv)
{
    int ret;
    struct edge_os_cli_service_priv *cli_priv;

    cli_priv = calloc(1, sizeof(struct edge_os_cli_service_priv));
    if (!cli_priv) {
        return -1;
    }

    edge_os_evtloop_init(&cli_priv->base, NULL);

    ret = edge_os_cli_cmdargs_parse(argc, argv, cli_priv);
    if (ret < 0) {
        return -1;
    }

    ret = edge_os_cli_setup_server(cli_priv);
    if (ret < 0)
        return -1;

    edge_os_evtloop_register_socket(&cli_priv->base, cli_priv, cli_priv->fd,
                                    edge_os_cli_server_accept_conn);

    edge_os_evtloop_run(&cli_priv->base);

    return 0;
}


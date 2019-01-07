#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

struct edge_os_cli_service_priv {
    int fd;
};

int edge_os_cli_cmdargs_parse(int argc, char **argv, struct edge_os_cli_service_priv *priv)
{
    return -1;
}

int main(int argc, char **argv)
{
    int ret;
    struct edge_os_cli_service_priv *cli_priv;

    cli_priv = calloc(1, sizeof(struct edge_os_cli_service_priv));
    if (!cli_priv) {
        return -1;
    }

    ret = edge_os_cli_cmdargs_parse(argc, argv, cli_priv);
    if (ret < 0) {
        return -1;
    }

    return 0;
}


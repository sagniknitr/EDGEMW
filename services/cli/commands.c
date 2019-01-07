#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <edge_os.h>

#define CLI_SERVER_PATH "/tmp/edge_os_cli.service"

struct edge_os_cli_command_priv {
    int fd;
};

static int edge_os_cli_command_cmdargs_parse(
                int argc, char **argv,
                struct edge_os_cli_command_priv *priv)
{
    int ret;

    while ((ret = getopt(argc, argv, "")) != -1) {
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct edge_os_cli_command_priv *cmd_priv;
    int ret;

    cmd_priv = calloc(1, sizeof(struct edge_os_cli_command_priv));
    if (!cmd_priv) {
        return -1;
    }

    ret = edge_os_cli_command_cmdargs_parse(
                        argc, argv, cmd_priv);
    if (ret < 0) {
        return -1;
    }

    return 0;
}


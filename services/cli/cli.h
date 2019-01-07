#ifndef __EDGEOS_SERVICES_CLI_H__
#define __EDGEOS_SERVICES_CLI_H__

#include <edge_os.h>

struct edge_os_cli_command_arg_list {
    char *arg;
    struct edge_os_cli_command_arg_list *next;
};

struct edge_os_cli_command_priv {
    int fd;
    struct edge_os_evtloop_base base;
};

int edge_os_cli_command_db_setup(struct edge_os_cli_command_priv *cmd_priv);

void edge_os_cli_call_callback(char *command,
                              void *priv,
                              struct edge_os_cli_command_arg_list *arg_list);

#endif


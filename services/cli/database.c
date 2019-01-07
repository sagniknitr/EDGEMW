#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <cli.h>
#include <show_callback.h>

static struct edge_os_cli_base_list {
    char *command;
    void (*callback)(struct edge_os_cli_command_arg_list *arg_list, void *priv);
} base_list[] = {
    {"show", show_callback},
#if 0
    {"net", net_callback},
    {"clear", clear_callback},
    {"enter", enter_callback},
    {"leave", leave_callback},
    {"user", user_callback},
    {"exit", exit_callback},
    {"load", load_callback},
    {"diagnose", diagnose_callback},
    {"configure" configure_callback},
    {"commit", commit_callback},
    {"start", start_callback},
    {"stop", stop_callback},
    {"exec", exec_callback},
#endif
};

int edge_os_cli_command_db_setup(struct edge_os_cli_command_priv *cmd_priv)
{
    return 0;
}

int edge_os_cli_call_callback(char *command,
                              void *priv,
                              struct edge_os_cli_command_arg_list *arg_list)
{
    size_t i;
    int flag = 0;

    for (i = 0; i < sizeof(base_list) / sizeof(base_list[0]); i ++) {
        if (!strcmp(base_list[i].command, command)) {
            base_list[i].callback(arg_list, priv);
            flag = 1;
        }
    }

    return flag;
}

void edge_os_cli_show_help()
{
    size_t i;

    printf("help:\n");
    for (i = 0; i < sizeof(base_list) / sizeof(base_list[0]); i ++) {
        printf("\t%s\n", base_list[i].command);
    }
}


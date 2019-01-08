#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <cli.h>

#define CLI_VERSION "v0.1"

static void version_callback(struct edge_os_cli_command_arg_list *arg_list, void *priv)
{
    if (arg_list)
        edge_os_error("cli: the command 'show version' does not accept any arguments\n");
    edge_os_log("version %s\n", CLI_VERSION);
}

struct edge_os_show_callback_list {
    char *command;
    void (*callback)(struct edge_os_cli_command_arg_list *arg_list, void *priv);
} show_callback_list[] = {
    {"version", version_callback},
};

void show_callback_help()
{
    size_t i;

    edge_os_error("show called without any args..\n");
    edge_os_error("help:\n");
    for (i = 0; i < sizeof(show_callback_list) / sizeof(show_callback_list[0]); i ++)
        edge_os_log("\t%s\n", show_callback_list[i].command);
}

void show_callback(struct edge_os_cli_command_arg_list *arg_list,
                   void *priv)
{
    struct edge_os_cli_command_arg_list *arg;
    size_t i;

    if (!arg_list) {
        show_callback_help();
        return;
    }

    for (arg = arg_list; arg; arg = arg->next) {
        for (i = 0; i < sizeof(show_callback_list) / sizeof(show_callback_list[0]); i ++) {
            if (!strcmp(show_callback_list[i].command, arg_list->arg)) {
                show_callback_list[i].callback(arg_list->next, priv);
                return;
            }
        }
    }
}


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <cli.h>

static void version_callback(struct edge_os_cli_command_arg_list *arg_list, void *priv)
{
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

    printf("show called without any args..\n");
    printf("help:\n");
    for (i = 0; i < sizeof(show_callback_list) / sizeof(show_callback_list[0]); i ++)
        printf("\t%s\n", show_callback_list[i].command);
}

void show_callback(struct edge_os_cli_command_arg_list *arg_list,
                   void *priv)
{
    if (!arg_list) {
        show_callback_help();
        return;
    }
}


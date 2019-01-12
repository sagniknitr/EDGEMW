#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <cli.h>
#include <edge_os.h>

static char *console_str = "console $ ";

#define CLI_SERVER_PATH "/tmp/edge_os_cli.service"

static int edge_os_cli_command_cmdargs_parse(
                int argc, char **argv,
                struct edge_os_cli_command_priv *priv)
{
    int ret;

    while ((ret = getopt(argc, argv, "")) != -1) {
    }

    return 0;
}

struct edge_os_backend_monitor_priv {
    int fd;
};

static void edge_os_backend_socket_monitor(void *data)
{
    struct edge_os_backend_monitor_priv *monitor = data;
    char msg[1024];
    int ret;

    while (1) {
        ret = edge_os_tcp_recv(monitor->fd, msg, sizeof(msg));
        if (ret <= 0) {
            edge_os_error("cli: backend cut connection abruptly.. shutting down..\n");
            exit(1);
        }
    }
}

static int edge_os_cli_backend_setup(struct edge_os_cli_command_priv *cmd_priv)
{
    cmd_priv->fd = edge_os_create_tcp_unix_client(CLI_SERVER_PATH);
    if (cmd_priv->fd < 0) {
        return -1;
    }

    struct edge_os_backend_monitor_priv *monitor;

    monitor = calloc(1, sizeof(struct edge_os_backend_monitor_priv));
    if (!monitor) {
        return -1;
    }

    monitor->fd = cmd_priv->fd;

    cmd_priv->backend_thread = edge_os_thread_create(
                                edge_os_backend_socket_monitor,
                                monitor, NULL, 0);
    if (!cmd_priv->backend_thread) {
        return -1;
    }

    return 0;
}

static void edge_os_evtloop_console_read(int sock, void *app_priv)
{
    int ret;
    char read_buf[1024];
    struct edge_os_cli_command_arg_list *args = NULL;
    struct edge_os_cli_service_priv *cli_priv = app_priv;

    edgeos_write_file(1, console_str, strlen(console_str));

    memset(read_buf, 0, sizeof(read_buf));
    ret = edgeos_read_file(sock, read_buf, sizeof(read_buf));
    if (ret < 0) {
        return;
    }

    // user keep doing ENTER
    if (read_buf[0] == '\n')
        return;

    read_buf[strlen(read_buf) - 1] = '\0';

    int off = 0;
    int read_len = strlen(read_buf);

    while (1) {
        struct edge_os_cli_command_arg_list *t;
        char output[1024];

        memset(output, 0, sizeof(output));

        off = edge_os_token_parser(read_buf, read_len,
                                  ' ', output,
                                  sizeof(output), off);
        if (off < 0) {
            break;
        }

        t = calloc(1, sizeof(struct edge_os_cli_command_arg_list));
        if (!t) {
            return;
        }

        t->arg = strdup(output);

        if (!args) {
            args = t;
        } else {
            struct edge_os_cli_command_arg_list *a;

            a = args;
            while (a->next)
                a = a->next;

            a->next = t;
        }
    }

    ret = edge_os_cli_call_callback(args->arg, cli_priv, args->next);
    if (ret == 0) {
        edge_os_error("cli: invalid command %s\n", args->arg);
        edge_os_cli_show_help();
    }

    struct edge_os_cli_command_arg_list *t1;
    struct edge_os_cli_command_arg_list *t2;

    t1 = t2 = args;
    while (t1) {
        t2 = t1;
        t1 = t1->next;
        free(t2->arg);
        free(t2);
    }
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

    ret = edge_os_cli_backend_setup(cmd_priv);
    if (ret < 0) {
        return -1;
    }

    ret = edge_os_cli_command_db_setup(cmd_priv);
    if (ret < 0) {
        return -1;
    }

    edge_os_thread_execute(cmd_priv->backend_thread);

    while (1) {
        edge_os_evtloop_console_read(1, cmd_priv);
    }

    return 0;
}


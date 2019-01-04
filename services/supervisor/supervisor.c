#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <edge_os.h>
#include <supervisor.h>

struct supervisor_cmdline {
    char *config_file;
    char *ipaddr;
    uint32_t port;
};

struct supervisor_monitor_list {
    pid_t process_id;
    char *process_name;
    char *process_fullpath;
    char *process_args[24];
    int process_args_n;
    int process_restart_count;
    int process_dependency_level;
    int process_fds[2];
};

struct supervisor_priv {
    struct supervisor_cmdline *cmdline;
    struct edge_os_config_parse_set *config_set;
    struct edge_os_list_base monitor_list;
    struct edge_os_evtloop_base evtbase;
    void *cmdctrl_priv;
};

static int supervisor_parse_cmdline(struct supervisor_priv *priv, int argc, char **argv)
{
    int ret;

    priv->cmdline = calloc(1, sizeof(struct supervisor_cmdline));
    if (!priv->cmdline)
        return -1;

    while ((ret = getopt(argc, argv, "p:i:o:")) != -1) {
        switch (ret) {
            case 'p':
                priv->cmdline->config_file = optarg;
            break;
            case 'i':
                priv->cmdline->ipaddr = optarg;
            break;
            case 'o':
                if (edge_os_stou(optarg, &priv->cmdline->port, 1)) {
                    return -1;
                }
            break;
        }
    }

    if (!priv->cmdline->config_file || !priv->cmdline->ipaddr
                || (priv->cmdline->port > 65535)) {
        return -1;
    } else {
        priv->config_set = edge_os_config_parse(priv->cmdline->config_file);
        if (!priv->config_set)
            return -1;
    }

    return 0;
}

static int supervisor_monitor_list_setup(struct supervisor_priv *priv)
{
    struct edge_os_config_parse_set *set;
    struct supervisor_monitor_list *monitor_list = NULL;

    edge_os_list_init(&priv->monitor_list);

    for (set = priv->config_set; set; set = set->next) {
        if (!strcmp(set->var, "process_name")) {
            if (monitor_list) {
                edge_os_list_add_tail(&priv->monitor_list, monitor_list);
            }

            monitor_list = calloc(1, sizeof(struct supervisor_monitor_list));
            if (!monitor_list) {
                return -1;
            }

            monitor_list->process_name = strdup(set->val);
        } else if (!strcmp(set->var, "process_fullpath")) {
            monitor_list->process_fullpath = strdup(set->val);
        } else if (!strcmp(set->var, "process_restart_count")) {
            if (edge_os_stoi(set->val, &monitor_list->process_restart_count, 1)) {
                return -1;
            }
        } else if (!strcmp(set->var, "process_args")) {
            size_t item = 0;
            int ret = 0;
            int input_len = strlen(set->val);
            char output[256];

            while (1) {
                ret = token_parser(set->val, input_len, ' ', output, sizeof(output), ret);
                if (ret == -1) {
                    break;
                }

                monitor_list->process_args[item] = strdup(output);
                item ++;
                if (item >= (sizeof(monitor_list->process_args) / sizeof(monitor_list->process_args[0]))) {
                    break;
                }
            }
            monitor_list->process_args_n = item;
        } else if (!strcmp(set->var, "process_dependency_level")) {
            if (edge_os_stoi(set->val, &monitor_list->process_dependency_level, 1)) {
                return -1;
            }
        }
    }

    if (monitor_list)
        edge_os_list_add_tail(&priv->monitor_list, monitor_list);
    else
        return -1;

    return 0;
}

static int __supervisor_cmdctrl_rpc_f(int fd, void *buf, int buflen, char *ip, int port)
{
    return 0;
}

static int supervisor_init_command_sock(struct supervisor_priv *priv)
{
    priv->cmdctrl_priv = edge_os_create_server_managed(&priv->evtbase, priv, EDGEOS_SERVER_UDP,
                                                        priv->cmdline->ipaddr, priv->cmdline->port, -1,
                                                        1024, NULL, __supervisor_cmdctrl_rpc_f);
    if (!priv->cmdctrl_priv)
        return -1;

    return 0;
}

static int __supervisor_start_process(struct supervisor_monitor_list *item)
{
    int ret;

    char fullpath[200];

    strcpy(fullpath, item->process_fullpath);
    strcat(fullpath, "/");
    strcat(fullpath, item->process_name);

    ret = access(fullpath, R_OK | X_OK);
    if (ret < 0) {
        return -1;
    }

    item->process_id = fork();
    if (item->process_id == 0) {
        close(item->process_fds[0]);

        ret = execv(fullpath, item->process_args);
        if (ret < 0) {
            _exit(1);
        }
        _exit(1);
    } else {
        close(item->process_fds[1]);
    }

    return 0;
}

struct __supervisor_process_parameters {
    struct supervisor_priv *priv;
    struct supervisor_monitor_list *monitor;
};

static int __supervisor_start_processes(struct supervisor_monitor_list *monitor, struct supervisor_priv *priv)
{
    int ret;

    ret = pipe(monitor->process_fds);
    if (ret < 0)
        return -1;

    ret = __supervisor_start_process(monitor);
    if (ret < 0)
        return -1;

    struct __supervisor_process_parameters *params;

    params = calloc(1, sizeof(struct __supervisor_process_parameters));
    if (!params)
        return -1;

    params->priv = priv;
    params->monitor = monitor;

    edge_os_evtloop_register_socket(&priv->evtbase, params,
                                        monitor->process_fds[0], __supervisor_monitor_process);

    return 0;
}

static int __supervisor_restart_process(struct supervisor_monitor_list *monitor, struct supervisor_priv *priv)
{
    int ret;
    int wait_out;

    // cleanup ..
    ret = waitpid(-1, &wait_out, WNOHANG);

    close(monitor->process_fds[0]);
    close(monitor->process_fds[1]);

    ret = __supervisor_start_processes(monitor, priv);

    return ret;
}

static void __supervisor_monitor_process(int sock, void *priv)
{
    struct __supervisor_process_parameters *params = priv;
    struct supervisor_priv *spriv = params->priv;
    struct supervisor_monitor_list *monitor = params->monitor;
    int ret;
    int wait_out;

    ret = waitpid(-1, &wait_out, WNOHANG);
    printf("res %d pid %d error %s\n", ret, monitor->process_id, strerror(errno));
    if (ret == monitor->process_id) {
        edge_os_evtloop_unregister_socket(&spriv->evtbase, monitor->process_fds[0]);
        close(monitor->process_fds[0]);
        __supervisor_restart_process(monitor, spriv);
    }

    free(params);
}

static int supervisor_start_processes(struct supervisor_priv *priv)
{
    struct edge_os_list *item;
    struct supervisor_monitor_list *monitor;
    int ret;

    for (item = priv->monitor_list.head; item; item = item->next) {
        monitor = item->data;

        ret = __supervisor_start_processes(monitor, priv);
        if (ret < 0) {
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct supervisor_priv *priv;
    int ret;

    priv = calloc(1, sizeof(struct supervisor_priv));
    if (!priv)
        return -1;

    ret = supervisor_parse_cmdline(priv, argc, argv);
    if (ret < 0)
        return -1;

    ret = supervisor_monitor_list_setup(priv);
    if (ret < 0)
        return -1;

    ret = edge_os_evtloop_init(&priv->evtbase, NULL);
    if (ret < 0)
        return -1;

    ret = supervisor_init_command_sock(priv);
    if (ret < 0)
        return -1;

    ret = supervisor_start_processes(priv);
    if (ret < 0)
        return -1;

    edge_os_evtloop_run(&priv->evtbase);

    return 0;
}


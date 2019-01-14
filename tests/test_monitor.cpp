#include <iostream>
#include <string>
extern "C" {
#include <edgeos_evtloop.h>
#include <edgeos_monitor.h>
}

static struct edge_os_evtloop_base base;

static void monitor_files(int fd, void *priv)
{
    struct edge_os_watch_status *status;

    status = edge_os_get_watch_events(priv);
    if (!status) {
        return;
    }

    struct edge_os_watch_status *s;

    for (s = status; s; s = s->next) {
        printf("s->path %s s->events %02x\n",
                            s->path, s->events);
    }
    exit(1);
}

int monitor_test(int argc, char **argv)
{
    void *mon_priv;
    int ret;

    printf("argv[1] %s\n", argv[1]);
    edge_os_evtloop_init(&base, NULL);

    mon_priv = edge_os_file_monitor_init();
    edge_os_monitor_event event = static_cast<edge_os_monitor_event>(EDGEOS_MONITOR_EVT_INACCESS | EDGEOS_MONITOR_EVT_INDELETE | EDGEOS_MONITOR_EVT_INMODIFY | EDGEOS_MONITOR_EVT_INOPEN);

    ret = edge_os_monitor_add(mon_priv, argv[1], event);
    if (ret < 0) {
        return -1;
    }

    int fd;

    fd = edge_os_get_monitor_fd(mon_priv);

    edge_os_evtloop_register_socket(&base, mon_priv, fd,
                            monitor_files);

    edge_os_evtloop_run(&base);

    return 0;
}


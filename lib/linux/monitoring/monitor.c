/**
 * @brief - monitoring layer interfaces from EDGEOS
 * @Author - Sagnik Basu (sagnik.basu@outlook.com)
 * @Copyright  - all rights reserved
 * License - MIT
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/inotify.h>
#include <edgeos_monitor.h>
#include <edgeos_logger.h>

struct edge_os_monitor_watch {
    int wfd;
    char *path;
};

struct edge_os_monitor_priv {
    int fd;
    struct edge_os_monitor_watch wfd_set[64];
    char read_buf[4096];
};

void* edge_os_monitor_init()
{
    struct edge_os_monitor_priv *priv;

    priv = calloc(1, sizeof(struct edge_os_monitor_priv));
    if (!priv) {
        edge_os_alloc_err(__FILE__, __func__, __LINE__);
        return NULL;
    }

    uint32_t i;

    for (i = 0; i < sizeof(priv->wfd_set) / sizeof(priv->wfd_set[0]); i ++) {
        priv->wfd_set[i].wfd = -1;
        priv->wfd_set[i].path = NULL;
    }

    priv->fd = inotify_init();
    if (priv->fd < 0) {
        edge_os_log_with_error(errno, "monitor: failed to inotify_init @ %s %u ",
                                        __func__, __LINE__);
        return NULL;
    }

    return priv;
}


int edge_os_monitor_add(void *mon_priv, const char *filename, edge_os_monitor_event events)
{
    struct edge_os_monitor_priv *priv = mon_priv;
    int ret;
    uint32_t i;
    uint32_t size;

    if (!filename) {
        return -1;
    }

    size = sizeof(priv->wfd_set) / sizeof(priv->wfd_set[0]);

    ret = access(filename, R_OK);
    if (ret < 0) {
        edge_os_log_with_error(errno, "monitor: failed to access %s @ %s %u ",
                                    filename, __func__, __LINE__);
        return -1;
    }

    int mode = 0;

    if (events & EDGEOS_MONITOR_EVT_INACCESS) {
        mode |= IN_ACCESS;
    }
    if (events & EDGEOS_MONITOR_EVT_INDELETE) {
        mode |= IN_DELETE;
    }
    if (events & EDGEOS_MONITOR_EVT_INMODIFY) {
        mode |= IN_MODIFY;
    }
    if (events & EDGEOS_MONITOR_EVT_INOPEN) {
        mode |= IN_OPEN;
    }

    for (i = 0; i < size; i ++) {
        if (priv->wfd_set[i].wfd == -1) {
            break;
        }
    }

    if (i == size) {
        edge_os_error("monitor: no valid watch fd index found for insertion @ %s %u\n",
                            __func__, __LINE__);
        return -1;
    }

    priv->wfd_set[i].wfd = inotify_add_watch(priv->fd, filename, mode);
    if (priv->wfd_set[i].wfd < 0) {
        edge_os_log_with_error(errno, "monitor: failed to add watch @ %s %u ",
                            __func__, __LINE__);
        return -1;
    }

    priv->wfd_set[i].path = strdup(filename);

    return 0;
}

struct edge_os_watch_status* edge_os_get_watch_events(void *mon_priv)
{
    struct edge_os_watch_status *status = NULL;
    struct edge_os_watch_status *tail = NULL;
    struct edge_os_monitor_priv *priv = mon_priv;
    int len;

    len = read(priv->fd, priv->read_buf, sizeof(priv->read_buf));
    if (len < 0) {
        return NULL;
    }

    int off = 0;
    while (1) {
        struct inotify_event *evt;
        struct edge_os_watch_status *tmp;
        uint32_t i;

        evt = (struct inotify_event *)(priv->read_buf + off);

        for (i = 0; i < sizeof(priv->wfd_set) / sizeof(priv->wfd_set[0]); i ++) {
            if (evt->wd == priv->wfd_set[i].wfd) {
                tmp = calloc(1, sizeof(struct edge_os_watch_status));
                if (!tmp) {
                    return NULL;
                }

                strcpy(tmp->path, priv->wfd_set[i].path);

                if (evt->mask & IN_OPEN) {
                    tmp->events |= EDGEOS_MONITOR_EVT_INOPEN;
                }
                if (evt->mask & IN_ACCESS) {
                    tmp->events |= EDGEOS_MONITOR_EVT_INACCESS;
                }
                if (evt->mask & IN_DELETE) {
                    tmp->events |= EDGEOS_MONITOR_EVT_INDELETE;
                }
                if (evt->mask & IN_MODIFY) {
                    tmp->events |= EDGEOS_MONITOR_EVT_INMODIFY;
                }

                if (!status) {
                    status = tmp;
                    tail = tmp;
                } else {
                    tail->next = tmp;
                    tail = tmp;
                }
                break;
            }
        }

        off += sizeof(struct inotify_event);
        if (off <= len) {
            break;
        }
    }

    return status;
}

int edge_os_monitor_remove(void *priv, const char *filename)
{
    struct edge_os_monitor_priv *mon_priv = priv;
    int ret;
    uint32_t i;

    for (i = 0; i < sizeof(mon_priv->wfd_set) / sizeof(mon_priv->wfd_set[0]); i ++) {
        if (!strcmp(mon_priv->wfd_set[i].path, filename)) {
            ret = inotify_rm_watch(mon_priv->fd, mon_priv->wfd_set[i].wfd);
            if (ret != 0) {
                return -1;
            }
            break;
        }
    }

    return 0;
}

void edge_os_free_watch_events(struct edge_os_watch_status *status)
{
    struct edge_os_watch_status *t = status;
    struct edge_os_watch_status *t2 = t;

    while (t) {
        t2 = t;
        t = t->next;
        free(t2);
    }
}

int edge_os_get_monitor_fd(void *mon_priv)
{
    struct edge_os_monitor_priv *priv = mon_priv;

    return priv->fd;
}



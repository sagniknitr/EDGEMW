/**
 * @brief - monitoring layer interfaces from EDGEOS
 * @Author - Devendra Naga (devendra.aaru@gmail.com)
 * @Copyright  - all rights reserved
 * License - MIT
 */

#ifndef __EDGEOS_MONITOR_H__
#define __EDGEOS_MONITOR_H__

typedef enum {
    EDGEOS_MONITOR_EVT_INACCESS = 0x01, // read or execve
    EDGEOS_MONITOR_EVT_INDELETE = 0x02,
    EDGEOS_MONITOR_EVT_INMODIFY = 0x04,
    EDGEOS_MONITOR_EVT_INOPEN = 0x08,
} edge_os_monitor_event;

struct edge_os_watch_status {
    char path[256];
    edge_os_monitor_event events;
    struct edge_os_watch_status *next;
};

void* edge_os_monitor_init();

int edge_os_monitor_add(void *mon_priv, const char *filename, edge_os_monitor_event events);

int edge_os_monitor_remove(void *priv, const char *filename);

struct edge_os_watch_status* edge_os_get_watch_events(void *mon_priv);

void edge_os_free_watch_events(struct edge_os_watch_status *status);

int edge_os_get_monitor_fd(void *mon_priv);

#endif



#ifndef __EDGE_EVTLOOP_H__
#define __EDGE_EVTLOOP_H__

#include <sys/select.h>
#include <list.h>

struct edge_os_evtloop_timer {
    int fd;
    int sec;
    int nsec;
    void *callback_data;
    void (*callback)(void *callback_data);
};

struct edge_os_evtloop_socket {
    int fd;
    void *callback_data;
    void (*callback)(void *callback_data);
};

struct edge_os_evtloop_signal {
    int fd;
    int sig;
    void *callback_data;
    void (*callback)(void *callback_data);
};

struct edge_os_evtloop_base {
    fd_set allfd_;
    int sig_fd;
    int maxfd_;
    struct edge_os_list_base *timer_base;
    struct edge_os_list_base *socket_base;
    struct edge_os_list_base *signal_base;
};

#endif

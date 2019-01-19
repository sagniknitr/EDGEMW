#ifndef __EDGEOS_EVTLOOP_H__
#define __EDGEOS_EVTLOOP_H__

#include <sys/socket.h>
#include <edgeos_list.h>

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
    void (*callback)(int sock, void *callback_data);
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
    struct edge_os_list_base timer_base;
    struct edge_os_list_base socket_base;
    struct edge_os_list_base signal_base;
};

int edge_os_evtloop_init(struct edge_os_evtloop_base *base, void *priv);
int edge_os_evtloop_register_timer(void *handle, void *app_priv, int sec, int usec,
                                      void (*__timer_callback)(void *app_priv));
int edge_os_evtloop_register_socket(void *handle, void *app_priv, int sock,
                                       void (*__socket_callback)(int sock, void *app_priv));
int edge_os_evtloop_register_signal(void *handle, void *app_priv, int sig,
                                       void (*__signal_callback)(void *app_priv));
void edge_os_evtloop_run(void *handle);

int edge_os_evtloop_unregister_socket(void *handle, int sock);

void edge_os_evtloop_deinit(void *handle);

#endif


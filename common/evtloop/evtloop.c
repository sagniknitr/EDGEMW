#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <sys/time.h>
#include <evtloop.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/signalfd.h>
#include <unistd.h>
#include <fcntl.h>
#include <edgeos_logger.h>

int edge_os_evtloop_init(struct edge_os_evtloop_base *base, void *priv)
{
    edge_os_list_init(&base->timer_base);
    edge_os_list_init(&base->socket_base);
    edge_os_list_init(&base->signal_base);

    FD_ZERO(&base->allfd_);
    base->maxfd_ = 0;

    return 0;
}

int __edge_os_evtloop_register_timer(void *handle, void *app_priv, int sec, int usec, int oneshot,
                                     void (*__timer_callback)(void *app_priv))
{
    struct edge_os_evtloop_base *base = handle;
    struct edge_os_evtloop_timer *timer;
    int ret;

    timer = calloc(1, sizeof(struct edge_os_evtloop_timer));
    if (!timer) {
        return -1;
    }

    timer->sec = sec;
    timer->nsec = usec;
    timer->callback_data = app_priv;
    timer->callback = __timer_callback;

    timer->fd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (timer->fd < 0) {
        edge_os_err("evt: failed to timerfd_create @ %s %u\n", __func__, __LINE__);
        return -1;
    }

    struct itimerspec its;

    its.it_value.tv_sec = sec;
    its.it_value.tv_nsec = usec * 1000;
    if (oneshot) {
        its.it_interval.tv_sec = 0;
        its.it_interval.tv_nsec = 0;
    } else {
        its.it_interval.tv_sec = sec;
        its.it_interval.tv_nsec = usec * 1000;
    }

    ret = timerfd_settime(timer->fd, 0, &its, NULL);
    if (ret < 0) {
        edge_os_err("evt: failed to timerfd_settime sec [%d] usec [%d] @ %s %u\n",
                                        sec, usec, __func__, __LINE__);
        return -1;
    }

    printf("set timer %d\n", timer->fd);
    FD_SET(timer->fd, &base->allfd_);
    if (timer->fd > base->maxfd_)
        base->maxfd_ = timer->fd;

    edge_os_list_add_tail(&base->timer_base, timer);

    return 0;
}

int edge_os_evtloop_register_timer(void *handle, void *app_priv, int sec, int usec,
                                      void (*__timer_callback)(void *app_priv))
{
    return __edge_os_evtloop_register_timer(handle, app_priv, sec, usec, 0,
                                               __timer_callback);
}

int edge_os_evtloop_register_socket(void *handle, void *app_priv, int sock,
                                       void (*__socket_callback)(int sock, void *app_priv))
{
    struct edge_os_evtloop_base *base = handle;
    struct edge_os_evtloop_socket *sock_;

    if (sock < 0)
        return -1;

    sock_ = calloc(1, sizeof(struct edge_os_evtloop_socket));
    if (!sock_) {
        return -1;
    }

    sock_->fd = sock;
    sock_->callback_data = app_priv;
    sock_->callback = __socket_callback;

    FD_SET(sock, &base->allfd_);

    if (sock > base->maxfd_)
        base->maxfd_ = sock;

    edge_os_list_add_tail(&base->socket_base, sock_);

    return 0;
}

int edge_os_evtloop_register_signal(void *handle, void *app_priv, int sig,
                                       void (*__signal_callback)(void *app_priv))
{
    struct edge_os_evtloop_base *base = handle;
    struct edge_os_evtloop_signal *sig_;

    sig_ = calloc(1, sizeof(struct edge_os_evtloop_signal));
    if (!sig_) {
        return -1;
    }

    sig_->sig = sig;
    sig_->callback_data = app_priv;
    sig_->callback = __signal_callback;

    edge_os_list_add_tail(&base->signal_base, sig_);

    return 0;
}

static void _edge_os_timer_for_each(void *callback_data, void *priv)
{
    struct edge_os_evtloop_timer *timer = callback_data;
    fd_set *fdset = priv;
    uint64_t expiry = 0;
    int ret;

    if (FD_ISSET(timer->fd, fdset)) {
        ret = read(timer->fd, &expiry, sizeof(expiry));
        if (ret > 0) {
            timer->callback(timer->callback_data);
        }
    }
}

static void _edge_os_socket_for_each(void *callback_data, void *priv)
{
    struct edge_os_evtloop_socket *sock = callback_data;
    fd_set *fdset = priv;

    if (FD_ISSET(sock->fd, fdset)) {
        sock->callback(sock->fd, sock->callback_data);
    }
}

static int _edge_os_evtloop_caller(struct edge_os_evtloop_base *base, fd_set *fdmask)
{
    int ret;

    if (FD_ISSET(base->sig_fd, fdmask)) {
        struct signalfd_siginfo si;

        ret = read(base->sig_fd, &si, sizeof(si));
        if (ret < 0) {
            return -1;
        }

        if (ret != sizeof(si)) {
            return -1;
        }

        if ((si.ssi_signo == SIGTERM) ||
            (si.ssi_signo == SIGINT)) {
            return -1;
        }
    }

    ret = edge_os_list_for_each(&base->timer_base,
                                    _edge_os_timer_for_each, fdmask);

    ret = edge_os_list_for_each(&base->socket_base,
                                    _edge_os_socket_for_each, fdmask);

    return 0;
}

static void _edge_os_get_max_timerfd(void *callback_data, void *priv)
{
    struct edge_os_evtloop_timer *timer;
    int *maxfd = priv;

    timer = callback_data;

    if (*maxfd < timer->fd) {
        *maxfd = timer->fd;
    }

}

static void _edge_os_get_max_socket_fd(void *callback_data, void *priv)
{
    struct edge_os_evtloop_socket *sock;
    int *maxfd = priv;

    sock = callback_data;

    if (*maxfd < sock->fd) {
        *maxfd = sock->fd;
    }
}

static int __edge_os_evtloop_get_maxfd(struct edge_os_evtloop_base *base)
{
    int maxfd = 0;

    edge_os_list_for_each(&base->timer_base,
                            _edge_os_get_max_timerfd, &maxfd);

    edge_os_list_for_each(&base->socket_base,
                            _edge_os_get_max_socket_fd, &maxfd);

    return maxfd;
}

static int edge_os_evtloop_setup_term_signals()
{
    sigset_t mask;

    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);

    sigprocmask(SIG_BLOCK, &mask, NULL);

    return signalfd(-1, &mask, 0);
}

void edge_os_evtloop_run(void *handle)
{
    int ret;
    struct edge_os_evtloop_base *base = handle;
    fd_set allset;

    base->sig_fd = edge_os_evtloop_setup_term_signals();
    if (base->sig_fd < 0) {
        edge_os_err("evtloop: failed to signalfd @ %s %u\n", 
                                    __func__, __LINE__);
        return;
    }

    FD_SET(base->sig_fd, &base->allfd_);

    while (1) {
        FD_ZERO(&allset);
        allset = base->allfd_;

        int maxfd = __edge_os_evtloop_get_maxfd(base);

        if (maxfd < base->sig_fd)
            maxfd = base->sig_fd;

        ret = select(maxfd + 1, &allset, NULL, NULL, NULL);
        if (ret > 0) {
            int res;

            res = _edge_os_evtloop_caller(base, &allset);
            if (res < 0) {
                edge_os_err("evtloop: exception @ %s %u\n",
                                    __func__, __LINE__);
                break;
            }
        } else if (ret < 0) { // signal ! .. error .. ctrl + c
            break;
        }
    }
}

void edge_os_evtloop_deinit(void *handle)
{

}


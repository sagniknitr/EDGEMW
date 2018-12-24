#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net_socket.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <edgeos_logger.h>
#include <string.h>

struct edge_os_logger_ctx {
    int logfd_;
    char *ipaddr;
    int port;
};

void *edge_os_logger_init(char *ipaddr, int port)
{
    struct edge_os_logger_ctx *handle;

    handle = calloc(1, sizeof(struct edge_os_logger_ctx));
    if (!handle) {
        return NULL;
    }

    handle->logfd_ = edge_os_new_udp_socket();
    if (handle->logfd_ < 0) {
        free(handle);
        return NULL;
    }

    handle->ipaddr = strdup(ipaddr);
    handle->port = port;

    return handle;
}

void edge_os_logger_deinit(void *handle)
{
    struct edge_os_logger_ctx *_l = handle;

    if (_l) {
        free(_l->ipaddr);
        close(_l->logfd_);
        free(_l);
    }
}

int edge_os_logger_writemsg(void *handle, char *fmt, ...)
{
    struct edge_os_logger_ctx *l;
    char buf[4096];
    va_list arg;
    int len;

    l = handle;

    va_start(arg, fmt);
    len = vsnprintf(buf, sizeof(buf), fmt, arg);
    va_end(arg);

    return edge_os_udp_sendto(l->logfd_, buf, len, l->ipaddr, l->port);
}


#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <net_socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <evtloop.h>
#include <stdlib.h>
#include <edgeos_logger.h>

static int __socket(int family, int protocol)
{
    return socket(family, protocol, 0);
}

int edge_os_new_tcp_socket()
{
    return __socket(AF_INET, SOCK_STREAM);
}

int edge_os_del_tcp_socket(int sock)
{
    if (sock >= 0)
        close(sock);

    return 0;
}

int edge_os_new_udp_socket()
{
    return __socket(AF_INET, SOCK_DGRAM);
}

int edge_os_new_unix_socket()
{
    return __socket(AF_UNIX, SOCK_DGRAM);
}

void edge_os_del_udp_socket(int sock)
{
    close(sock);
}

int edge_os_create_udp_client()
{
    return edge_os_new_udp_socket();
}

int edge_os_create_udp_unix_client(const char *addr)
{
    struct sockaddr_un serv;
    int sock;
    int ret;

    sock = edge_os_new_unix_socket();
    if (sock < 0) {
        return -1;
    }

    unlink(addr);
    strcpy(serv.sun_path, addr);
    serv.sun_family = AF_UNIX;

    ret = bind(sock, (struct sockaddr *)&serv, sizeof(serv));
    if (ret < 0) {
        goto err;
    }

    return sock;
err:
    if (sock > 0)
        close(sock);

    return -1;
}

int edge_os_create_udp_unix_server(const char *addr)
{
    return edge_os_create_udp_unix_client(addr);
}

int edge_os_create_tcp_unix_client(const char *path)
{
    int sock;
    int ret;

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0)
        return -1;

    struct sockaddr_un serv;

    strcpy(serv.sun_path, path);
    serv.sun_family = AF_UNIX;

    ret = connect(sock, (struct sockaddr *)&serv, sizeof(serv));
    if (ret < 0)
        goto fail;

    return sock;

fail:
    close(sock);

    return -1;
}

int edge_os_create_tcp_server(const char *ip, int port, int n_conns)
{
    struct sockaddr_in serv;
    int ret;
    int sock = edge_os_new_tcp_socket();

    if (sock < 0) {
        edge_os_err("socket: failed to create new tcp socket @ %s %u\n",
                                __func__, __LINE__);
        return -1;
    }

    ret = edge_os_socket_ioctl_reuse_addr(sock);
    if (ret < 0) {
        return -1;
    }

    if (ip)
        serv.sin_addr.s_addr = inet_addr(ip);
    else
        serv.sin_addr.s_addr = INADDR_ANY;

    serv.sin_port = htons(port);
    serv.sin_family = AF_INET;

    ret = bind(sock, (struct sockaddr *)&serv, sizeof(serv));
    if (ret < 0) {
        goto fail;
    }

    ret = listen(sock, n_conns);
    if (ret < 0) {
        goto fail;
    }
    
    return sock;

fail:
    if (sock > 0)
        close(sock);

    return -1;
}

int edge_os_create_tcp_client(const char *ip, int port)
{
    int ret;
    int sock;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        return -1;

    struct sockaddr_in serv;

    serv.sin_addr.s_addr = inet_addr(ip);
    serv.sin_port = htons(port);
    serv.sin_family = AF_INET;

    ret = connect(sock, (struct sockaddr *)&serv, sizeof(serv));
    if (ret < 0)
        goto fail;

    return sock;

fail:
    close(sock);
    return -1;
}

int edge_os_accept_conn(int sock, char *ip, int *port)
{
    struct sockaddr_in serv;
    socklen_t len = sizeof(serv);
    int cli_conn;

    cli_conn = accept(sock, (struct sockaddr *)&serv, &len);
    if (cli_conn < 0) {
        perror("accept");
        return -1;
    }

    if (ip)
        strcpy(ip, inet_ntoa(serv.sin_addr));

    if (port)
        *port = htons(serv.sin_port);

    return cli_conn;
}

int edge_os_create_tcp_unix_server(const char *path, const int n_conns)
{
    int sock;
    int ret;

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0)
        return -1;

    unlink(path);

    struct sockaddr_un serv;

    strcpy(serv.sun_path, path);
    serv.sun_family = AF_UNIX;

    ret = bind(sock, (struct sockaddr *)&serv, sizeof(serv));
    if (ret < 0)
        goto fail;

    ret = listen(sock, n_conns);
    if (ret < 0)
        goto fail;

    return sock;

fail:
    close(sock);

    return -1;
}

int edge_os_create_udp_server(const char *ip, int port)
{
    struct sockaddr_in serv;
    int ret;
    int sock = edge_os_new_udp_socket();

    if (sock < 0) {
        edge_os_err("socket: failed to create new udp socket @ %s %u\n",
                            __func__, __LINE__);
        return -1;
    }

    ret = edge_os_socket_ioctl_reuse_addr(sock);
    if (ret < 0) {
        edge_os_err("socket: failed to bind to device @ %s %u\n",
                            __func__, __LINE__);
        goto fail;
    }

    if (ip)
        serv.sin_addr.s_addr = inet_addr(ip);
    else
        serv.sin_addr.s_addr = INADDR_ANY;

    serv.sin_port = htons(port);
    serv.sin_family = AF_INET;

    ret = bind(sock, (struct sockaddr *)&serv, sizeof(serv));
    if (ret < 0) {
        goto fail;
    }

    return sock;

fail:
    if (sock > 0)
        close(sock);
    return -1;
}


int edge_os_create_udp_mcast_server(char *ip, int port, char *mcast_ip)
{
    int sock;
    int ret;

    sock = edge_os_create_udp_server(NULL, port);
    if (sock < 0) {
        return -1;
    }

    ret = edge_os_socket_ioctl_set_mcast_if(sock, ip);
    if (ret < 0) {
        return -1;
    }

    ret = edge_os_socket_ioctl_set_mcast_add_member(sock, ip, mcast_ip);
    if (ret < 0) {
        return -1;
    }

    return sock;
}

int edge_os_create_udp_mcast_client(char *ip, int port, char *mcast_group, char *ipaddr)
{
    int sock;
    int ret;

    sock = edge_os_create_udp_client();
    if (sock < 0) {
        return -1;
    }

    ret = edge_os_socket_ioctl_set_mcast_if(sock, ipaddr);
    if (ret < 0) {
        return -1;
    }

    return sock;
}

int edge_os_socket_ioctl_set_mcast_if(int fd, char *ipaddr)
{
    struct ip_mreq mcast_if;

    mcast_if.imr_interface.s_addr = inet_addr(ipaddr);

    return setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF,
                      &mcast_if.imr_interface, sizeof(struct in_addr));
}

int edge_os_socket_ioctl_set_mcast_add_member(int fd, char *ipaddr, char *group)
{
    struct ip_mreq mcast_add;
    int ret;

    memset(&mcast_add, 0, sizeof(mcast_add));

    mcast_add.imr_multiaddr.s_addr = inet_addr(group);
    mcast_add.imr_interface.s_addr = htonl(INADDR_ANY);

    ret = setsockopt(fd, IPPROTO_IP,
                      IP_ADD_MEMBERSHIP, &mcast_add,
                      sizeof(mcast_add));
    if (ret < 0) {
        return -1;
    }

    return 0;
}

int edge_os_socket_ioctl_set_nonblock(int fd)
{
    int flags = 0;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return -1;

    flags |= O_NONBLOCK;

    return fcntl(fd, F_SETFL, flags);
}

int edge_os_socket_ioctl_bind_to_device(int fd)
{
    int set = 1;

    return setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &set, sizeof(set));
}

int edge_os_socket_ioctl_reuse_addr(int fd)
{
    int set = 1;

    return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &set, sizeof(set));
}

int edge_os_udp_unix_sendto(int fd, void *msg, int msglen, char *dest)
{
    struct sockaddr_un d;

    strcpy(d.sun_path, dest);
    d.sun_family = AF_UNIX;

    return sendto(fd, msg, msglen, 0, (struct sockaddr *)&d, sizeof(d));
}

int edge_os_tcp_send(int fd, void *msg, int msglen)
{
    return send(fd, msg, msglen, 0);
}

int edge_os_tcp_recv(int fd, void *msg, int msglen)
{
    return recv(fd, msg, msglen, 0);
}

int edge_os_udp_sendto(int fd, void *msg, int msglen, char *dest, int dest_port)
{
    struct sockaddr_in d = {
        .sin_addr.s_addr = inet_addr(dest),
        .sin_port = htons(dest_port),
        .sin_family = AF_INET,
    };
    int ret;

    ret = sendto(fd, msg, msglen, 0, (struct sockaddr *)&d, sizeof(d));
    return ret;
}

int edge_os_udp_recvfrom(int fd, void *msg, int msglen, char *dest, int *dest_port)
{
    struct sockaddr_in r;
    socklen_t r_l = sizeof(struct sockaddr_in);
    int ret;

    ret = recvfrom(fd, msg, msglen, 0, (struct sockaddr *)&r, &r_l);
    if (ret < 0) {
        return -1;
    }

    if (dest) {
        char *str;

        str = inet_ntoa(r.sin_addr);
        if (!str)
            return -1;

        strcpy(dest, str);
    }

    if (dest_port)
        *dest_port = htons(r.sin_port);

    return ret;
}

struct edge_os_client_list {
    int fd;
    char ip[40];
    int port;
};

struct edge_os_managed_server_config {
    struct edge_os_list_base client_list;
    void *evtloop_base;
    uint8_t *buf;
    void *app_ctx;
    edge_os_server_type_t type;
    int bufsize;
    int fd;
    void (*default_acceptor)(int fd, char *ip, int port);
    int (*default_recv)(int fd, void *data, int datalen);
};

int edge_os_client_list_for_each(void *data, void *priv)
{
    struct edge_os_client_list *cl = data;
    struct edge_os_client_list *cl_given = priv;

    if (cl->fd == cl_given->fd) {
        return 1;
    }

    return 0;
}

static int edge_os_client_list_add(struct edge_os_list_base *base, struct edge_os_client_list *cl)
{
    void *elem_id;

    elem_id = edge_os_list_find_elem(base, edge_os_client_list_for_each, cl);
    if (elem_id == 0)
        edge_os_list_add_tail(base, cl);

    return elem_id ? 0: 1;
}

static void __edge_os_default_recv(int sock, void *priv)
{
    struct edge_os_managed_server_config *config = priv;
    int rxsize;

    rxsize = edge_os_tcp_recv(sock, config->buf, config->bufsize);
    if (rxsize <= 0)
        return;

    if (config->default_recv)
        config->default_recv(sock, config->buf, rxsize);
}

static void __edge_os_default_rfrm(int sock, void *priv)
{
    struct edge_os_managed_server_config *config = priv;
    int rxsize;

    rxsize = edge_os_udp_recvfrom(sock, config->buf, config->bufsize, NULL, NULL);
    if (rxsize <= 0)
        return;

    if (config->default_recv)
        config->default_recv(sock, config->buf, rxsize);
}

static void edge_os_default_acceptor(int sock, void *priv)
{
    struct edge_os_managed_server_config *config = priv;
    struct edge_os_client_list *cl;
    int ret;

    cl = calloc(1, sizeof(struct edge_os_client_list));
    if (!cl) {
        return;
    }

    cl->fd = edge_os_accept_conn(config->fd, cl->ip, &cl->port);
    if (cl->fd < 0)
        goto bad;

    if (config->default_acceptor)
        config->default_acceptor(cl->fd, cl->ip, cl->port);

    ret = edge_os_client_list_add(&config->client_list, cl);
    if (ret == 0)
        goto bad;

    if ((config->type == EDGEOS_SERVER_TCP) ||
            (config->type == EDGEOS_SERVER_TCP_UNIX))
        edge_os_evtloop_register_socket(config->evtloop_base, config, cl->fd,
                                        __edge_os_default_recv);
    else
        edge_os_evtloop_register_socket(config->evtloop_base, config, cl->fd,
                                        __edge_os_default_rfrm);

    return;

bad:
    free(cl);
}

void* edge_os_create_server_managed(void *evtloop_base,
                                    void *app_ctx,
                                    edge_os_server_type_t type,
                                    const char *ip,
                                    int port,
                                    int n_conns,
                                    int expect_bufsize,
                                    void (*default_accept)(int fd, char *ip, int port),
                                    int (*default_recv)(int fd, void *data, int datalen))
{
    struct edge_os_managed_server_config *config;
    int fd;

    config = calloc(1, sizeof(struct edge_os_managed_server_config));
    if (!config) {
        return NULL;
    }

    config->buf = calloc(1, expect_bufsize);
    if (!config->buf)
        goto bad;

    config->bufsize = expect_bufsize;

    edge_os_list_init(&config->client_list);

    switch (type) {
        case EDGEOS_SERVER_TCP:
            fd = edge_os_create_tcp_server(ip, port, n_conns);
        break;
        case EDGEOS_SERVER_UDP:
            fd = edge_os_create_udp_server(ip, port);
        break;
        case EDGEOS_SERVER_TCP_UNIX:
            fd = edge_os_create_tcp_unix_server(ip, n_conns);
        break;
        case EDGEOS_SERVER_UDP_UNIX:
            fd = edge_os_create_udp_unix_server(ip);
        break;
        default:
            return NULL;
    }

    config->type = type;
    config->default_acceptor = default_accept;
    config->evtloop_base = evtloop_base;
    config->default_recv = default_recv;

    edge_os_evtloop_register_socket(evtloop_base, config, fd,
                                    edge_os_default_acceptor);

    return config;
bad:
    free(config);
    return NULL;
}


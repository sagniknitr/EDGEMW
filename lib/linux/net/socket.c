#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <unistd.h>
#include <edgeos_netapi.h>
#include <sys/un.h>
#include <fcntl.h>
#include <edgeos_evtloop.h>
#include <stdlib.h>
#include <edgeos_logger.h>

// managed server client configuration data
struct edge_os_client_list {
    int fd;
    char ip[40];
    int port;
};

// managed server configuration data
struct edge_os_managed_server_config {
    struct edge_os_list_base client_list;
    void *evtloop_base;
    uint8_t *buf;
    void *app_ctx;
    edge_os_server_type_t type;
    int bufsize;
    int fd;
    void (*default_acceptor)(int fd, char *ip, int port);
    int (*default_recv)(int fd, void *data, int datalen, char *ip, int port);
};

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

    if (!addr) {
        edge_os_error("net: invalid addr %p @ %s %u\n",
                                    addr, __func__, __LINE__);
        return -1;
    }

    sock = edge_os_new_unix_socket();
    if (sock < 0) {
        edge_os_log_with_error(errno, "net: failed to create unix socket ");
        return -1;
    }

    unlink(addr);
    strcpy(serv.sun_path, addr);
    serv.sun_family = AF_UNIX;

    ret = bind(sock, (struct sockaddr *)&serv, sizeof(serv));
    if (ret < 0) {
        edge_os_log_with_error(errno, "net: failed to bind unix socket ");
        goto err;
    }

    return sock;
err:
    close(sock);

    return -1;
}

int edge_os_create_udp_unix_server(const char *addr)
{
    return edge_os_create_udp_unix_client(addr);
}

int __edge_os_connect_address(const char *addr, const char *service_name, int family)
{
    int fd = -1;
    int ret;
    struct addrinfo hint;
    struct addrinfo *s;

    memset(&hint, 0, sizeof(hint));

    hint.ai_family = family;
    hint.ai_socktype = SOCK_STREAM;

    ret = getaddrinfo(addr, service_name, &hint, &s);
    if (ret != 0) {
        edge_os_log_with_error(errno, "net: failed to getaddrinfo ");
        return -1;
    }

    struct addrinfo *ai;

    for (ai = s; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            edge_os_log_with_error(errno, "net: failed to open socket ");
            return -1;
        }

        ret = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (ret < 0) {
            edge_os_log_with_error(errno, "net: failed to connect ");
            return -1;
        }
        break;
    }

    return fd;
}

int edge_os_connect_address6(const char *addr, const char *service_name)
{
    return __edge_os_connect_address(addr, service_name, AF_INET6);
}

int edge_os_connect_address4(const char *addr, const char *service_name)
{
    return __edge_os_connect_address(addr, service_name, AF_INET);
}

int edge_os_create_tcp_unix_client(const char *path)
{
    int sock;
    int ret;

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        edge_os_log_with_error(errno, "net: failed to socket ");
        return -1;
    }

    struct sockaddr_un serv;

    strcpy(serv.sun_path, path);
    serv.sun_family = AF_UNIX;

    ret = connect(sock, (struct sockaddr *)&serv, sizeof(serv));
    if (ret < 0) {
        edge_os_log_with_error(errno, "net: failed to connect ");
        goto fail;
    }

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
        edge_os_log_with_error(errno, "net: failed to create tcp socket @ %s %u ",
                                    __func__, __LINE__);
        return -1;
    }

    ret = edge_os_socket_ioctl_reuse_addr(sock);
    if (ret < 0) {
        edge_os_log_with_error(errno, "net: failed to set reuse addr @ %s %u ",
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
        edge_os_log_with_error(errno, "net: failed to bind ");
        goto fail;
    }

    ret = listen(sock, n_conns);
    if (ret < 0) {
        edge_os_log_with_error(errno, "net: failed to listen ");
        goto fail;
    }
    
    return sock;

fail:
    close(sock);

    return -1;
}

int edge_os_create_tcp_client(const char *ip, int port)
{
    int ret;
    int sock;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        edge_os_log_with_error(errno, "net: failed to socket ");
        return -1;
    }

    struct sockaddr_in serv;

    serv.sin_addr.s_addr = inet_addr(ip);
    serv.sin_port = htons(port);
    serv.sin_family = AF_INET;

    ret = connect(sock, (struct sockaddr *)&serv, sizeof(serv));
    if (ret < 0) {
        edge_os_log_with_error(errno, "net: failed to connect @ %s %u ",
                                    __func__, __LINE__);
        goto fail;
    }

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
        edge_os_log_with_error(errno, "net: failed to accept connection @ %s %u ",
                                    __func__, __LINE__);
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
    if (sock < 0) {
        edge_os_log_with_error(errno, "net: failed to socket ");
        return -1;
    }

    unlink(path);

    struct sockaddr_un serv;

    strcpy(serv.sun_path, path);
    serv.sun_family = AF_UNIX;

    ret = bind(sock, (struct sockaddr *)&serv, sizeof(serv));
    if (ret < 0) {
        edge_os_log_with_error(errno, "net: failed to bind ");
        goto fail;
    }

    ret = listen(sock, n_conns);
    if (ret < 0) {
        edge_os_log_with_error(errno, "net: failed to listen ");
        goto fail;
    }

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
        edge_os_log_with_error(errno, "socket: failed to create new udp socket @ %s %u ",
                            __func__, __LINE__);
        return -1;
    }

    ret = edge_os_socket_ioctl_reuse_addr(sock);
    if (ret < 0) {
        edge_os_log_with_error(errno, "socket: failed to bind to device @ %s %u ",
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
        edge_os_log_with_error(errno, "socket: failed to bind " );
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

    // error handled in the edge_os_create_udp_server
    sock = edge_os_create_udp_server(NULL, port);
    if (sock < 0) {
        return -1;
    }

    ret = edge_os_socket_ioctl_set_mcast_if(sock, ip);
    if (ret < 0) {
        edge_os_error("net: failed to set mcast if on sock %d ip %s @ %s %u\n",
                                sock, ip, __func__, __LINE__);
        goto bad;
    }

    ret = edge_os_socket_ioctl_set_mcast_add_member(sock, ip, mcast_ip);
    if (ret < 0) {
        edge_os_error("net: failed to set mcast add member on sock %d mcast_ip %s @ %s %u\n",
                                sock, mcast_ip, __func__, __LINE__);
        goto bad;
    }

    return sock;

bad:
    return -1;
}

int edge_os_create_udp_mcast_client(char *ip, int port, char *mcast_group, char *ipaddr)
{
    int sock;
    int ret;

    sock = edge_os_create_udp_client();
    if (sock < 0) {
        edge_os_log_with_error(errno, "net: failed to create udp client @ %s %u ",
                                    __func__, __LINE__);
        return -1;
    }

    ret = edge_os_socket_ioctl_set_mcast_if(sock, ipaddr);
    if (ret < 0) {
        edge_os_log_with_error(errno, "net: failed to set multicast on socket @ %s %u ",
                                    __func__, __LINE__);
        close(sock);
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
        edge_os_log_with_error(errno, "net: failed to setsockopt @ %s %u ",
                                        __func__, __LINE__);
        return -1;
    }

    return 0;
}

int edge_os_socket_ioctl_set_nonblock(int fd)
{
    int flags = 0;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        edge_os_log_with_error(errno, "net: failed to F_GETFL @ %s %u ",
                                        __func__, __LINE__);
        return -1;
    }

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

int edge_os_socket_ioctl_reset_reuse_addr(int fd)
{
    int set = 0;

    return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &set, sizeof(set));
}

int edge_os_socket_ioctl_set_broadcast(int fd)
{
    int set = 1;

    return setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &set, sizeof(set));
}

int edge_os_socket_ioctl_keepalive(int fd)
{
    int set = 1;

    return setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &set, sizeof(set));
}

int edge_os_net_setmaxconn(int conns)
{
#define SOMAX_CONN_FILE "/proc/sys/net/core/somaxconn"
    int fd;
    char buf[10];
    int ret;

    ret = snprintf(buf, sizeof(buf), "%d\n", conns);

    fd = open(SOMAX_CONN_FILE, O_WRONLY);
    if (fd < 0) {
        edge_os_log_with_error(errno, "failed to open %s @ %s %u ",
                                    SOMAX_CONN_FILE, __func__, __LINE__);
        return -1;
    }

    ret = write(fd, buf, ret);
    if (ret < 0) {
        edge_os_log_with_error(errno, "failed to write to %s @ %s %u ",
                                    SOMAX_CONN_FILE, __func__, __LINE__);
        close(fd);
        return -1;
    }

    close(fd);

    return 0;
#undef SOMAX_CONN_FILE
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
    if (ret < 0) {
        edge_os_log_with_error(errno, "failed to sendto @ %s %u ",
                                         __func__, __LINE__);
    }
    return ret;
}

int edge_os_udp_recvfrom(int fd, void *msg, int msglen, char *dest, int *dest_port)
{
    struct sockaddr_in r;
    socklen_t r_l = sizeof(struct sockaddr_in);
    int ret;

    ret = recvfrom(fd, msg, msglen, 0, (struct sockaddr *)&r, &r_l);
    if (ret < 0) {
        edge_os_log_with_error(errno, "failed to recvfrom @ %s %u ",
                                            __func__, __LINE__);
        return -1;
    }

    if (dest) {
        char *str;

        str = inet_ntoa(r.sin_addr);
        if (!str) {
            edge_os_error("net: failed to inet_ntoa @ %s %u\n",
                                        __func__, __LINE__);
            return -1;
        }

        strcpy(dest, str);
    }

    if (dest_port)
        *dest_port = htons(r.sin_port);

    return ret;
}

static int edge_os_client_list_for_each(void *data, void *priv)
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
    if (elem_id == NULL)
        edge_os_list_add_tail(base, cl);

    return elem_id ? 0: 1;
}

static void edge_os_client_list_del(void *ptr)
{
    struct edge_os_client_list *cl = ptr;

    close(cl->fd);
    free(cl);
}

static void edge_os_client_list_remove(struct edge_os_list_base *base, struct edge_os_client_list *cl)
{
    struct edge_os_client_list *cl1;

    cl1 = edge_os_list_find_elem(base, edge_os_client_list_for_each, cl);
    if (cl1)
        edge_os_list_delete(base, cl1, edge_os_client_list_del);
}

static void __edge_os_default_recv(int sock, void *priv)
{
    struct edge_os_managed_server_config *config = priv;
    int rxsize;

    rxsize = edge_os_tcp_recv(sock, config->buf, config->bufsize);
    if (rxsize <= 0) {
        struct edge_os_client_list cl = {
            .fd = sock,
        };

        edge_os_client_list_remove(&config->client_list, &cl);
        edge_os_evtloop_unregister_socket(config->evtloop_base, sock);
        return;
    }

    if (config->default_recv)
        config->default_recv(sock, config->buf, rxsize, NULL, -1);
}

static void __edge_os_default_rfrm(int sock, void *priv)
{
    struct edge_os_managed_server_config *config = priv;
    int rxsize;
    char dest[40];
    int dest_port;

    // error message dump already done at os_udp_recvfrom
    rxsize = edge_os_udp_recvfrom(sock, config->buf, config->bufsize, dest, &dest_port);
    if (rxsize <= 0) {
        edge_os_evtloop_unregister_socket(config->evtloop_base, sock);
        return;
    }

    if (config->default_recv)
        config->default_recv(sock, config->buf, rxsize, dest, dest_port);
}

static void edge_os_default_acceptor(int sock, void *priv)
{
    struct edge_os_managed_server_config *config = priv;
    struct edge_os_client_list *cl;
    int ret;

    cl = calloc(1, sizeof(struct edge_os_client_list));
    if (!cl) {
        edge_os_error("socket: failed to allocate @ %s %u\n",
                                __func__, __LINE__);
        return;
    }

    // error mesg is handled in os_accept_conn
    cl->fd = edge_os_accept_conn(config->fd, cl->ip, &cl->port);
    if (cl->fd < 0)
        goto bad;

    if (config->default_acceptor)
        config->default_acceptor(cl->fd, cl->ip, cl->port);

    ret = edge_os_client_list_add(&config->client_list, cl);
    if (ret == 0) {
        edge_os_error("socket: error, client exists ! @ %s %u\n",
                                __func__, __LINE__);
        goto bad;
    }

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
                                    int (*default_recv)(int fd, void *data, int datalen, char *ip, int port))
{
    struct edge_os_managed_server_config *config;

    config = calloc(1, sizeof(struct edge_os_managed_server_config));
    if (!config) {
        edge_os_error("net: failed to allocate @ %s %u\n", __func__, __LINE__);
        return NULL;
    }

    config->buf = calloc(1, expect_bufsize);
    if (!config->buf) {
        edge_os_error("socket: failed to allocate @ %s %u\n",
                                __func__, __LINE__);
        goto bad;
    }

    config->bufsize = expect_bufsize;

    edge_os_list_init(&config->client_list);

    config->app_ctx = app_ctx;

    switch (type) {
        case EDGEOS_SERVER_TCP:
            config->fd = edge_os_create_tcp_server(ip, port, n_conns);
        break;
        case EDGEOS_SERVER_UDP:
            config->fd = edge_os_create_udp_server(ip, port);
        break;
        case EDGEOS_SERVER_TCP_UNIX:
            config->fd = edge_os_create_tcp_unix_server(ip, n_conns);
        break;
        case EDGEOS_SERVER_UDP_UNIX:
            config->fd = edge_os_create_udp_unix_server(ip);
        break;
        default:
            edge_os_error("socket: invalid type %d @ %s %u\n",
                                type, __func__, __LINE__);
            return NULL;
    }

    config->type = type;
    config->default_acceptor = default_accept;
    config->evtloop_base = evtloop_base;
    config->default_recv = default_recv;

    edge_os_evtloop_register_socket(evtloop_base, config, config->fd,
                                    edge_os_default_acceptor);

    return config;
bad:
    free(config);
    return NULL;
}

struct edge_os_raw_sock_params {
    int fd;
    int ifidnex;
    edge_os_raw_sock_type_t type;
    struct ether_header eh;
    struct ifreq ifr;
    uint8_t srcmac[6];
    uint8_t *txbuf;
    int txbuflen;
};

void* edge_os_raw_socket_create(edge_os_raw_sock_type_t type, const char *ifname, int txbuf_len)
{
    int ret;
    struct edge_os_raw_sock_params *raw_params;

    raw_params = calloc(1, sizeof(struct edge_os_raw_sock_params));
    if (!raw_params) {
        return NULL;
    }

    raw_params->fd = socket(AF_PACKET, SOCK_RAW, ETH_P_ALL);
    if (raw_params->fd < 0) {
        return NULL;
    }

    if (type == EDGEOS_RAW_SOCK_ETH) {
        raw_params->txbuf = calloc(1, txbuf_len + sizeof(struct ether_header));
        if (!raw_params->txbuf) {
            return NULL;
        }

        raw_params->txbuflen = txbuf_len + sizeof(struct ether_header);

        strcpy(raw_params->ifr.ifr_name, ifname);
        ret = ioctl(raw_params->fd, SIOCGIFINDEX, &raw_params->ifr);
        if (ret < 0) {
            return NULL;
        }

        raw_params->ifidnex = raw_params->ifr.ifr_ifindex;

        memset(&raw_params->ifr, 0, sizeof(raw_params->ifr));
        ret = ioctl(raw_params->fd, SIOCGIFHWADDR, &raw_params->ifr);
        if (ret < 0) {
            return NULL;
        }

        memcpy(raw_params->srcmac, (uint8_t *)(raw_params->ifr.ifr_hwaddr.sa_data), 6);
        memcpy(raw_params->eh.ether_shost, raw_params->srcmac, 6);
    } else {
        return NULL;
    }

    return raw_params;
}

int edge_os_raw_socket_send_eth_frame(
                    void *raw_handle,
                    uint8_t *srcmac,
                    uint8_t *dstmac,
                    uint16_t ethertype,
                    uint8_t *data,
                    uint32_t datalen)
{
    struct edge_os_raw_sock_params *raw_params = raw_handle;
    struct sockaddr_ll ll;
    int ret;

    ll.sll_ifindex = raw_params->ifidnex;

    ll.sll_halen = ETH_ALEN;

    ll.sll_addr[0] = dstmac[0];
    ll.sll_addr[1] = dstmac[1];
    ll.sll_addr[2] = dstmac[2];
    ll.sll_addr[3] = dstmac[3];
    ll.sll_addr[4] = dstmac[4];
    ll.sll_addr[5] = dstmac[5];

    memcpy(raw_params->eh.ether_shost, srcmac, 6);
    memcpy(raw_params->eh.ether_dhost, dstmac, 6);
    raw_params->eh.ether_type = ethertype;

    memcpy(raw_params->txbuf, &raw_params->eh, sizeof(raw_params->eh));
    memcpy(raw_params->txbuf + sizeof(raw_params->eh),
                data, datalen);

    ret = sendto(raw_params->fd, raw_params->txbuf,
                 datalen + sizeof(raw_params->eh),
                 0, (struct sockaddr *)&ll, sizeof(ll));
    if (ret < 0) {
        return -1;
    }

    return ret;
}


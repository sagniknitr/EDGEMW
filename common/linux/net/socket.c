#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <net_socket.h>
#include <sys/un.h>
#include <fcntl.h>

static int __socket(int family, int protocol)
{
    return socket(family, protocol, 0);
}

int edge_os_new_tcp_socket()
{
    return __socket(AF_INET, SOCK_STREAM);
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

int edge_os_create_unix_client(char *addr)
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

int edge_os_create_unix_server(char *addr)
{
    return edge_os_create_unix_client(addr);
}

int edge_os_create_tcp_server(char *ip, int port)
{
    return 0;
}

int edge_os_create_udp_server(char *ip, int port)
{
    struct sockaddr_in serv;
    int ret;
    int sock = edge_os_new_udp_socket();

    if (sock < 0) {
        return -1;
    }

    ret = edge_os_socket_ioctl_bind_to_device(sock);
    if (ret < 0) {
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

    sock = edge_os_create_udp_server(ip, port);
    if (sock < 0) {
        return -1;
    }

    ret = edge_os_socket_ioctl_set_mcast_if(sock, mcast_ip);
    if (ret < 0) {
        return -1;
    }

    ret = edge_os_socket_ioctl_set_mcast_add_member(sock, ip, NULL);
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

int edge_os_socket_ioctl_set_mcast_add_member(int fd, char *ipaddr, char *ifname)
{
    struct ip_mreq mcast_add;

    mcast_add.imr_multiaddr.s_addr = inet_addr(ipaddr);
    mcast_add.imr_interface.s_addr = INADDR_ANY;

    return setsockopt(fd, IPPROTO_IP,
                      IP_ADD_MEMBERSHIP, &mcast_add,
                      sizeof(mcast_add));
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

int edge_os_udp_unix_sendto(int fd, void *msg, int msglen, char *dest)
{
    struct sockaddr_un d;

    strcpy(d.sun_path, dest);
    d.sun_family = AF_UNIX;

    return sendto(fd, msg, msglen, 0, (struct sockaddr *)&d, sizeof(d));
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

int edge_os_udp_recvfrom(int fd, void *msg, int msglen, char *dest, int *dest_len)
{
    return recvfrom(fd, msg, msglen, 0, NULL, NULL);
}


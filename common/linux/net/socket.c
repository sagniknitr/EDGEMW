#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <net_socket.h>
#include <sys/un.h>

int create_tcp_server(char *ip, int port)
{
    return 0;
}

int create_udp_server(char *ip, int port)
{
    return 0;
}

int __socket(int family, int protocol)
{
    return socket(family, protocol, 0);
}

int new_tcp_socket()
{
    return __socket(AF_INET, SOCK_STREAM);
}

int new_udp_socket()
{
    return __socket(AF_INET, SOCK_DGRAM);
}

int new_unix_socket()
{
    return __socket(AF_UNIX, SOCK_DGRAM);
}

void del_udp_socket(int sock)
{
    close(sock);
}

int create_udp_client()
{
    return new_udp_socket();
}

int create_unix_client(char *addr)
{
    struct sockaddr_un serv;
    int sock;
    int ret;

    sock = new_unix_socket();
    if (sock < 0) {
        return -1;
    }

    unlink(addr);
    strcpy(serv.sun_path, addr);
    serv.sun_family = AF_UNIX;

    ret = bind(sock, (struct sockaddr *)&serv, sizeof(serv));
    if (ret < 0) {
        return -1;
    }

    return sock;
}

int create_unix_server(char *addr)
{
    return create_unix_client(addr);
}

int udp_unix_sendto(int fd, void *msg, int msglen, char *dest)
{
    struct sockaddr_un d;

    strcpy(d.sun_path, dest);
    d.sun_family = AF_UNIX;

    return sendto(fd, msg, msglen, 0, (struct sockaddr *)&d, sizeof(d));
}

int udp_sendto(int fd, void *msg, int msglen, char *dest, int dest_port)
{
    struct sockaddr_in d = {
        .sin_addr.s_addr = inet_addr(dest),
        .sin_port = htons(dest_port),
        .sin_family = AF_INET,
    };

    return sendto(fd, msg, msglen, 0, (struct sockaddr *)&d, sizeof(d));
}

int udp_recvfrom(int fd, void *msg, int msglen, char *dest, int *dest_len)
{
    return recvfrom(fd, msg, msglen, 0, NULL, NULL);
}


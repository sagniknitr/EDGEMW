#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <net_socket.h>

int create_tcp_server(char *ip, int port)
{
    return 0;
}

int create_udp_server(char *ip, int port)
{
    return 0;
}

int new_udp_socket()
{
    int sock;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return -1;
    }

    return sock;
}


void del_udp_socket(int sock)
{
    close(sock);
}

int create_udp_client()
{
    return new_udp_socket();
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


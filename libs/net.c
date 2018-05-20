#include "net_i.h"
#include <iostream>

int netSocket::initTcpServer(char *dest, int dest_port, int n_conn,
                             void (*accept_callback)(int sock))
{
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }

    int ret;
    int opt = 1;

    ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (ret < 0) {
        goto err;
    }

    serv_in.sin_addr.s_addr = inet_addr(dest);
    serv_in.sin_port = htons(dest_port);
    serv_in.sin_family = AF_INET;

    ret = bind(sock, (struct sockaddr *)&serv_in, sizeof(serv_in));
    if (ret < 0) {
        goto err;
    }

    n_conns = n_conn;

    ret = listen(sock, n_conn);
    if (ret < 0) {
        goto err;
    }

    accept_cb = accept_callback;

    return sock;

err:
    if (sock > 0) {
        close(sock);
    }
    return -1;
}

int netSocket::initTcpClient(char *dest, int dest_port)
{
    int ret;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }

    serv_in.sin_addr.s_addr = inet_addr(dest);
    serv_in.sin_port = htons(dest_port);
    serv_in.sin_family = AF_INET;

    ret = connect(sock, (struct sockaddr *)&serv_in, sizeof(serv_in));
    if (ret < 0) {
        goto err;
    }

    return sock;

err:
    if (sock > 0) {
        close(sock);
    }
    return -1;
}

int netSocket::initUdpServer(char *dest, int dest_port)
{
    int opt = 1;
    int ret;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return -1;
    }

    ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (ret < 0) {
        goto err;
    }

    serv_in.sin_addr.s_addr = inet_addr(dest);
    serv_in.sin_port = htons(dest_port);
    serv_in.sin_family = AF_INET;

    ret = bind(sock, (struct sockaddr *)&serv_in, sizeof(serv_in));
    if (ret < 0) {
        goto err;
    }

    return sock;

err:
    if (sock > 0) {
        close(sock);
    }
    return -1;
}

int netSocket::initUdpClient(char *dest, int dest_port)
{
    int ret;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return -1;
    }

    serv_in.sin_addr.s_addr = inet_addr(dest);
    serv_in.sin_port = htons(dest_port);
    serv_in.sin_family = AF_INET;

    ret = connect(sock, (struct sockaddr *)&serv_in, sizeof(serv_in));
    if (ret < 0) {
        goto err;
    }

    return 0;

err:
    if (sock > 0) {
        close(sock);
    }
    return -1;
}

int netSocket::initTcpServerUnix(char *dest, int n_conn,
                                 void (*accept_callback)(int sock))
{
    int ret;

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }

    unlink(dest);
    strcpy(serv_un.sun_path, dest);
    serv_un.sun_family = AF_UNIX;

    ret = bind(sock, (struct sockaddr *)&serv_un, sizeof(serv_un));
    if (ret < 0) {
        goto err;
    }

    ret = listen(sock, n_conn);
    if (ret < 0) {
        goto err;
    }

    accept_cb = accept_callback;

    return 0;

err:
    if (sock > 0) {
        close(sock);
    }
    return -1;
}

int netSocket::initTcpClientUnix(char *dest)
{
    int ret;

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }

    strcpy(serv_un.sun_path, dest);
    serv_un.sun_family = AF_UNIX;

    ret = connect(sock, (struct sockaddr *)&serv_un, sizeof(serv_un));
    if (ret < 0) {
        goto err;
    }

    return 0;

err:
    if (sock > 0) {
        close(sock);
    }
    return -1;
}

int netSocket::initUdpServerUnix(char *dest)
{
    int ret;

    sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sock < 0) {
        return -1;
    }

    unlink(dest);
    strcpy(serv_un.sun_path, dest);
    serv_un.sun_family = AF_UNIX;

    ret = bind(sock, (struct sockaddr *)&serv_un, sizeof(serv_un));
    if (ret < 0) {
        goto err;
    }

    return 0;

err:
    if (sock > 0) {
        close(sock);
    }
    return -1;
}

int netSocket::initUdpClientUnix(char *serv_dest, char *dest)
{
    sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sock < 0) {
        return -1;
    }

    strcpy(serv_un.sun_path, serv_dest);
    serv_un.sun_family = AF_UNIX;

    unlink(dest);
    strcpy(cli_un.sun_path, dest);
    cli_un.sun_family = AF_UNIX;

    return 0;
}

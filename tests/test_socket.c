#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <net_socket.h>

static int sock = -1;
static int tcp = 0;
static int udp = 0;
static int unix_conn = 0;
static int server = 0;
static int client = 0;
static char *ip = NULL;
static int port = 0;
static int conn = 0;
static int exec_mode = 0;

int executor()
{
    if (sock < 0) {
        return -1;
    }

    fprintf(stderr, "socket %d created\n", sock);

    while (exec_mode) {
        char hello[ ] = "testing message..\n";

        if (tcp) {
            if (unix_conn) {
            } else {
                edge_os_tcp_send(sock, hello, strlen(hello));

                printf("send msg ..\n");
            }
        }
        sleep(1);
    }

    return 0;
}

int main(int argc, char **argv)
{
    int ret;

    while ((ret = getopt(argc, argv, "i:p:tuUcsC:e")) != -1) {
        switch (ret) {
            case 'i':
                ip = optarg;
            break;
            case 'p':
                port = atoi(optarg);
            break;
            case 't':
                tcp = 1;
            break;
            case 'u':
                udp = 1;
            break;
            case 'U':
                unix_conn = 1;
            break;
            case 'c':
                client = 1;
            break;
            case 's':
                server = 1;
            break;
            case 'e':
                exec_mode = 1;
            break;
            case 'C':
                conn = atoi(optarg);
            break;
        }
    }

    if (server) {
        if (tcp) {
            if (unix_conn) {
                sock = edge_os_create_tcp_unix_server(ip, conn);
            } else {
                sock = edge_os_create_tcp_server(ip, port, conn);
            }

            executor();

            edge_os_del_tcp_socket(sock);
        }
        if (udp) {
            if (unix_conn) {
                sock = edge_os_create_udp_unix_server(ip);
            } else {
                sock = edge_os_create_udp_server(ip, port);
            }

            executor();

            edge_os_del_udp_socket(sock);
        }
    }

    if (client) {
        if (tcp) {
            if (unix_conn) {
                sock = edge_os_create_tcp_unix_client(ip);
            } else {
                sock = edge_os_create_tcp_client(ip, port);
            }

            executor();

            edge_os_del_tcp_socket(sock);
        }
        if (udp) {
            if (unix_conn) {
                sock = edge_os_create_udp_unix_client(ip);
            } else {
                sock = edge_os_create_udp_client();
            }

            executor();

            edge_os_del_udp_socket(sock);
        }
    }

    return 0;
}


#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <net_socket.h>

int main(int argc, char **argv)
{
    int sock = -1;
    int tcp = 0;
    int udp = 0;
    int unix_conn = 0;
    int server = 0;
    int client = 0;
    char *ip = NULL;
    int port = 0;
    int conn = 0;
    int ret;

    while ((ret = getopt(argc, argv, "i:p:tuUcsC:")) != -1) {
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
        }
        if (udp) {
            if (unix_conn) {
                sock = edge_os_create_udp_unix_server(ip);
            } else {
                sock = edge_os_create_udp_server(ip, port);
            }
        }
    }

    if (client) {
        if (tcp) {
            if (unix_conn) {
                sock = edge_os_create_tcp_unix_client(ip);
            } else {
                sock = edge_os_create_tcp_client(ip, port);
            }
        }
        if (udp) {
            if (unix_conn) {
                sock = edge_os_create_udp_unix_client(ip);
            } else {
                sock = edge_os_create_udp_client();
            }
        }
    }

    if (sock < 0) {
        return -1;
    }

    fprintf(stderr, "socket %d created\n", sock);

    while (1) {
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


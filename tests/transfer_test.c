#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <getopt.h>
#include <edgeos_sched.h>
#include <evtloop.h>
#include <net_socket.h>


static struct timeval start_serv;
static struct timeval stop_serv;
static struct timeval delta_serv;

void accept_cb(int fd, char *ip1, int port1)
{
    printf("conn [%d] from ip %s port %d\n", fd, ip1, port1);
}

int rx_cb(int fd, void *data, int datalen)
{
    static uint64_t bytelen = 0;
    static uint64_t transfer_count = 0;

    if (datalen <= 0) {
        return -1;
    }

    if (start_serv.tv_sec == 0) {
        gettimeofday(&start_serv, 0);
    }

    gettimeofday(&stop_serv, 0);

    bytelen += datalen;
    transfer_count ++;

    timersub(&stop_serv, &start_serv, &delta_serv);

    if (delta_serv.tv_sec >= 10) {
        fprintf(stderr, "bytes %f Gb/s transfer count %ju\n", (bytelen * 8) / (1024.0 * 1024.0 * 1024.0 * 10), transfer_count);
        memset(&start_serv, 0, sizeof(start_serv));
        memset(&stop_serv, 0, sizeof(stop_serv));
        bytelen = 0;
        transfer_count = 0;
    }

    return datalen;
}

int main(int argc, char **argv)
{
    int server = 0;
    int client = 0;
    int ret;

    while ((ret = getopt(argc, argv, "sc")) != -1) {
        switch (ret) {
            case 's':
                server = 1;
            break;
            case 'c':
                client = 1;
            break;
            default:
                return -1;
        }
    }

    struct edge_os_evtloop_base base;


    edge_os_evtloop_init(&base, NULL);

    if (server) {
        edge_os_set_process_cpu(0);
        edge_os_create_server_managed(&base,
                                      NULL,
                                      EDGEOS_SERVER_TCP,
                                      "127.0.0.1",
                                      2222,
                                      11,
                                      65535 * 2,
                                      accept_cb,
                                      rx_cb);

        edge_os_evtloop_run(&base);

    } else if (client) {
        int sock;

        edge_os_set_process_cpu(7);
        sock = edge_os_create_tcp_client("127.0.0.1", 2222);
        if (sock < 0) {
            return -1;
        }

        char buf[65535 * 2];

        while (1) {
            edge_os_tcp_send(sock, buf, sizeof(buf));
        }

        edge_os_del_tcp_socket(sock);
    }

    return 0;
}


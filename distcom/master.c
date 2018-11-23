#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <evtloop.h>
#include <net_socket.h>
#include <dist_sdp.h>
#include <list.h>

struct dist_master_database {
    char name[20];
    char ip[20];
    int port;
};

struct dist_master_node {
    int sock;
    struct edge_os_evtloop_base base;
    struct edge_os_list_base db;
};

static void dist_master_rxmsg(void *callback_ptr)
{
    struct dist_master_node *priv = callback_ptr;
    uint8_t msg[4096];
    char ip[20];
    int port;
    int off = 0;
    int ret;

    ret = edge_os_udp_recvfrom(priv->sock, msg, sizeof(msg), ip, &port);
    if (ret < 0) {
        return;
    }

    if (msg[0] == 0x01) {
        int name_len = 0;
        int ip_len = 0;

        struct dist_master_database *db;

        db = calloc(1, sizeof(struct dist_master_database));
        if (!db) {
            return;
        }

        off ++;
        name_len = msg[off];

        memcpy(db->name, msg + off, name_len);
        off += name_len;

        off ++;
        ip_len = msg[off];

        memcpy(db->ip, msg + off, ip_len);
        off += ip_len;

        memcpy(&db->port, msg + off, sizeof(db->port));
        off += sizeof(db->port);

        edge_os_list_add_tail(&priv->db, db);
    }
}

int main(int argc, char **argv)
{
    struct dist_master_node *priv;
    int ret;

    priv = calloc(1, sizeof(struct dist_master_node));
    if (!priv) {
        return -1;
    }

    priv->sock = edge_os_create_udp_server("127.0.0.1", 12132);
    if (priv->sock < 0) {
        return -1;
    }

    ret = edge_os_evtloop_init(&priv->base, NULL);
    if (ret) {
        printf("%s %u\n", __func__, __LINE__);
        return -1;
    }

    edge_os_list_init(&priv->db);

    edge_os_evtloop_register_socket(&priv->base, priv, priv->sock, dist_master_rxmsg);

    edge_os_evtloop_run(&priv->base);

    return 0;
}

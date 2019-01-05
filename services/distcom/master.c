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
#include <edgeos_netapi.h>
#include <dist_sdp.h>
#include <edgeos_list.h>
#include <edgeos_logger.h>

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

struct dist_query_msg {
    char name[20];
    char ip[20];
    int port;
    void *priv;
};

void find_query_name(void *priv_data, void *ctx)
{
    struct dist_master_database *db = priv_data;
    struct dist_query_msg *query = ctx;
    struct dist_master_node *priv = query->priv;

    if (!strcmp(query->name, db->name)) {
        struct dist_sdp_query_name_resp resp;

        strcpy(resp.name, db->name);
        strcpy(resp.ipaddr, db->ip);
        resp.port = db->port;

        dist_sdp_prepmsg_query_response(priv->sock, &resp, query->ip, query->port);
    }

    free(query);
}

static void dist_master_rxmsg(int sock, void *callback_ptr)
{
    struct dist_master_node *priv = callback_ptr;
    uint8_t msg[4096];
    char ip[20];
    int port;
    int off = 0;
    int ret;

    ret = edge_os_udp_recvfrom(priv->sock, msg, sizeof(msg), ip, &port);
    if (ret < 0) {
        edge_os_error("master: failed to udp recv from @ %s %u\n", __func__, __LINE__);
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

        off ++;

        memcpy(db->name, msg + off, name_len);
        off += name_len;

        ip_len = msg[off];

        off ++;

        memcpy(db->ip, msg + off, ip_len);
        off += ip_len;

        memcpy(&db->port, msg + off, sizeof(db->port));
        off += sizeof(db->port);

        db->port = htons(db->port);

        edge_os_list_add_tail(&priv->db, db);

        struct dist_sdp_register_resp resp;

        memcpy(resp.name, db->name, name_len);
        resp.resp = DIST_SDP_REG_NAME_RES_OK;

        dist_sdp_prepmsg_regname_resp(priv->sock, &resp, ip, port);
    } else if (msg[0] == 0x03) {
        int name_len = 0;
        char name[20];

        off ++;

        name_len = msg[off];
        off ++;

        memcpy(name, &msg[off], name_len);
        off += name_len;

        struct dist_query_msg *query;

        query = calloc(1, sizeof(struct dist_query_msg));
        if (!query) {
            return;
        }

        strcpy(query->name, name);
        query->priv = priv;
        strcpy(query->ip, ip);
        query->port = port;

        edge_os_list_for_each(&priv->db, find_query_name, query);
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
        return -1;
    }

    edge_os_list_init(&priv->db);

    edge_os_evtloop_register_socket(&priv->base, priv, priv->sock, dist_master_rxmsg);

    edge_os_evtloop_run(&priv->base);

    return 0;
}

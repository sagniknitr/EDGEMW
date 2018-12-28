#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <net_socket.h>
#include <evtloop.h>
#include <list.h>
#include <prng.h>
#include <dist_sdp.h>
#include <edgeos_logger.h>

struct distcomm_priv {
    int prng;
    char *master_addr;
    int master_port;
    struct edge_os_evtloop_base base;
};

void* distcomm_init(char *master_addr, int master_port)
{
    struct distcomm_priv *priv;
    int ret;

    priv = calloc(1, sizeof(struct distcomm_priv));
    if (!priv) {
        edge_os_error("distcomm: failed to allocate @ %s %u\n",
                                    __func__, __LINE__);
        return NULL;
    }

    ret = edge_os_evtloop_init(&priv->base, priv);
    if (ret) {
        edge_os_error("distcomm: failed to event loop init @ %s %u\n",
                                    __func__, __LINE__);
        goto fail;
    }

    priv->prng = edge_os_prng_init(NULL);
    if (ret) {
        edge_os_error("distcomm: failed to prng init @ %s %u\n",
                                    __func__, __LINE__);
        goto fail;
    }

    priv->master_addr = strdup(master_addr);
    priv->master_port = master_port;

        printf("maste rport %d\n", priv->master_port);
    return priv;

fail:
    if (priv)
        free(priv);

    return NULL;
}

struct distcomm_pub_node {
    char *pubname;
    char *ip;
    int port;
    int sock;
};

void* distcom_create_pub(void *ctx, char *pubname)
{
    struct distcomm_priv *priv = ctx;
    struct distcomm_pub_node *pub_node;
    int port = 0;
    int sock;
    int ret;

    pub_node = calloc(1, sizeof(struct distcomm_pub_node));
    if (!pub_node) {
        edge_os_error("distcomm: failed to allocate @ %s %u\n",
                                __func__, __LINE__);
        return NULL;
    }

    if (edge_os_prng_get_bytes(priv->prng, (uint8_t *)&port, 2)) {
        edge_os_error("distcomm: failed to get prng bytes @ %s %u\n",
                                __func__, __LINE__);
        return NULL;
    }

    port = 2000 + (port % 65535);

    sock = edge_os_create_udp_mcast_client(NULL, port, "224.0.0.1", "192.168.1.1");
    if (sock < 0) {
        edge_os_error("distcomm: failed to create udp multi_cast client @ %s %u\n",
                                __func__, __LINE__);
        return NULL;
    }

    pub_node->pubname = strdup(pubname);
    pub_node->ip = strdup("224.0.0.1");
    pub_node->port = port;
    pub_node->sock = sock;

    struct dist_sdp_register_name reg;

    strcpy(reg.name, pubname);
    strcpy(reg.ipaddr, "224.0.0.1");
    reg.port = port;

    ret = dist_sdp_msg_reg_name(sock, &reg, priv->master_addr, priv->master_port);
    if (ret < 0) {
        edge_os_error("distcomm: failed to register sdp name @ %s %u\n",
                                __func__, __LINE__);
        return NULL;
    }

    struct dist_sdp_register_resp resp;

    ret = dist_sdp_msg_reg_name_resp(sock, &resp);
    if (ret < 0) {
        edge_os_error("distcomm: failed to receive register sdp response @ %s %u\n",
                                __func__, __LINE__);
        return NULL;
    }

    if (resp.resp != DIST_SDP_REG_NAME_RES_OK) {
        edge_os_error("distcomm: resp.resp %d is not ok @ %s %u\n",
                        resp.resp, __func__, __LINE__);
        return NULL;
    }

    return pub_node;
}

int distcomm_publish(void *ctx, void *msg, int msglen)
{
    struct distcomm_pub_node *pub_node = ctx;

    return edge_os_udp_sendto(pub_node->sock, msg, msglen,
                              pub_node->ip, pub_node->port);
}

struct distcomm_sub_node {
    char *pathname;
    char *ip;
    int port;
    int sock;
    void *priv_ptr;
    uint8_t *data_ptr;
    int dataptr_len;
    void (*sub_callback)(void *priv_ptr, void *data, int datalen);
};

void sub_generic_func(int sock, void *callback_ptr)
{
    struct distcomm_sub_node *sub = callback_ptr;
    char ip[20];
    int port;
    int ret;

    ret = edge_os_udp_recvfrom(sub->sock, sub->data_ptr, sub->dataptr_len, ip, &port);
    if (ret < 0) {
        return;
    }

    sub->sub_callback(sub->priv_ptr, sub->data_ptr, ret);
}

void* distcom_create_sub(void *ctx, char *subname, void (sub_callback)(void *priv_ptr, void *data, int data_len))
{
    struct distcomm_priv *priv = ctx;
    struct distcomm_sub_node *sub_node;
    int port = 0;
    int sock;
    int ret;

    sub_node = calloc(1, sizeof(struct distcomm_sub_node));
    if (!sub_node) {
        edge_os_error("dist: failed to allocate sub_node @ %s %u\n",
                                __func__, __LINE__);
        return NULL;
    }

    if (edge_os_prng_get_bytes(priv->prng, (uint8_t *)&port, sizeof(port))) {
        return NULL;
    }

    port = 2000 + (port % 6535);

    sock = edge_os_create_udp_client();
    if (sock < 0) {
        return NULL;
    }

    sub_node->pathname = strdup(subname);
    sub_node->ip = strdup("224.0.0.1");
    sub_node->port = 0;
    sub_node->sock = sock;

    struct dist_sdp_query_name query;

    strcpy(query.name, subname);

    ret = dist_sdp_query_name(sock, &query, priv->master_addr, priv->master_port);
    if (ret < 0) {
        return NULL;
    }

    struct dist_sdp_query_name_resp resp;

    ret = dist_sdp_query_name_resp(sock, &resp);
    if (ret < 0) {
        return NULL;
    }

    edge_os_del_udp_socket(sock);

    sock = edge_os_create_udp_mcast_server("192.168.1.1", resp.port, resp.ipaddr);
    if (sock < 0) {
        return NULL;
    }

    sub_node->data_ptr = calloc(1, 65535);
    if (!sub_node->data_ptr) {
        return NULL;
    }

    sub_node->sub_callback = sub_callback;
    sub_node->dataptr_len = 65535;

    edge_os_evtloop_register_socket(&priv->base, sub_node, sock, sub_generic_func);

    return sub_node;
}

void distcomm_run(void *ctx)
{
    struct distcomm_priv *priv = ctx;

    edge_os_evtloop_run(&priv->base);
}

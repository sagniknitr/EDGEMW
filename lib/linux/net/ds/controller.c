#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include <list.h>
#include <evtloop.h>
#include <net_socket.h>
#include <dist_sdp.pb-c.h>

struct ds_dns_list {
    int fd;
    char topic_name[40];
    char ip[40];
    int port;
    int available;
};

struct ds_controller_priv {
    int fd;
    char *ip;
    int port;
    struct ds_dns_list *dns_list;
    struct edge_os_evtloop_base base;
};

static struct ds_dns_list *ds_dns_find_item(struct ds_controller_priv *priv, char *topic_name)
{
    int i;

    for (i = 0; i < 10; i ++) {
        if (!strcmp(priv->dns_list[i].topic_name, topic_name)) {
            return &(priv->dns_list[i]);
        }
    }

    return NULL;
}

#if 0
static struct ds_dns_list *ds_dns_find_free(struct ds_controller_priv *priv)
{
    int i;

    for (i = 0; i < 10; i ++) {
        if (priv->dns_list[i].available) {
            return &(priv->dns_list[i]);
        }
    }

    return NULL;
}
#endif

#if 0
static void ds_dns_add_item(struct ds_controller_priv *priv, char *topic_name, char *ip, int port)
{
    struct ds_dns_list *new;

    new = ds_dns_find_free(priv);
    if (!new) {
        return;
    }

    strcpy(new->topic_name, topic_name);
    strcpy(new->ip, ip);
    new->port = port;
    new->available = 0;
}
#endif

void _ds_controller_send_dresp(int fd, struct ds_controller_priv *priv, struct ds_dns_list *resp)
{
    DcControllerMsgs msg = DC_CONTROLLER_MSGS__INIT;
    uint8_t sendbuf[1024];
    int enc_size;

    msg.mi = DC_CONTROLLER_MSGS__MESSAGE_INFO__discovery_resp;

    msg.dresp = calloc(1, sizeof(DcDiscoveryResp));
    if (!msg.dresp) {
        return;
    }

    dc_discovery_resp__init(msg.dresp);

    msg.dresp->is_topic_available = 0;
    if (resp) {
        msg.dresp->is_topic_available = 1;
        msg.dresp->topic_name = strdup(resp->topic_name);
        msg.dresp->ipaddr = strdup(resp->ip);
        msg.dresp->port = resp->port;
    }

    enc_size = dc_controller_msgs__get_packed_size(&msg);

    dc_controller_msgs__pack(&msg, sendbuf);

    edge_os_tcp_send(fd, sendbuf, enc_size);
}

void _ds_controller_read_conn(int fd, void *data)
{
    struct ds_controller_priv *priv = data;
    uint8_t datarx[4096];
    int datalen;

    datalen = edge_os_tcp_recv(fd, datarx, sizeof(datarx));
    if (datalen <= 0) {
        edge_os_evtloop_unregister_socket(&priv->base, fd);
        return;
    }

    DcControllerMsgs *msg;

    msg = dc_controller_msgs__unpack(NULL, datalen, datarx);
    if (!msg) {
        return;
    }

    switch (msg->mi) {
        case DC_CONTROLLER_MSGS__MESSAGE_INFO__create_topic_req:
        break;
        case DC_CONTROLLER_MSGS__MESSAGE_INFO__discovery_req: {
            printf("topic name %s\n", msg->dreq->topic_name);

            struct ds_dns_list *item = ds_dns_find_item(priv, msg->dreq->topic_name);

            _ds_controller_send_dresp(fd, priv, item);
        } break;
        case DC_CONTROLLER_MSGS__MESSAGE_INFO__create_topic_resp:
        case DC_CONTROLLER_MSGS__MESSAGE_INFO__discovery_resp:
        case DC_CONTROLLER_MSGS__MESSAGE_INFO__notifications:
        default:
        break;
    }
}

void _ds_controller_accept_conn(int fd, void *data)
{
    struct ds_controller_priv *priv = data;
    struct ds_dns_list *new;

    printf("connection\n");
    new = calloc(1, sizeof(struct ds_dns_list));
    if (!new) {
        return;
    }

    new->fd = edge_os_accept_conn(fd, NULL, NULL);
    if (new->fd < 0) {
        return;
    }

    edge_os_evtloop_register_socket(&priv->base, priv, new->fd,
                                    _ds_controller_read_conn);
}

int main(int argc, char **argv)
{
    struct ds_controller_priv *priv;
    int ret;

    priv = calloc(1, sizeof(struct ds_controller_priv));
    if (!priv) {
        return -1;
    }

    while ((ret = getopt(argc, argv, "i:p:")) != -1) {
        switch (ret) {
            case 'i':
                priv->ip = optarg;
            break;
            case 'p':
                priv->port = atoi(optarg);
            break;
        }
    }

    priv->dns_list = calloc(10, sizeof(struct ds_dns_list));
    if (!priv->dns_list) {
        goto bad;
    }

    int i;

    for (i = 0; i < 10; i ++) {
        priv->dns_list[i].available = 1;
    }

    edge_os_evtloop_init(&priv->base, NULL);

    priv->fd = edge_os_create_tcp_server(priv->ip, priv->port, 10);
    if (priv->fd < 0) {
        goto bad;
    }

    edge_os_evtloop_register_socket(&priv->base, priv, priv->fd,
                                    _ds_controller_accept_conn);

    edge_os_evtloop_run(&priv->base);

bad:
    edge_os_del_tcp_socket(priv->fd);

    return -1;
}


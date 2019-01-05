#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include <edgeos_list.h>
#include <evtloop.h>
#include <edgeos_netapi.h>
#include <dist_sdp.pb-c.h>
#include <sysioctl.h>

char *ip;
int port;

typedef enum {
    STATE_DREQ_SENT = 1,
    STATE_DRESP_RECV_AVAIL = 2,
    STATE_DRESP_RECV_NOT_AVAIL = 3,
    STATE_CTOPIC_REG_SENT = 4,
    STATE_CTOPIC_RESP_RECV = 5,
} sm_t;

struct edge_os_evtloop_base base;

struct ds_client_priv {
    int fd;
    char ip[40];
    int port;
    struct edge_os_evtloop_base *base;
    sm_t  sm;
};


void _ds_subscriber_recv_msg(int fd, struct ds_client_priv *priv)
{
    uint8_t rxbuf[1024];
    int ret;

    ret = edge_os_tcp_recv(fd, rxbuf, sizeof(rxbuf));
    if (ret <= 0) {
        edge_os_evtloop_unregister_socket(&priv->base, fd);
        return;
    }

    DcControllerMsgs *msg;

    msg = dc_controller_msgs__unpack(NULL, ret, rxbuf);

    if (msg->mi == DC_CONTROLLER_MSGS__MESSAGE_INFO__discovery_resp) {
        if (priv->sm == STATE_DREQ_SENT) {
            printf("response is_topic_avail %d topicname %s ip %s port %d\n",
                                msg->dresp->is_topic_available, msg->dresp->topic_name, msg->dresp->ipaddr, msg->dresp->port);
            if (msg->dresp->is_topic_available) {
                strcpy(priv->ip, msg->dresp->ipaddr);
                priv->port = msg->dresp->port;
                priv->sm = STATE_DRESP_RECV_AVAIL;
            } else {
                priv->sm = STATE_DRESP_RECV_NOT_AVAIL;
            }
        }
    }
}


sm_t _ds_subscriber_send_msg(struct ds_client_priv *priv, const char *topic)
{
    DcControllerMsgs msg = DC_CONTROLLER_MSGS__INIT;
    uint8_t sendtx[1024];
    int enc_size;

    msg.mi = DC_CONTROLLER_MSGS__MESSAGE_INFO__discovery_req;

    if (priv->sm == 0) {
        msg.dreq = calloc(1, sizeof(DcDiscoveryReq));
        if (!msg.dreq) {
            return priv->sm;
        }

        dc_discovery_req__init(msg.dreq);
        msg.dreq->topic_name = strdup(topic);

        enc_size = dc_controller_msgs__get_packed_size(&msg);

        dc_controller_msgs__pack(&msg, sendtx);

        edge_os_tcp_send(priv->fd, sendtx, enc_size);

        priv->sm = STATE_DREQ_SENT;
    }

    return priv->sm;
}

struct ds_subscriber_context {
    int fd;
    char ip[40];
    int port;
    void *priv;
    void *usr_priv;
    void (*subscriver_c)(int sock, void *data, int datalen, void *priv);
};

void _ds_subscriber_data_callback(int fd, void *data)
{
    struct ds_subscriber_context *sc = data;
    struct ds_client_priv *priv = sc->priv;
    uint8_t buf[2048];
    int ret;

    ret = edge_os_tcp_recv(fd, buf, sizeof(buf));
    if (ret <= 0) {
        edge_os_evtloop_unregister_socket(&priv->base, fd);
        return;
    }

    sc->subscriver_c(fd, buf, ret, sc->usr_priv);
}

static int ds_subscriber_setup_conn(struct ds_subscriber_context *sc, struct ds_client_priv *priv)
{
    char localip[40];
    int ret;

    ret = edgeos_get_net_ipaddr("wlp68s0", localip, sizeof(localip));
    if (ret < 0) {
        goto bad;
    }

    sc->fd = edge_os_create_udp_mcast_server(localip, priv->port, priv->ip);
    if (sc->fd < 0) {
        goto bad;
    }

    edge_os_evtloop_register_socket(&priv->base, sc, sc->fd,
                                    _ds_subscriber_data_callback);

    return 0;

bad:
    return -1;
}

static void _ds_subscriber_notify_callback(int fd, void *data)
{
    struct ds_subscriber_context *sc = data;
    struct ds_client_priv *priv = sc->usr_priv;

    _ds_subscriber_recv_msg(priv->fd, priv);

    if (priv->sm == STATE_DRESP_RECV_AVAIL) {
        ds_subscriber_setup_conn(sc, priv);
    }
}

int dc_subscriber_create(void *evtloop_base, const char *topic, void *usr_priv, void (*subscriber_c)(int sock, void *data, int datalen, void *priv))
{
    struct ds_client_priv *priv;
    int ret;

    priv = calloc(1, sizeof(struct ds_client_priv));
    if (!priv) {
        return -1;
    }

    priv->base = evtloop_base;

    priv->fd = edge_os_create_tcp_client(ip, port);
    if (priv->fd < 0) {
        goto bad;
    }

    if (priv->sm == 0) {
        _ds_subscriber_send_msg(priv, topic);
    }

    if (priv->sm == STATE_DREQ_SENT) {
        printf("read subscriber msg\n");
        _ds_subscriber_recv_msg(priv->fd, priv);
    }

    struct ds_subscriber_context *sc;

    sc = calloc(1, sizeof(struct ds_subscriber_context));
    if (!sc) {
        goto bad;
    }

    if (priv->sm == STATE_DRESP_RECV_AVAIL) {
        ret = ds_subscriber_setup_conn(sc, priv);
        if (ret < 0)
            goto bad;
    } else {
        edge_os_evtloop_register_socket(&priv->base, sc, priv->fd,
                                         _ds_subscriber_notify_callback);
    }

bad:
    return -1;
}

void subscriber_callback(int fd, void *data, int datalen, void *priv)
{
}

int main(int argc, char **argv)
{
    int subscriver = 0;
    int ret;

    while ((ret = getopt(argc, argv, "i:p:s")) != -1) {
        switch (ret) {
            case 'i':
                ip = optarg;
            break;
            case 'p':
                port = atoi(optarg);
            break;
            case 's':
                subscriver = 1;
            break;
        }
    }

    edge_os_evtloop_init(&base, NULL);

    if (subscriver)
        dc_subscriber_create(&base, "/devnaga", NULL, subscriber_callback);

    edge_os_evtloop_run(&base);

    return -1;
}


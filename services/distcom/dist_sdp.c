#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <edgeos_evtloop.h>
#include <edgeos_netapi.h>
#include <dist_sdp.h>

int dist_sdp_msg_reg_name(int sock, struct dist_sdp_register_name *reg, char *ip, int port)
{
    uint8_t txbuf[2048];
    int name_len = 0;
    int ip_len = 0;
    int port_be = 0;
    int txbuf_len = 0;

    if (!ip) {
        return -1;
    }

    if ((strlen(reg->name) > 20) || (strlen(reg->ipaddr) > 20)) {
        return -1;
    }

    txbuf[txbuf_len] = 0x01;
    txbuf_len ++;

    name_len = strlen(reg->name);
    ip_len = strlen(reg->ipaddr);

    txbuf[txbuf_len] = name_len;
    txbuf_len ++;

    memcpy(&txbuf[txbuf_len], reg->name, name_len);
    txbuf_len += name_len;

    txbuf[txbuf_len] = ip_len;
    txbuf_len ++;

    memcpy(&txbuf[txbuf_len], reg->ipaddr, ip_len);
    txbuf_len += ip_len;

    port_be = htons(reg->port);

    memcpy(&txbuf[txbuf_len], &port_be, sizeof(port_be));
    txbuf_len += sizeof(port_be);

    return edge_os_udp_sendto(sock, txbuf, txbuf_len, ip, port);
}

int dist_sdp_prepmsg_regname_resp(int sock, struct dist_sdp_register_resp *resp, char *ip, int send_port)
{
    uint8_t txbuf[2048];
    int name_len = 0;
    int txbuf_len = 0;

    if (!resp) {
        return -1;
    }

    txbuf[txbuf_len] = 0x02;
    txbuf_len ++;

    name_len = strlen(resp->name);

    txbuf[txbuf_len] = name_len;
    txbuf_len ++;

    memcpy(&txbuf[txbuf_len], resp->name, name_len);
    txbuf_len += name_len;

    memcpy(&txbuf[txbuf_len], &(resp->resp), sizeof(resp->resp));
    txbuf_len += sizeof(resp->resp);

    return edge_os_udp_sendto(sock, txbuf, txbuf_len, ip, send_port);
}

int dist_sdp_msg_reg_name_resp(int sock, struct dist_sdp_register_resp *resp)
{
    uint8_t res[2048];
    char ip[20];
    int port;
    int name_len = 0;
    int off = 0;
    int ret;

    ret = edge_os_udp_recvfrom(sock, res, sizeof(res), ip, &port);
    if (ret < 0) {
        return -1;
    }

    if (res[0] == 0x02) {
        off ++;

        name_len = res[off];
        off ++;

        memcpy(resp->name, &res[off], name_len);
        off += name_len;

        resp->resp = res[off];

        return 0;
    }

    return -1;
}

int dist_sdp_query_name(int sock, struct dist_sdp_query_name *query, char *ip, int port)
{
    uint8_t txbuf[2048];
    int name_len = 0;
    int txbuf_len = 0;

    if (!ip) {
        return -1;
    }

    txbuf[txbuf_len] = 0x03;
    txbuf_len ++;

    name_len = strlen(query->name);

    txbuf[txbuf_len] = name_len;
    txbuf_len ++;

    memcpy(&txbuf[txbuf_len], query->name, name_len);
    txbuf_len += name_len;

    return edge_os_udp_sendto(sock, txbuf, txbuf_len, ip, port);
}

int dist_sdp_prepmsg_query_response(int sock, struct dist_sdp_query_name_resp *query, char *ip, int port)
{
    uint8_t txbuf[2048];
    int name_len = 0;
    int ip_len = 0;
    int port_be = 0;
    int txbuf_len = 0;

    txbuf[txbuf_len] = 0x04;
    txbuf_len ++;

    name_len = strlen(query->name);
    ip_len = strlen(query->ipaddr);

    txbuf[txbuf_len] = name_len;
    txbuf_len ++;

    memcpy(&txbuf[txbuf_len], query->name, name_len);
    txbuf_len += name_len;

    txbuf[txbuf_len] = ip_len;
    txbuf_len ++;
    
    memcpy(&txbuf[txbuf_len], query->ipaddr, ip_len);
    txbuf_len += ip_len;

    port_be = htons(query->port);

    memcpy(&txbuf[txbuf_len], &port_be, sizeof(port_be));
    txbuf_len += sizeof(port_be);

    return edge_os_udp_sendto(sock, txbuf, txbuf_len, ip, port);
}

int dist_sdp_query_name_resp(int sock, struct dist_sdp_query_name_resp *query)
{
    uint8_t rxbuf[2048];
    int name_len = 0;
    char ip[20];
    int port;
    int ip_len = 0;
    int off = 0;
    int ret;

    ret = edge_os_udp_recvfrom(sock, rxbuf, sizeof(rxbuf), ip, &port);
    if (ret < 0) {
        return -1;
    }

    if (rxbuf[0] == 0x04) {
        off ++;

        name_len = rxbuf[off];
        off ++;

        memcpy(query->name, &rxbuf[off], name_len);
        off += name_len;

        ip_len = rxbuf[off];
        off ++;

        memcpy(query->ipaddr, &rxbuf[off], ip_len);
        off += ip_len;

        memcpy(&query->port, &rxbuf[off], sizeof(int));
        off += sizeof(int);

        query->port = htons(query->port);
        
        return 0;
    }

    return -1;
}

#ifndef __EDGEOS_DIST_SDP_H__
#define __EDGEOS_DIST_SDP_H__

struct dist_sdp_register_name {
    char name[20];
    char ipaddr[20];
    int port;
};

typedef enum {
    DIST_SDP_REG_NAME_RES_OK = 0,
    DIST_SDP_REG_NAME_RES_EXIST = 1,
} reg_name_resp_t;

struct dist_sdp_register_resp {
    char name[20];
    reg_name_resp_t resp;
};

struct dist_sdp_query_name {
    char name[20];
};

struct dist_sdp_query_name_resp {
    char name[20];
    char ipaddr[20];
    int port;
};

typedef enum {
    DIST_SDP_REG_NAME,
    DIST_SDP_QUERY_NAME_REQ,
    DIST_SDP_QUERY_NAME_RESP,
} dist_sdp_req_t;

// from client to DIstMaster
int dist_sdp_msg_reg_name(int sock, struct dist_sdp_register_name *reg, char *ip, int port);

// from Distmaster to the Client
int dist_sdp_prepmsg_regname_resp(int sock, struct dist_sdp_register_resp *resp, char *ip, int port);

int dist_sdp_msg_reg_name_resp(int sock, struct dist_sdp_register_resp *resp);

int dist_sdp_query_name(int sock, struct dist_sdp_query_name *query, char *ip, int port);

int dist_sdp_query_name_resp(int sock, struct dist_sdp_query_name_resp *query);

#endif

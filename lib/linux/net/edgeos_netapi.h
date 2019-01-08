#ifndef __EDGEOS_NETAPI_H__
#define __EDGEOS_NETAPI_H__

// server types to choose for the managed server
typedef enum {
    // create tcp server
    EDGEOS_SERVER_TCP,

    // create udp server
    EDGEOS_SERVER_UDP,

    // create tcp unix server
    EDGEOS_SERVER_TCP_UNIX,

    // create udp unix server
    EDGEOS_SERVER_UDP_UNIX
} edge_os_server_type_t;

typedef enum {
    EDGEOS_RAW_SOCK_ETH = 1,
    EDGEOS_RAW_SOCK_ICMP = 2,
} edge_os_raw_sock_type_t;

/**
 * @brief - create new udp socket
 * 
 * @return returns socket address on success and -1 on failure
 */
int edge_os_new_udp_socket();

/**
 * @brief - create new unix socket
 *
 * @return - returns socket address on success and -1 on failure
 */
int edge_os_new_unix_socket();

/**
 * @brief - create new tcp socket
 *
 * @return - return socket address
 */
int edge_os_new_tcp_socket();


/**
 * @brief - create tcp server
 *
 * @param ip - ip address of the server
 * @param port - port number
 * @param n_conns - number of connects to listen
 *
 * Description-
 *
 * creates a tcp server with given ip and port, (reuses the address automatically)
 * and returns the server fd. The caller must perform os_accept_conn
 *
 * @return return socket address on success -1 on failure
 */
int edge_os_create_tcp_server(const char *ip, int port, int n_conn);

int edge_os_create_tcp_client(const char *ip, int port);

int edge_os_create_udp_server(const char *ip, int port);

/**
 * @brief - create UDP client
 *
 * @return - returns the UDP socket
 */
int edge_os_create_udp_client();

/**
 * @brief - delete UDP socket
 */
void edge_os_del_udp_socket(int sock);

int edge_os_del_tcp_socket(int sock);



int edge_os_create_tcp_unix_client(const char *path);

int edge_os_create_tcp_unix_server(const char *path, const int n_conns);

int edge_os_create_udp_unix_client(const char *addr);
int edge_os_create_udp_unix_server(const char *addr);


int edge_os_create_udp_mcast_server(char *ip, int port, char *mcast_ip);
int edge_os_create_udp_mcast_client(char *ip, int port, char *mcast_group, char *ipaddr);


int edge_os_accept_conn(int sock, char *ip, int *port);

int edge_os_udp_sendto(int fd, void *msg, int msglen, char *dest, int dest_port);
int edge_os_udp_recvfrom(int fd, void *msg, int msglen, char *dest, int *dest_len);

int edge_os_tcp_send(int fd, void *msg, int msglen);
int edge_os_tcp_recv(int fd, void *msg, int msglen);

int edge_os_udp_unix_sendto(int fd, void *msg, int msglen, char *dest);

int edge_os_socket_ioctl_set_nonblock(int fd);
int edge_os_socket_ioctl_set_mcast_add_member(int fd, char *ipaddr, char *ifname);
int edge_os_socket_ioctl_set_mcast_if(int fd, char *ipaddr);
int edge_os_socket_ioctl_bind_to_device(int fd);
int edge_os_socket_ioctl_reuse_addr(int fd);



void* edge_os_create_server_managed(void *evtloop_base,
                                    void *app_ctx,
                                    edge_os_server_type_t type,
                                    const char *ip,
                                    int port,
                                    int n_conns,
                                    int expect_bufsize,
                                    void (*default_accept)(int fd, char *ip, int port),
                                    int (*default_recv)(int fd, void *data, int datalen, char *ip, int port));

int edge_os_net_setmaxconn(int conns);

int edge_os_connect_address6(const char *addr, const char *service_name);

int edge_os_connect_address4(const char *addr, const char *service_name);

#endif


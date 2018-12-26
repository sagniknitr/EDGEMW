#ifndef __NET_SOCKET_H__
#define __NET_SOCKET_H__

typedef enum {
    EDGEOS_SERVER_TCP,
    EDGEOS_SERVER_UDP,
    EDGEOS_SERVER_TCP_UNIX,
    EDGEOS_SERVER_UDP_UNIX
} edge_os_server_type_t;

/**
 * @brief - create new udp socket
 * 
 * @return returns socket address
 */
int edge_os_new_udp_socket();

int edge_os_new_unix_socket();
int edge_os_new_tcp_socket();


int edge_os_create_tcp_server(const char *ip, int port, int n_conn);

int edge_os_create_tcp_client(const char *ip, int port);

int edge_os_create_udp_server(const char *ip, int port);

int edge_os_create_udp_client();

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
                                    int (*default_recv)(int fd, void *data, int datalen));

#endif


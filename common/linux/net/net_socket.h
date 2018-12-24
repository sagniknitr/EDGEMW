#ifndef __NET_SOCKET_H__
#define __NET_SOCKET_H__

int edge_os_new_udp_socket();
int edge_os_new_unix_socket();
int edge_os_new_tcp_socket();


int edge_os_create_tcp_server(char *ip, int port, int n_conn);

int edge_os_create_tcp_client(const char *ip, int port);

int edge_os_create_udp_server(char *ip, int port);

int edge_os_create_udp_client();

void edge_os_del_udp_socket(int sock);

int edge_os_del_tcp_socket(int sock);



int edge_os_create_tcp_unix_client(const char *path);

int edge_os_create_tcp_unix_server(const char *path, const int n_conns);

int edge_os_create_udp_unix_client(char *addr);
int edge_os_create_udp_unix_server(char *addr);


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





#define format_inet_sockaddr(__serv, __ip, __port) { \
    __serv->sin_addr.s_addr = inet_addr(__ip); \
    __serv->sin_port = htons(__port); \
    __serv->sin_family = AF_INET; \
};

#endif


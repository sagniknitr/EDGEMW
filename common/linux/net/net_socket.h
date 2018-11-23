#ifndef __NET_SOCKET_H__
#define __NET_SOCKET_H__

int edge_os_new_udp_socket();
int edge_os_new_unix_socket();
int edge_os_new_tcp_socket();
void edge_os_del_udp_socket(int sock);

int edge_os_create_tcp_server(char *ip, int port);
int edge_os_create_udp_server(char *ip, int port);

int edge_os_create_udp_client();
int edge_os_create_unix_client(char *addr);
int edge_os_create_unix_server(char *addr);
int edge_os_create_udp_mcast_server(char *ip, int port);
int edge_os_create_udp_mcast_client(char *ip, int port, char *mcast_group);

int edge_os_udp_sendto(int fd, void *msg, int msglen, char *dest, int dest_port);
int edge_os_udp_recvfrom(int fd, void *msg, int msglen, char *dest, int *dest_len);

int edge_os_socket_ioctl_set_nonblock(int fd);
int edge_os_socket_ioctl_set_mcast_add_member(int fd, char *ipaddr, char *ifname);
int edge_os_socket_ioctl_bind_to_device(int fd);


int edge_os_udp_unix_sendto(int fd, void *msg, int msglen, char *dest);

#define format_inet_sockaddr(__serv, __ip, __port) { \
    __serv->sin_addr.s_addr = inet_addr(__ip); \
    __serv->sin_port = htons(__port); \
    __serv->sin_family = AF_INET; \
};

#endif
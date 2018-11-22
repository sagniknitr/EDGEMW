#ifndef __NET_SOCKET_H__
#define __NET_SOCKET_H__

int new_udp_socket();
void del_udp_socket(int sock);


int create_tcp_server(char *ip, int port);
int create_udp_server(char *ip, int port);

int create_udp_client();
int create_unix_client(char *addr);
int create_unix_server(char *addr);

int udp_sendto(int fd, void *msg, int msglen, char *dest, int dest_port);
int udp_recvfrom(int fd, void *msg, int msglen, char *dest, int *dest_len);

int udp_unix_sendto(int fd, void *msg, int msglen, char *dest);

#define format_inet_sockaddr(__serv, __ip, __port) { \
    __serv->sin_addr.s_addr = inet_addr(__ip); \
    __serv->sin_port = htons(__port); \
    __serv->sin_family = AF_INET; \
};

#endif

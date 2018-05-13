#include "net_i.h"

int net_create_tcp_inet_socket(char *ip, int port, int n_conns)
{
	return -1;
}

int net_connect_tcp_inet_socket(char *ip, int port)
{
	return -1;
}

int net_create_udp_inet_socket(char *ip, int port)
{
	return -1;
}

int net_connect_udp_inet_socket(char *ip, int port)
{
	return -1;
}

int net_tcp_send(int sock, uint8_t *data, int data_len)
{
	return -1;
}

int net_tcp_recv(int sock, uint8_t *data, int data_len)
{
	return -1;
}

int net_udp_send_simple(int sock, char *dest, int dest_port, uint8_t *data, int data_len)
{
	return -1;
}

int net_udp_send(int sock, struct sockaddr *dest, socklen_t dest_len, uint8_t *data, int data_len)
{
	return -1;
}

int net_create_tcp_unix_socket(char *unix_addr, int n_conns)
{
	return -1;
}

int net_connect_tcp_unix_socket(char *ip, int port)
{
	return -1;
}

int net_create_udp_unix_socket(char *unix_addr, int n_conns)
{
	return -1;
}

int net_connect_udp_unix_socket(char *unix_serv_addr, char *client_addr)
{
	return -1;
}

#ifndef __MWOS_NET_I_H__
#define __MWOS_NET_I_H__

extern "C" {
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <unistd.h>
}

class netSocket {
    private:
        int sock;
        struct sockaddr_in serv_in;
        struct sockaddr_in6 serv_in6;
        struct sockaddr_in dest_in;
        struct sockaddr_in6 dest_in6;
        struct sockaddr_un serv_un;
        struct sockaddr_un cli_un;
        char addr[200];
        char cli_addr[200];
        int port;
        int n_conns;

        netSocket() {
            sock = -1;
            memset(addr, 0, sizeof(addr));
            port = -1;
            n_conns = 0;
        }

        ~netSocket() {
            if (sock > 0) {
                close(sock);
            }
        }
    public:
        int initTcpServer(char *dest, int port, int n_conn);
        int initUdpServer(char *dest, int port);
        int initTcpClient(char *dest, int port);
        int initUdpClient(char *dest, int port);
        int initTcpServerUnix(char *dest, int n_conn);
        int initTcpClientUnix(char *dest);
        int initUdpServerUnix(char *dest);
        int initUdpClientUnix(char *serv_dest, char *addr);
};

#endif


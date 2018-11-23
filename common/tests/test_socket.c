#include <net_socket.h>

int main()
{
    int sock;

    sock = edge_os_create_udp_client();
    if (sock < 0) {
        return -1;
    }

    edge_os_del_udp_socket(sock);

    return 0;
}


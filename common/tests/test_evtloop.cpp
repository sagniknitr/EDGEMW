#include <iostream>
#include <functional>
extern "C" {
#include <evtloop.h>
#include <net_socket.h>
}
#include <cstring>

static struct edge_os_evtloop_base base;

// FIXME: std::bind 
void accept_callback(void *priv);
void recv_callback(void *priv);

class TcpServer {
    private:
        int fd_;
        int clientFd_;
    public:
        int getFd()
        {
            return fd_;
        }
        int setClientFd(int fd)
        {
            clientFd_ = fd;

            return 0;
        }
        int getClientFd()
        {
            return clientFd_;
        }


        TcpServer(std::pair<std::string, int> ipPort)
        {
            fd_ = edge_os_create_tcp_server(ipPort.first.c_str(), ipPort.second, 1000);
            edge_os_evtloop_register_socket(&base, this, fd_, accept_callback);
        }


};

void accept_callback(void *app_priv)
{
    int clientFd;
    TcpServer *s = reinterpret_cast<TcpServer *>(app_priv);

    clientFd = edge_os_accept_conn(s->getFd(), NULL, NULL);
    if (clientFd < 0)
        return;

    edge_os_evtloop_register_socket(&base, s, clientFd, recv_callback);
    s->setClientFd(clientFd);
}

void recv_callback(void *app_priv)
{
    char msg[80];
    TcpServer *s = reinterpret_cast<TcpServer *>(app_priv);
    int ret;

    ret = edge_os_tcp_recv(s->getClientFd(), msg, sizeof(msg));
    if (ret < 0)
        return;

    std::cerr << msg << std::endl;
}

void repeated_timer(void *priv);

class TcpClient {
    private:
        int fd_;

    public:
        int getFd()
        {
            return fd_;
        }

        TcpClient(std::pair<std::string, int> ipPort)
        {
            fd_ = edge_os_create_tcp_client(ipPort.first.c_str(), ipPort.second);

            std::cerr << fd_ << std::endl;
            edge_os_evtloop_register_timer(&base, this, 1, 0, repeated_timer);
        }
};

void repeated_timer(void *priv)
{
    TcpClient *c = reinterpret_cast<TcpClient *>(priv);
    char msg[] = "Hello\n";

    std::cerr << "send msg" << std::endl;
    edge_os_tcp_send(c->getFd(), msg, strlen(msg));
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "<%s> server/client\n", argv[0]);
        return -1;
    }

    edge_os_evtloop_init(&base, NULL);

    if (!strcmp(argv[1], "server")) {
        TcpServer s(std::pair<std::string, int>("127.0.0.1", 1244));
    } else if (!strcmp(argv[1], "client")) {
        TcpClient c(std::pair<std::string, int>("127.0.0.1", 1244));
    }

    edge_os_evtloop_run(&base);
}


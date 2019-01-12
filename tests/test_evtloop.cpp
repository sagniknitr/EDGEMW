#include <iostream>
#include <functional>
extern "C" {
#include <edgeos_evtloop.h>
#include <edgeos_netapi.h>
}
#include <cstring>

static struct edge_os_evtloop_base base;

// FIXME: std::bind 
void accept_callback(int sock, void *priv);
void recv_callback(int sock, void *priv);

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

static int client_count = 0;

void accept_callback(int sock, void *app_priv)
{
    int clientFd;
    TcpServer *s = reinterpret_cast<TcpServer *>(app_priv);

    clientFd = edge_os_accept_conn(s->getFd(), NULL, NULL);
    if (clientFd < 0)
        return;

    client_count ++;

    printf("new client %d\n", clientFd);
    edge_os_evtloop_register_socket(&base, s, clientFd, recv_callback);
    s->setClientFd(clientFd);
}

void recv_callback(int sock, void *app_priv)
{
    char msg[80];
    TcpServer *s = reinterpret_cast<TcpServer *>(app_priv);
    int ret;

    ret = edge_os_tcp_recv(sock, msg, sizeof(msg));
    if (ret <= 0) {
        printf("close %d %d\n", s->getClientFd(), sock);
        edge_os_evtloop_unregister_socket(&base, sock);
        client_count --;

        if (client_count <= 0)
            exit(0);
        return;
        //exit(0);
    }

    std::cerr << "sock " << sock << "m : " << msg << std::endl;
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
            edge_os_evtloop_register_timer(&base, this, 0, 10 * 1000, repeated_timer);
        }
};

void repeated_timer(void *priv)
{
    TcpClient *c = reinterpret_cast<TcpClient *>(priv);
    char msg[] = "Hello";
    static int counter =  4000;

    if (counter <= 0) {
        exit(0);
    }
    std::cerr << "send msg" << std::endl;
    edge_os_tcp_send(c->getFd(), msg, strlen(msg));
    counter --;
}

int evtloop_test(int argc, char **argv)
{
    edge_os_evtloop_init(NULL, NULL);
    edge_os_evtloop_register_timer(NULL, NULL, 0, 0, NULL);
    edge_os_evtloop_register_socket(NULL, NULL, -1, NULL);
    edge_os_evtloop_unregister_socket(NULL, -1);

    edge_os_evtloop_init(&base, NULL);

    if (!strcmp(argv[1], "server")) {
        TcpServer s(std::pair<std::string, int>("127.0.0.1", 1244));
    } else if (!strcmp(argv[1], "client")) {
        for (auto i = 0; i < 100; i ++) {
            TcpClient *c = new TcpClient(std::pair<std::string, int>("127.0.0.1", 1244));

            std::cerr << c->getFd() << std::endl;
        }
    } else {
        fprintf(stderr, "<%s> server/client\n", argv[0]);
        return -1;
    }

    edge_os_evtloop_run(&base);

	return 0;
}


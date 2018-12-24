#include <iostream>
#include <string>
#include <vector>
#include <stdint.h>
extern "C" {
#include <net_socket.h>
#include <evtloop.h>
}
#include <ClientMgr.hpp>
#include <MasterLoop.hpp>
#include <TcpServer.hpp>

static receiveNotifier *r__ = nullptr;
static newConnNotifier *n__ = nullptr;

void autoReceiveData(void *priv)
{
    TcpServer *s = reinterpret_cast<TcpServer *>(priv);

    uint8_t buf[4096];
    int fd = s->cMgr_->firstFd(); // FIXME: fix this at the evtloop.c: make the callback accept a socket fd
    int ret;
    
    ret = edge_os_tcp_recv(fd, buf, sizeof(buf));
    if (ret < 0) {
        return;
    }

    if (s->r_) {
        receiveNotifier r = s->r_;
        (r)(fd, buf, ret);
    }
}

void autoAcceptConnections(void *priv)
{
    TcpServer *s = reinterpret_cast<TcpServer *>(priv);
    char ip[20];
    int port;
    int fd;

    fd = edge_os_accept_conn(s->serverFd_, ip, &port);
    if (fd < 0) {
        return;
    }

    std::cerr << " accept connection " << fd << std::endl;
    s->cMgr_->addFd(fd);

    if (s->n_) {
        newConnNotifier n = s->n_;
        (n)(fd);
    }

    edge_os_evtloop_register_socket(s->m_->getMasterLoopBase(), s, fd, autoReceiveData);
}

TcpServer::TcpServer(MasterLoop *m, std::pair<std::string, int> ipPort)
{
    m_ = m;

    n_ = nullptr;
    r_ = nullptr;

    cMgr_ = new ClientMgr;

    serverFd_ = edge_os_create_tcp_server(ipPort.first.c_str(), ipPort.second, 44);
    
    if (serverFd_ < 0)
        return;

    edge_os_evtloop_register_socket(m->getMasterLoopBase(), this, serverFd_, autoAcceptConnections);
}

TcpServer::~TcpServer()
{
    edge_os_del_tcp_socket(serverFd_);
}

void TcpServer::registerNotifiers(receiveNotifier r, newConnNotifier n)
{
    r_ = r;
    n_ = n;
}

#ifndef __EDGEOS_TCPSERVER_HPP__
#define __EDGEOS_TCPSERVER_HPP__

#include <MasterLoop.hpp>
#include <ClientMgr.hpp>

class TcpServer;

typedef int (*receiveNotifier)(int fd, void *data, int dataLen);
typedef int (*newConnNotifier)(int fd);

class TcpServer {
    public:
        TcpServer(MasterLoop *m, std::pair<std::string, int> ipPort);
        ~TcpServer();

        void registerNotifiers(receiveNotifier r, newConnNotifier n);

        friend void autoAcceptConnections(void *priv);
        friend void autoReceiveData(void *priv);
        int sendMessage(int fd, void *data, int dataLen);

    private:
        int serverFd_;
        ClientMgr *cMgr_;
        MasterLoop *m_;
        receiveNotifier r_;
        newConnNotifier n_;
};



#endif

#ifndef __EDGEOS_CLIENT_MGR_HPP__
#define __EDGEOS_CLIENT_MGR_HPP__

#include <string>
#include <vector>

struct clientInfo {
    int clientFd_;
};

class ClientMgr {
    public:
        int addFd(int fd);
        int delFd(int fd);
        int maxFd();
        int firstFd();
        int lastFd();

    private:
        std::vector<clientInfo> clientList_;
};

#endif

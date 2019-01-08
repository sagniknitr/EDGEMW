#include <iostream>
#include <ClientMgr.hpp>

int ClientMgr::addFd(int fd)
{
    clientInfo c = {
        .clientFd_ = fd,
    };

    clientList_.push_back(c);

    return 0;
}

int ClientMgr::delFd(int fd)
{
    clientInfo c = {
        .clientFd_ = fd,
    };
    std::vector<clientInfo>::iterator it;

    for (it = clientList_.begin(); it != clientList_.end(); it ++) {
        clientInfo i = *it;

        if (i.clientFd_ == c.clientFd_) {
            break;
        }
    }

    if (it != clientList_.end()) {
        clientList_.erase(it);
        return 0;
    }

    return -1;
}

// FIXME
int ClientMgr::maxFd()
{
    return -1;
}

int ClientMgr::firstFd()
{
    std::vector<clientInfo>::iterator it = clientList_.begin();

    if (clientList_.empty())
        return -1;
        
    return (*it).clientFd_;
}

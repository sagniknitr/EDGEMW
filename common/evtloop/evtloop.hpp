#ifndef __EVTLOOP_HPP__
#define __EVTLOOP_HPP__

#include <vector>
#include <sys/select.h>

namespace edgeMW {

struct evtLoopSock {
    int fd_;
    void *callbackPtr;
    void (*callback)(void *callbackPtr);
};

struct evtLoopTimer {
    int sec;
    int nsec;
    int fd_;
    void *callbackPtr;
    void (*callback)(void *callbackPtr);
};

class evtLoop {
    private:
        std::vector<struct evtLoopTimer> timerList_;
        std::vector<struct evtLoopSock> socketList_;
        fd_set allfd_;
        int getMaxFd()
        {
            std::vector<struct evtLoopSock>::const_iterator it;
            int  maxFd = 0;

            for (it = socketList_.begin(); it != socketList_.end(); it ++) {
                if (maxFd < it->fd_) {
                    maxFd = it->fd_;
                }
            }

            std::vector<struct evtLoopTimer>::const_iterator it1;

            for (it1 = timerList_.begin(); it1 != timerList_.end(); it1 ++) {
                if (maxFd < it1->fd_) {
                    maxFd = it->fd_;
                }
            }

            return maxFd;
        }
    public:
        evtLoop();
        int registerSock(int fd_, void *callbackPtr,
                         void (*callback)(void *callbackPtr));
        int registerTimer(int sec, int nsec, void *callbackPtr,
                          void (*callback)(void *callbackPtr));
        void run();
        ~evtLoop();
};

int runnerInit();
int runnerRegisterSock(int fd_, void *callbackPtr,
                       void (*callback)(void *callbackPtr));
int runnerRegisterTimer(int sec, int nsec, void *callbackPtr,
                        void (*callback)(void *callbackPtr));
int run();
void runnerDeinit();

};

#endif


#ifndef __EVTLOOP_HPP__
#define __EVTLOOP_HPP__

#include <vector>

namespace edgeMW {

struct evtLoopSock {
    int fd_;
    void *callbackPtr;
    void (*callback)(void *callbackPtr);
};

struct evtLoopTimer {
    int sec;
    int nsec;
    void *callbackPtr;
    void (*callback)(void *callbackPtr);
};

class evtLoop {
    private:
        std::vector<struct evtLoopTimer> timerList_;
        std::vector<struct evtLoopSock> socketList_;
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


/**
 * CopyRight Devnaga <devendra.aaru@gmail.com>
 * 
 * License Apache2
 */
#include <iostream>
#include <vector>
#include <evtloop.hpp>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/select.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/timerfd.h>

namespace edgeMW {

evtLoop::evtLoop()
{
    FD_ZERO(&allfd_);
}

int evtLoop::registerSock(int fd_, void *callbackPtr,
                          void (*callback)(void *callbackPtr))
{
    struct evtLoopSock sock;

    sock.fd_ = fd_;
    sock.callbackPtr = callbackPtr;
    sock.callback = callback;

    socketList_.push_back(sock);

    return 0;
}

int evtLoop::registerTimer(int sec, int nsec, void *callbackPtr,
                           void (*callback)(void *callbackPtr))
{
    struct evtLoopTimer timer;
    int ret;

    timer.fd_ = timerfd_create(CLOCK_MONOTONIC, 0);
    if (timer.fd_ < 0) {
        return -1;
    }

    struct itimerspec its;

    its.it_value.tv_sec = sec;
    its.it_value.tv_nsec = nsec;
    its.it_interval.tv_sec = sec;
    its.it_interval.tv_nsec = nsec;

    ret = timerfd_settime(timer.fd_, 0, &its, NULL);
    if (ret < 0) {
        return -1;
    }

    FD_SET(timer.fd_, &allfd_);

    timerList_.push_back(timer);
    return 0;
}

void evtLoop::run()
{
    int maxFd;
    fd_set rfd;
    int ret;

    maxFd = getMaxFd();
    while (1) {
        rfd = allfd_;
        ret = select(maxFd + 1, &rfd, NULL, NULL, NULL);
        if (ret < 0) {
            break;
        }
        if (ret > 0) {
            std::vector<struct evtLoopTimer>::const_iterator it;
            std::vector<struct evtLoopSock>::const_iterator it1;

            // TBD: run it in thread
            for (it = timerList_.begin(); it != timerList_.end(); it ++) {
                if (FD_ISSET(it->fd_, &rfd)) {
                    it->callback(it->callbackPtr);
                }
            }

            // TBD: run it in thread
            for (it1 = socketList_.begin(); it1 != socketList_.end(); it1 ++) {
                if (FD_ISSET(it1->fd_, &rfd)) {
                    it1->callback(it1->callbackPtr);
                }
            }
        }
    }
}

evtLoop::~evtLoop()
{
    std::vector<struct evtLoopTimer>::const_iterator it;

    for (it = timerList_.begin(); it != timerList_.end(); it ++) {
        close(it->fd_);
    }

    timerList_.clear();
    socketList_.clear();
}

static evtLoop *loop;

int runnerInit()
{
    loop = new evtLoop;

    return 0;
}

int runnerRegisterSock(int fd_, void *callbackPtr,
                       void (*callback)(void *callbackPtr))
{
    return loop->registerSock(fd_, callbackPtr, callback);
}

int runnerRegisterTimer(int sec, int nsec, void *callbackPtr,
                        void (*callback)(void *callbackPtr))
{
    return loop->registerTimer(sec, nsec, callbackPtr, callback);
}

void run()
{
    loop->run();
}

void runnerDeinit()
{
    delete loop;
}

};


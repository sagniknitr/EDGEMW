#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>
#include <edgeos_datetime.h>
#include <edgeos_logger.h>

int edge_os_gettimeofday(struct edge_os_timeval *t)
{
    struct timeval t_;

    if (!t) {
        edge_os_error("date_time: invalid t ptr %p @ %s %u\n", 
                            t, __func__, __LINE__);
        return -1;
    }

    gettimeofday(&t_, NULL);

    t->sec = t_.tv_sec;
    t->usec = t_.tv_usec;

    return 0;
}

int edge_os_settimeofday(struct edge_os_timeval *t)
{
    int ret;
    struct timeval t_;

    if (!t) {
        edge_os_error("date_time: invlaid t ptr %p @ %s %u\n",
                            t, __func__, __LINE__);
        return -1;
    }

    t_.tv_sec = t->sec;
    t_.tv_usec = t->usec;

    ret = settimeofday(&t_, NULL);
    if (ret < 0) {
        edge_os_log_with_error(errno, "date_time: failed to settimeofday ");
        return -1;
    }

    return 0;
}

int edge_os_get_monotonic_clock(struct edge_os_timespec *t)
{
    struct timespec t_;
    int ret;

    ret = clock_gettime(CLOCK_MONOTONIC, &t_);
    if (ret < 0) {
        edge_os_log_with_error(errno, "date_time: failed to clock_gettime ");
        return -1;
    }

    t->sec = t_.tv_sec;
    t->nsec = t_.tv_nsec;

    return 0;
}

int edge_os_nanosleep(long nsec)
{
    int ret;
    long sec_ = 0;
    long nsec_;

    if (nsec >= (1000 * 1000 * 1000)) {
        sec_ = nsec / (1000 * 1000 * 1000);
        nsec_ = nsec % (1000 * 1000 * 1000);
    } else {
        sec_ = 0;
        nsec_ = nsec;
    }

    struct timespec t_ = {
        .tv_sec = sec_,
        .tv_nsec = nsec_,
    };

    // no remaining sleep ... :(
    ret = nanosleep(&t_, NULL);
    if (ret < 0) {
        edge_os_log_with_error(errno, "date_time: failed to nanosleep ");
        return -1;
    }

    return 0;
}


#ifndef __EDGEOS_DATETIME_H__
#define __EDGEOS_DATETIME_H__

struct edge_os_timeval {
    long sec;
    long usec;
};


struct edge_os_timespec {
    long sec;
    unsigned long long nsec;
};


int edge_os_gettimeofday(struct edge_os_timeval *t);

int edge_os_settimeofday(struct edge_os_timeval *t);

int edge_os_get_monotonic_clock(struct edge_os_timespec *t);

int edge_os_nanosleep(long nsec);

#endif


#ifndef __MWOS_DEBUG_H__
#define __MWOS_DEBUG_H__

#include <stdio.h>
#include <syslog.h>

#define MWOS_ERR(fmt, ...) { \
    fprintf(stderr, fmt, ##__VA_ARGS__);\
    syslog(LOG_USER| LOG_ERR, fmt, ##__VA_ARGS__); \
}

#endif


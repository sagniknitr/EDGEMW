#ifndef __EOS_LOGGER_H__
#define __EOS_LOGGER_H__

#include <syslog.h>

#define edge_os_log(fmt, ...) { \
    syslog(LOG_USER | LOG_INFO, fmt, ##__VA_ARGS__); \
    fprintf(stderr, fmt, ##__VA_ARGS__); \
}

#define edge_os_err(fmt, ...) { \
    syslog(LOG_ERR | LOG_INFO, fmt, ##__VA_ARGS__); \
    fprintf(stderr, fmt, ##__VA_ARGS__); \
}

#define edge_os_debug(fmt, ...) { \
    fprintf(stderr, fmt, ##__VA_ARGS__); \
}

#endif

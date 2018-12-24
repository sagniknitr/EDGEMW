#ifndef __EOS_LOGGER_H__
#define __EOS_LOGGER_H__

#include <syslog.h>
#include <stdarg.h>

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

#define edge_os_fatal edge_os_err

void *edge_os_logger_init(char *ipaddr, int port);
void edge_os_logger_deinit(void *handle);
int edge_os_logger_writemsg(void *handle, char *fmt, ...);
int edge_os_logger_write_valist(void *handle, char *fmt, va_list arg);
void edge_os_set_logger_fallback_local(void *handle);

#endif


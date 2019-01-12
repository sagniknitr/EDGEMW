#ifndef __EOS_LOGGER_H__
#define __EOS_LOGGER_H__

#include <syslog.h>
#include <stdarg.h>

void edge_os_log(char *fmt, ...);
void edge_os_log_with_error(int error, char *fmt, ...);
void edge_os_debug(char *fmt, ...);
void edge_os_error(char *fmt, ...);
void edge_os_alloc_err(const char *file, const char *func, int line);

void *edge_os_logger_init(char *ipaddr, int port);
void edge_os_logger_deinit(void *handle);
int edge_os_logger_writemsg(void *handle, char *fmt, ...);
int edge_os_logger_write_valist(void *handle, char *fmt, va_list arg);
void edge_os_set_logger_fallback_local(void *handle);

#endif


#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>

#ifdef CONFIG_EDGEOS_DETAILED_ERRORS

#define EDGEOS_COLOR_RED "\x1B[31m"
#define EDGEOS_COLOR_GREEN "\x1B[32m"
#define EDGEOS_COLOR_YELLOW "\x1B[33m"
#define EDGEOS_COLOR_BLUE "\x1B[34m"
#define EDGEOS_COLOR_MAGENTA "\x1B[35m"
#define EDGEOS_COLOR_CYAN "\x1B[36m"
#define EDGEOS_COLOR_RESET "\033[0m"

void __edge_os_log(va_list ap, char *fmt, char *color)
{
    char buf[4096];
    int buflen;

    buflen = vsnprintf(buf, sizeof(buf), fmt, ap);
    if (buflen < 0)
        return;

    fprintf(stderr, "%s%s"EDGEOS_COLOR_RESET, color, buf);
}

void edge_os_log(char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    __edge_os_log(ap, fmt, EDGEOS_COLOR_GREEN);
    va_end(ap);
}

void edge_os_debug(char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    __edge_os_log(ap, fmt, EDGEOS_COLOR_BLUE);
    va_end(ap);
}

void edge_os_error(char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    __edge_os_log(ap, fmt, EDGEOS_COLOR_RED);
    va_end(ap);
}

void edge_os_alloc_err(const char *file, const char *func, int line)
{
    edge_os_error("%s: failed to allocate @ %s %u\n",
                        file, func, line);
}

void edge_os_log_with_error(int error, char *fmt, ...)
{
    va_list ap;
    int ret;
    char buf[4096];
    size_t buflen;

    va_start(ap, fmt);

    buflen = vsnprintf(buf, sizeof(buf), fmt, ap);

    if (buflen < sizeof(buf)) {
        ret = strerror_r(error, buf + buflen, sizeof(buf) - buflen);
        if (ret < 0) {
            strcpy(buf, " unknown error ");
        }
    }

    fprintf(stderr, EDGEOS_COLOR_RED"%s"EDGEOS_COLOR_RESET"\n", buf);

    va_end(ap);
}

#else

void edge_os_log(char *fmt, ...)
{
}

void edge_os_debug(char *fmt, ...)
{
}

void edge_os_error(char *fmt, ...)
{
}

void edge_os_log_with_error(int error, char *fmt, ...)
{
}


#endif


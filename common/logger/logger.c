#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>

void edge_os_log(char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
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

    fprintf(stderr, "%s\n", buf);

    va_end(ap);
}


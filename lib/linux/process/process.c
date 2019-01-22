#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <edgeos_fsapi.h>
#include <edgeos_logger.h>

int edge_os_in_root()
{
    return geteuid();
}

int edge_os_get_hostname(char *hostname, int len)
{
#define PROC_HOSTNAME "/proc/sys/kernel/hostname"
    int ret;
    int fd;

    fd = edgeos_open_file(PROC_HOSTNAME, "r");
    if (fd < 0) {
        return -1;
    }

    ret = edgeos_read_file(fd, hostname, len);
    if (ret < 0) {
    }

    edgeos_close_file(fd);
    return ret;
#undef PROC_HOSTNAME
}


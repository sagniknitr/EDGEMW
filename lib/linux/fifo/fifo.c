#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#define EDGEOS_DEFAULT_FIFO_SIZE (8 * 1024 * 1024)

int edge_os_fifo_create(const char *fifo_path, int fifo_size)
{
    int ret;
    int fd;

    unlink(fifo_path);

    ret = mkfifo(fifo_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    if (ret < 0) {
        return -1;
    }

    if (fifo_size <= 0)
        fifo_size = EDGEOS_DEFAULT_FIFO_SIZE;

    fd = open(fifo_path, O_CREAT | O_RDWR,
                    S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    if (fd < 0) {
        return -1;
    }

    ret = fcntl(fd, F_SETPIPE_SZ, fifo_size);
    if (ret < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

int edge_os_fifo_open(const char *fifo_path)
{
    int fd;

    fd = open(fifo_path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    return fd;
}

int edge_os_fifo_write(int fd, void *buf, int buflen)
{
    return write(fd, buf, buflen);
}

int edge_os_fifo_read(int fd, void *buf, int buflen)
{
    return read(fd, buf, buflen);
}


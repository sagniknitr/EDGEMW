#ifndef __EDGEOS_FIFO_H__
#define __EDGEOS_FIFO_H__

int edge_os_fifo_create(const char *fifo_path, int fifo_size);

int edge_os_fifo_open(const char *fifo_path);

int edge_os_fifo_write(int fd, void *buf, int buflen);

int edge_os_fifo_read(int fd, void *buf, int buflen);

int edge_os_fifo_close(int fd, const char *path);

#endif



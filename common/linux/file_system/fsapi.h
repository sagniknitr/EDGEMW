#ifndef __EOS_FSAPI_H__
#define __EOS_FSAPI_H__

int edgeos_create_file(const char *filename);

int edgeos_create_file_truncated(const char *filename, const int filesize);

int edgeos_write_file(int fd, void *msg, int msg_len);

int edgeos_read_file(int fd, void *msg, int msg_len);

int edgeos_close_file(int fd);

int edgeos_delete_file(const char *filename);

#endif


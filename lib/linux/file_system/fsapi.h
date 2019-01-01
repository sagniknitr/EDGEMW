#ifndef __EOS_FSAPI_H__
#define __EOS_FSAPI_H__

int edgeos_create_file(const char *filename);

int edgeos_create_file_truncated(const char *filename, const int filesize);

int edgeos_write_file(int fd, void *msg, int msg_len);

int edgeos_read_file(int fd, void *msg, int msg_len);

int edgeos_close_file(int fd);

int edgeos_delete_file(const char *filename);

int edgeos_write_file__safe(int fd, void *msg, int msg_len);

int edgeos_read_file__safe(int fd, void *msg, int msg_len);

int edgeos_open_file(const char *filename, const char *mode);

int edgeos_read_file__cb(const void *priv, const char *filename, void (*read_callback)(const void *ptr, void *data, int data_len));

int edgeos_get_filesize(const char *filename, size_t *file_size);

int edgeos_read_directory(void *priv, const char *dir,
                        void (*read_callback)(void *priv, const char *filename));

int edgeos_file_in_directory(const char *dir, const char *filename);

int edgeos_create_directory(const char *dir, int owner, int group, int other);

int edge_os_write_file2(const char *file, void *msg, int msg_len);

#endif


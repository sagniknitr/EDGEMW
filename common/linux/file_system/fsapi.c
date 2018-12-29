#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <fsapi.h>
#include <edgeos_logger.h>

int edgeos_create_file(const char *filename)
{
    int fd;

    if (!filename)
        return -1;

    fd = open(filename, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    if (fd < 0)
        return -1;

    return fd;
}

int edgeos_create_file_truncated(const char *filename, const int filesize)
{
    int fd;
    int ret;

    if (!filename || (filesize < 0)) {
        edge_os_error("fsapi: invalid filename or invalid filesize @ %s %u\n",
                                __func__, __LINE__);
        return -1;
    }

    fd = edgeos_create_file(filename);
    if (fd < 0) {
        edge_os_error("fsapi: failed to create file %s @ %s %u\n",
                                __func__, __LINE__);
        return -1;
    }

    ret = ftruncate(fd, filesize);
    if (ret < 0) {
        edge_os_log_with_error(errno, "failed to truncate file @ %s %u ",
                                __func__, __LINE__);
        close(fd);
        return -1;
    }

    return fd;
}

int edgeos_open_file(const char *filename, const char *mode)
{
    int fd;
    int opts = O_RDONLY;
    mode_t creat_opts = 0;

    if (!strcmp(mode, "r")) {
        opts = O_RDONLY;
    } else if (!strcmp(mode, "w")) {
        opts = O_WRONLY;
        creat_opts = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;
    } else if (!strcmp(mode, "rw")) {
        opts = O_RDWR;
    } else if (!strcmp(mode, "a")) {
        opts = O_RDWR | O_APPEND;
    } else {
        return -1;
    }

    if (creat_opts) {
        fd = open(filename, opts, creat_opts);
    } else {
        fd = open(filename, opts);
    }

    if (fd < 0)
        return -1;

    return fd;
}

int edgeos_read_file__cb(const void *priv, const char *filename, void (*read_callback)(const void *ptr, void *data, int data_len))
{
    uint8_t stream[1024];
    int fd;
    int ret;

    if (!read_callback)
        return -1;

    fd = open(filename, O_RDONLY);
    if (fd < 0)
        return -1;

    while (1) {
        ret = read(fd, stream, sizeof(stream) - 1);
        if (ret < 0) {
            break;
        }

        read_callback(priv, stream, ret);
    }

    return 0;
}

int edgeos_write_file(int fd, void *msg, int msg_len)
{
    return write(fd, msg, msg_len);
}

int edgeos_read_file(int fd, void *msg, int msg_len)
{
    return read(fd, msg, msg_len);
}

int edgeos_write_file__safe(int fd, void *msg, int msg_len)
{
    if (!msg || (msg_len <= 0))
        return -1;

    return write(fd, msg, msg_len);
}

int edgeos_read_file__safe(int fd, void *msg, int msg_len)
{
    if (!msg || (msg_len <= 0))
        return -1;

    return read(fd, msg, msg_len);
}

int edgeos_close_file(int fd)
{
    return close(fd);
}

int edgeos_delete_file(const char *filename)
{
    return unlink(filename);
}

int edgeos_get_filesize(const char *filename, size_t *file_size)
{
    struct stat s;
    int ret;

    if (!file_size) {
        edge_os_error("fsapi: invalid file_size @ %s %u\n",
                                __func__, __LINE__);
        return -1;
    }

    ret = stat(filename, &s);
    if (ret) {
        edge_os_log_with_error(errno, "failed to stat %s @ %s %u ",
                                filename, __func__, __LINE__);
        return -1;
    }

    *file_size = s.st_size;
    return 0;
}

int edgeos_read_directory(void *priv, const char *dir,
                        void (*read_callback)(void *priv, const char *filename))
{
    struct dirent *e;
    DIR *d;

    if (!read_callback || !dir)
        return -1;

    d = opendir(dir);
    if (!d)
        return -1;

    while ((e = readdir(d)) != NULL) {
        read_callback(priv, e->d_name);
    }

    closedir(d);

    return 0;
}

int edgeos_file_in_directory(const char *dir, const char *filename)
{
    struct dirent *e;
    int file_present = 0;
    DIR *d;

    if (!dir || !filename)
        return -1;

    d = opendir(dir);
    if (!d)
        return -1;

    while ((e = readdir(d)) != NULL) {
        if (!strcmp(filename, e->d_name)) {
            file_present = 1;
            break;
        }
    }

    closedir(d);

    return file_present;
}

int edgeos_create_directory(const char *dir, int owner, int group, int other)
{
    mode_t mode = S_IRUSR | S_IWUSR;

    umask(0);

    if (owner)
        mode = S_IRUSR | S_IWUSR;
    if (group)
        mode |= S_IRGRP | S_IWGRP;
    if (other)
        mode |= S_IROTH | S_IWOTH;

    return mkdir(dir, mode);
}


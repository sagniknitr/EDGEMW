#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <edgeos_fsapi.h>
#include <edgeos_logger.h>

int edgeos_create_file(const char *filename)
{
    int fd;

    if (!filename) {
        edge_os_error("fsapi: invalid filename pointer @ %s %u\n",
                                __func__, __LINE__);
        return -1;
    }

    fd = open(filename, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    if (fd < 0) {
        edge_os_log_with_error(errno, "fsapi: failed to open file %s ",
                                    filename);
        return -1;
    }

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
        opts = O_CREAT | O_WRONLY | O_TRUNC;
        creat_opts = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;
    } else if (!strcmp(mode, "rw")) {
        opts = O_RDWR;
    } else if (!strcmp(mode, "a")) {
        opts = O_RDWR | O_APPEND;
    } else if (!strcmp(mode, "wx")) {
        opts = O_CREAT | O_WRONLY | O_TRUNC | O_EXCL;
        creat_opts = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;
    } else {
        edge_os_error("fsapi: unsupported mode %s @ %s %u\n",
                                mode, __func__, __LINE__);
        return -1;
    }

    if (creat_opts) {
        fd = open(filename, opts, creat_opts);
    } else {
        fd = open(filename, opts);
    }

    if (fd < 0) {
        edge_os_log_with_error(errno, "fsapi: failed to open file %s ",
                                filename);
        return -1;
    }

    return fd;
}

int edgeos_read_file__cb(const void *priv, const char *filename, void (*read_callback)(const void *ptr, void *data, int data_len))
{
    uint8_t stream[1024];
    int fd;
    int ret;

    if (!filename || !read_callback) {
        edge_os_error("fsapi: invalid read_callback @ %s %u\n",
                            __func__, __LINE__);
        return -1;
    }

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        edge_os_log_with_error(errno, "fsapi: failed to open file %s ",
                            filename);
        return -1;
    }

    while (1) {
        ret = read(fd, stream, sizeof(stream) - 1);
        if (ret <= 0) {
            break;
        }

        read_callback(priv, stream, ret);
    }

    close(fd);

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
    // over head checks
    if ((fd < 0) || !msg || (msg_len <= 0))
        return -1;

    return write(fd, msg, msg_len);
}

int edgeos_read_file__safe(int fd, void *msg, int msg_len)
{
    // over head checks..
    if ((fd < 0) || !msg || (msg_len <= 0))
        return -1;

    return read(fd, msg, msg_len);
}

int edgeos_close_file(int fd)
{
    return close(fd);
}

int edge_os_write_file2(const char *file, void *msg, int msg_len)
{
    int fd;

    // error handling done at open_file
    fd = edgeos_open_file(file, "w");
    if (fd < 0)
        return -1;

    edgeos_write_file(fd, msg, msg_len);

    close(fd);

    return 0;
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

    if (!read_callback || !dir) {
        edge_os_error("fsapi: invalid read_callback or dir @ %s %u\n",
                                    __func__, __LINE__);
        return -1;
    }

    d = opendir(dir);
    if (!d) {
        edge_os_log_with_error(errno, "fsapi: failed to opendir @ %s %u ",
                                    __func__, __LINE__);
        return -1;
    }

    while ((e = readdir(d)) != NULL) {

        // skip the . and ..
        if (!strcmp(e->d_name, ".") ||
            !strcmp(e->d_name, "..")) {
            continue;
        }

        // name can be a file or a directory again
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

    if (!dir || !filename) {
        edge_os_error("fsapi: invalid dir or filename @ %s %u\n",
                                __func__, __LINE__);
        return -1;
    }

    d = opendir(dir);
    if (!d) {
        edge_os_log_with_error(errno, "fsapi: failed to opendir @ %s %u ",
                                    __func__, __LINE__);
        return -1;
    }

    while ((e = readdir(d)) != NULL) {
        // skip the . and ..
        if (!strcmp(e->d_name, ".") ||
            !strcmp(e->d_name, ".."))
            continue;

        if (!strcmp(filename, e->d_name)) {
            file_present = 1;
            break;
        }
    }

    closedir(d);

    return file_present;
}

int edgeos_scan_directory_recurse(const char *dir,
                                  void *priv,
                                  void (*scan_callback)(char *fullpath, int is_dir, void *priv))
{
    edge_os_error("fsapi: this function %s is not implemented\n",
                        __func__);
    return -1;
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

int edge_os_file_create_mmap(const char *file, const char *mode)
{
    edge_os_error("fsapi: this function %s is not supported\n",
                                __func__);
    return -1;
}

int edge_os_file_accessible(const char *file, edge_os_access_mode_t mode)
{
    int ret;
    int a_mode = 0;

    if (!file) {
        edge_os_error("fsapi: invalid file ptr %p @ %s %u\n",
                            file, __func__, __LINE__);
        return -1;
    }
    
    if (mode & EDGE_OS_ACCESS_READ_OK) {
        a_mode |= R_OK;
    }

    if (mode & EDGE_OS_ACCESS_WRITE_OK) {
        a_mode |= W_OK;
    }

    if (mode & EDGE_OS_ACCESS_EXE_OK) {
        a_mode |= X_OK;
    }

    if (!a_mode) {
        edge_os_error("fsapi: invalid access mode %02x\n", mode);
        return -1;
    }

    ret = access(file, a_mode);
    if (ret < 0) {
        edge_os_log_with_error(errno, "fsapi: failed to access() file %s ",
                                        file);
        return -1;
    }

    return 0;
}

int edge_os_create_directory_recurse(const char *dir, int owner, int group, int other)
{
    edge_os_error("fsapi: this function %s is not supported\n",
                                __func__);
    return -1;
}

int edge_os_remove_directory(const char *dir)
{
    int ret;

    ret = rmdir(dir);
    if (ret < 0) {
        edge_os_log_with_error(errno, "fsapi: failed to rmdir %s ",
                                        dir);
        return -1;
    }

    return 0;
}


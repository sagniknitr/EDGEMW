#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <fsapi.h>

int edgeos_create_file(const char *filename)
{
    int fd;

    fd = open(filename, O_CREAT | O_RDWR, S_IRWXU);
    if (fd < 0)
        return -1;

    return fd;
}

int edgeos_create_file_truncated(const char *filename, const int filesize)
{
    int fd;

    fd = edgeos_create_file(filename);
    if (fd < 0)
        return -1;

    ftruncate(fd, filesize);

    return fd;
}

int edgeos_write_file(int fd, void *msg, int msg_len)
{
    return write(fd, msg, msg_len);
}

int edgeos_read_file(int fd, void *msg, int msg_len)
{
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

    ret = stat(filename, &s);
    if (ret)
        return -1;

    *file_size = s.st_size;
    return 0;
}

int edgeos_read_directory(void *priv, const char *dir,
                        void (*read_callback)(void *priv, const char *filename))
{
    struct dirent *e;
    DIR *d;

    if (!read_callback)
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


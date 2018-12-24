#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
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


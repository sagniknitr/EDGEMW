#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <prng.h>

#ifdef OS_LINUX
#define PRNG_DEV "/dev/urandom"
#elif OS_QNX
#define PRNG_DEV "/dev/random"
#endif

int edge_os_prng_init(char *prngdev)
{
    if (!prngdev)
        prngdev = PRNG_DEV;

    return open(prngdev, O_RDONLY);
}

int edge_os_prng_get_bytes(int fd, uint8_t *bytes, size_t len)
{
    int ret;

    if (!bytes)
        return -1;

    ret = read(fd, bytes, len);
    if (ret < 0)
        return -1;

    if ((size_t)ret != len)
        return -1;

    return 0;
}

void edge_os_prng_deinit(int fd)
{
    close(fd);
}


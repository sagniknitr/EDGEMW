#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <edgeos_prng.h>
#include <edgeos_logger.h>

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

    if (!bytes) {
        edge_os_error("prng: bytes is invalid %p @ %s %u\n",
                            bytes, __func__, __LINE__);
        return -1;
    }

    ret = read(fd, bytes, len);
    if (ret < 0) {
        edge_os_log_with_error(errno, "prng: failed to read bytes %u ",
                            len);
        return -1;
    }

    if ((size_t)ret != len) {
        edge_os_error("prng: couldn't read full bytes read:%d request %d @ %s %u\n",
                        ret, len, __func__, __LINE__);
        return -1;
    }

    return 0;
}

void edge_os_prng_deinit(int fd)
{
    close(fd);
}


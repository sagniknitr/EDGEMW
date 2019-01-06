#include <stdio.h>
#include <stdint.h>
#include <edgeos_prng.h>

int prng_test(int argc, char **argv)
{
    int fd;

    fd = edge_os_prng_init(NULL);
    if (fd < 0)
        return -1;

    int bytes = 0;

    if (edge_os_prng_get_bytes(fd, (void *)&bytes, sizeof(bytes)))
        return -1;

    uint8_t array[2048];

    if (edge_os_prng_get_bytes(fd, (void *)array, sizeof(array)))
        return -1;

    if (edge_os_prng_get_bytes(fd, NULL, -1) != -1)
        return -1;

    if (edge_os_prng_get_bytes(fd, (void *)&bytes, -1) != -1)
        return -1;

    edge_os_prng_deinit(fd);

    return 0;
}


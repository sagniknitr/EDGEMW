#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <edgeos_logger.h>

void *handle;

int main(int argc, char **argv)
{
    if (argc != 3) {
        return -1;
    }

    handle = edge_os_logger_init(argv[1], atoi(argv[2]));
    if (!handle) {
        return -1;
    }

    while (1) {
        edge_os_logger_writemsg(handle, "hello logger");
        usleep(100 * 1000);
    }

    return 0;
}


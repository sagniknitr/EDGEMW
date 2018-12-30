#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <edgeos_logger.h>

void *handle;

void signal_handler(int s)
{
    fprintf(stderr, "term signal invoked..\n");
    exit(0);
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        return -1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGQUIT, signal_handler);
    signal(SIGTERM, signal_handler);

    handle = edge_os_logger_init(argv[1], atoi(argv[2]));
    if (!handle) {
        return -1;
    }

    while (1) {
        edge_os_logger_writemsg(handle, "logger: hello logger");
        usleep(100 * 1000);
    }

    return 0;
}


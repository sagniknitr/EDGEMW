#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <unistd.h>
#include <sys/wait.h>

int edge_os_set_process_cpu(int cpu_number)
{
    cpu_set_t set;
    int ret;

    CPU_ZERO(&set);
    CPU_SET(cpu_number, &set);

    ret = sched_setaffinity(getpid(), sizeof(set), &set);
    if (ret < 0) {
        return -1;
    }

    return 0;
}


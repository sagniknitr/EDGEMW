#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <unistd.h>
#include <sys/wait.h>

int edge_os_set_process_cpu(int *cpu_number, int size)
{
    cpu_set_t set;
    int j;
    int ret;

    CPU_ZERO(&set);

    for (j = 0; j < size; j ++)
        CPU_SET(cpu_number[j], &set);

    ret = sched_setaffinity(getpid(), sizeof(set), &set);
    if (ret < 0) {
        return -1;
    }

    return 0;
}

int edge_os_get_num_cpu()
{
    return sysconf(_SC_NPROCESSORS_ONLN);
}


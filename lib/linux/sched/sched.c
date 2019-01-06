#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <unistd.h>
#include <sys/wait.h>
#include <edgeos_sched.h>

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

edge_os_sched_policy_t edge_os_get_sched_policy_self()
{
    edge_os_sched_policy_t prio = EDGEOS_SCHED_POLICY_INVAL;
    int ret;

    ret = sched_getscheduler(0);
    switch (ret) {
        case SCHED_OTHER:
            prio = EDGEOS_SCHED_POLICY_RR_TIMESHARED;
        break;
        case SCHED_BATCH:
            prio = EDGEOS_SCHED_POLICY_BATCH;
        break;
        case SCHED_IDLE:
            prio = EDGEOS_SCHED_POLICY_IDLE;
        break;
        case SCHED_FIFO:
            prio = EDGEOS_SCHED_POLICY_FIFO;
        break;
        case SCHED_RR:
            prio = EDGEOS_SCHED_POLICY_RR;
        break;
    }

    return prio;
}

int edge_os_get_sched_prio_min_max(int *min, int *max, edge_os_sched_policy_t policy)
{
    int ret;
    int sched_policy  = -1;

    switch (policy) {
        case EDGEOS_SCHED_POLICY_RR_TIMESHARED:
            sched_policy = SCHED_OTHER;
        break;
        case EDGEOS_SCHED_POLICY_BATCH:
            sched_policy = SCHED_BATCH;
        break;
        case EDGEOS_SCHED_POLICY_IDLE:
            sched_policy = SCHED_IDLE;
        break;
        case EDGEOS_SCHED_POLICY_FIFO:
            sched_policy = SCHED_FIFO;
        break;
        case EDGEOS_SCHED_POLICY_RR:
            sched_policy = SCHED_RR;
        break;
        default:
            return -1;
    }

    ret = sched_get_priority_max(sched_policy);
    if (ret < 0) {
        return -1;
    }

    *max = ret;

    ret = sched_get_priority_min(sched_policy);
    if (ret < 0) {
        return -1;
    }

    *min = ret;

    return 0;
}

int edge_os_set_sched_priority(int priority)
{
    int ret;
    struct sched_param param = {
        .sched_priority = priority,
    };

    ret = sched_setparam(0, &param);
    if (ret < 0) {
        return -1;
    }

    return 0;
}

int edge_os_get_num_cpu()
{
    return sysconf(_SC_NPROCESSORS_ONLN);
}


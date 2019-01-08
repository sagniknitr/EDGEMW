#ifndef __EDGEOS_SCHED_H__
#define __EDGEOS_SCHED_H__

int edge_os_set_process_cpu(int *cpu_number, int size);

int edge_os_get_num_cpu();

typedef enum {
    EDGEOS_SCHED_POLICY_RR_TIMESHARED,
    EDGEOS_SCHED_POLICY_BATCH,
    EDGEOS_SCHED_POLICY_IDLE,
    EDGEOS_SCHED_POLICY_FIFO,
    EDGEOS_SCHED_POLICY_RR,
    EDGEOS_SCHED_POLICY_INVAL = 128,
} edge_os_sched_policy_t;

edge_os_sched_policy_t edge_os_get_sched_policy_self();

int edge_os_get_sched_prio_min_max(int *min, int *max, edge_os_sched_policy_t policy);

#endif


#include <stdio.h>
#include <edgeos_sched.h>

int sched_test(int argc, char **argv)
{
    int n_cpu;

    n_cpu = edge_os_get_num_cpu();
    printf("num cpu %d\n", n_cpu);

    return 0;
}


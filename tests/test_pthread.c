#include <stdio.h>
#include <unistd.h>
#include <edgeos_pthreads.h>

void thread_func(void *data)
{
    int *ptr = data;

    while (1) {
        (*ptr) ++;

        if ((*ptr) == 0x1ead)
            break;
    }
    printf("thread exits..\n");
}

int pthread_test(int argc, char **argv)
{
    int val = 0;
    void *p;

    p = edge_os_thread_create(thread_func, &val, NULL, 0);
    if (!p) {
        fprintf(stderr, "failed to thread create @ %s %u\n",
                            __func__, __LINE__);
        return -1;
    }

    if (edge_os_thread_execute(p)) {
        fprintf(stderr, "failed to exec  thread @ %s %u\n",
                            __func__, __LINE__);
        return -1;
    }

    sleep(4);
    edge_os_thread_stop(p);

    sleep(1);

    return 0;
}


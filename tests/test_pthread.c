#include <stdio.h>
#include <unistd.h>
#include <edgeos_pthreads.h>

void thread_func(void *data)
{
    int *ptr = data;

    while (1) {
        (*ptr) ++;

        fprintf(stderr, "val: %d\n", *ptr);
    }
}

int main(int argc, char **argv)
{
    int val = 0;
    void *p;

    p = edgeos_thread_create(thread_func, &val, NULL, 0);
    if (!p) {
        fprintf(stderr, "failed to thread create @ %s %u\n",
                            __func__, __LINE__);
        return -1;
    }

    sleep(1);

    if (edgeos_thread_execute(p)) {
        fprintf(stderr, "failed to exec  thread @ %s %u\n",
                            __func__, __LINE__);
        return -1;
    }

    while (1) {
        sleep(10);
    }

}


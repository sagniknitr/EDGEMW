#include <stdio.h>
#include <edgeos_queue.h>

int queue_test(int argc, char **argv)
{
    struct edge_os_queue_base b;

    edge_os_queue_init(&b);

    int array[144];
    int i;

    for (i = 0; i < 144; i ++) {
        array[i] = i + 1;

        edge_os_queue_enque(&b, &array[i]);
    }

    while (1) {
        void *data;

        data = edge_os_queue_deque(&b);
        if (!data)
            break;

        printf("%d ", *(int *)data);
    }
    printf("\n");

    return 0;
}


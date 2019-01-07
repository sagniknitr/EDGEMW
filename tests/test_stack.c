#include <stdio.h>
#include <edgeos_stack.h>


int stack_test(int argc, char **argv)
{
    struct edge_os_stack_base b;
    int array[10];
    int i;

    edge_os_stack_init(&b);

    for (i = 0; i < 10; i ++) {
        array[i] = i + 1;

        edge_os_stack_push(&b, &array[i]);
    }

    while (1) {
        void *t;

        t = edge_os_stack_pop(&b);
        if (!t)
            break;


        printf("%d\n", *(int *)t);
    }

    for (i = 0; i < 4; i ++) {
        edge_os_stack_push(&b, &array[i]);
    }

    while (1) {
        void *t;

        t = edge_os_stack_pop(&b);
        if (!t)
            break;
    }

    return 0;
}



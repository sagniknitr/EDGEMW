#include <stdio.h>
#include <edgeos_dlist.h>

void print_f(void *data)
{
    printf("%02d ", *((int *)data));
}

int dlist_test(int argc, char **argv)
{
    struct edge_os_dlist_base b;
    int array[141];
    int i;

    edge_os_dlist_init(NULL);

    edge_os_dlist_init(&b);

    for (i = 0; i < 141; i ++) {
        array[i] = i + 1;
        edge_os_dlist_add_tail(&b, &array[i]);
        edge_os_dlist_add_tail(NULL, NULL);
    }

    printf("forward:\n");
    edge_os_dlist_print_forward(&b, print_f);
    edge_os_dlist_print_forward(NULL, NULL);
    printf("\n");

    printf("backward:\n");
    edge_os_dlist_print_backwards(&b, print_f);
    edge_os_dlist_print_backwards(NULL, NULL);
    printf("\n");

    edge_os_dlist_delete(&b, NULL, &array[0]);

    edge_os_dlist_delete(NULL, NULL, NULL);

    edge_os_dlist_delete(&b, NULL, &array[100]);

    edge_os_dlist_delete(&b, NULL, &array[140]);
    edge_os_dlist_delete(&b, NULL, &array[110]);
    edge_os_dlist_delete(&b, NULL, &array[1]);

    printf("forward:\n");
    edge_os_dlist_print_forward(&b, print_f);
    printf("\n");

    edge_os_dlist_free_all(&b, NULL);

    edge_os_dlist_free_all(NULL, NULL);

    return 0;
}



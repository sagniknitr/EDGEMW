#include <stdio.h>
#include <edgeos_static_list.h>

static void print_f(void *data)
{
    printf("%02d ", (*(int*)data));
}

int static_list_test(int argc, char **argv)
{
    struct edge_os_static_list_base b;
    int array[244];
    int i;

    edge_os_static_list_create(&b, 244);

    for (i = 0; i < 244; i ++) {
        array[i] = i + 1;

        edge_os_static_list_add(&b, &array[i]);
    }

    edge_os_static_list_del(&b, NULL, &array[4]);

    printf("dump:\n");
    edge_os_static_list_print(&b, print_f);
    printf("\n");

    edge_os_static_list_free_all(&b, NULL);

    return 0;
}


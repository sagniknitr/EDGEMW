#include <stdio.h>
#include <stdlib.h>
#include <list.h>

static int static_ptr_test()
{
    struct edge_os_list_base b;
    int v = 1;

    edge_os_list_init(&b);

    if (edge_os_list_add_tail(&b, &v))
        return -1;

    return 0;
}

static int dynamic_ptr_test()
{
    struct edge_os_list_base *b;
    int v = 1;

    b = calloc(1, sizeof(struct edge_os_list_base));
    if (!b)
        return -1;

    edge_os_list_init(b);

    if (edge_os_list_add_tail(b, &v)) {
        free(b);
        return -1;
    }

    free(b);

    return 0;
}

static int small_list_test()
{
    return dynamic_ptr_test();
}

static int counter = 0;

static void foreach_f(void *data, void *priv)
{
    counter ++;
}

static int cmp_f(void *data, void *mydata)
{
    int *d = data;
    int *m = mydata;

    if (*d == *m)
        return 1;

    return 0;
}

static void free_f(void *data)
{
}

static int large_list_test()
{
    int array[1044];
    int i;
    struct edge_os_list_base b;

    edge_os_list_init(&b);

    for (i = 0; i < 1000; i ++) {
        array[i] = i;
        if (edge_os_list_add_tail(&b, &array[i]))
            return -1;
    }

    edge_os_list_for_each(&b, foreach_f, NULL);

    if (edge_os_list_find_elem(&b, cmp_f, &array[999]) == 0)
        return -1;

    if (edge_os_list_find_elem(&b, cmp_f, &array[41]) == 0)
        return -1;

    if (edge_os_list_find_elem(&b, cmp_f, &array[0]) == 0)
        return -1;

    array[1004] = 1004;
    if (edge_os_list_find_elem(&b, cmp_f, &array[1004]) == 1)
        return -1;

    edge_os_list_free(&b, free_f);

    if (counter == 1000)
        return 0;

    return -1;
}

int list_test(int argc, char **argv)
{
    if (static_ptr_test())
        return -1;
    if (dynamic_ptr_test())
        return -1;
    if (small_list_test())
        return -1;
    if (large_list_test())
        return -1;

    return 0;
}


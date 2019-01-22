#include <stdio.h>
#include <stdlib.h>
#include <edgeos_list.h>
#include <edgeos_logger.h>

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

    edge_os_list_find_elem(&b, cmp_f, &array[999]);

    edge_os_list_find_elem(&b, cmp_f, &array[41]);

    edge_os_list_find_elem(&b, cmp_f, &array[0]);

    array[1004] = 1004;
    edge_os_list_find_elem(&b, cmp_f, &array[1004]);

    edge_os_list_delete(&b, &array[0], NULL);

    edge_os_list_delete(&b, &array[999], free_f);

    edge_os_list_delete(&b, &array[1004], NULL);

    edge_os_list_free(&b, free_f);

    return 0;
}

int list_test(int argc, char **argv)
{
    edge_os_log("test: starting list_test\n");
    edge_os_list_init(NULL);
    edge_os_list_add_tail(NULL, NULL);
    edge_os_list_delete(NULL, NULL, NULL);
    edge_os_list_for_each(NULL, NULL, NULL);
    edge_os_debug("tests: checking if there is no segfaults ..\n");
    static_ptr_test();
    dynamic_ptr_test();
    small_list_test();
    large_list_test();

    return 0;
}


#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <edgeos_hashtbl.h>

void foreach_p(void *d, void *priv)
{
    char *string = d;

    printf("val %s\n", string);
}

int cmp_cb(void *data, void *given)
{
    char *d = data;
    char *f = given;

    printf("d %s f %s\n", d, f);
    return !strcmp(d, f);
}

int hashtbl_test(int argc, char **argv)
{
    struct edge_os_hash_tbl_base h;
    int ret;

    ret = edge_os_hashtbl_init(&h, 10, edge_os_string_hash);
    if (ret < 0) {
        return -1;
    }

    char strings[][20] = {
        "Hello",
        "djb2",
        "hash",
        "fun",
        "crypto",
        "hash2",
        "ecc",
        "curves",
        "aes",
        "hashes",
    };

    uint32_t i;

    for (i = 0; i < sizeof(strings) / sizeof(strings[0]); i ++) {
        edge_os_hashtbl_add(&h, strings[i]);
    }

    edge_os_hashtbl_delete(&h, NULL, &strings[2]);
    edge_os_hashtbl_foreach(&h, foreach_p, NULL);
    printf("find %p\n", edge_os_hashtbl_find(&h, cmp_cb, &strings[3]));

    edge_os_hashtbl_free(&h, NULL);

    return 0;
}


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

	ret = edge_os_hashtbl_init(NULL, 10, NULL);
	ret = edge_os_hashtbl_add(NULL, NULL);
	ret = edge_os_hashtbl_delete(NULL, NULL, NULL);
	void *data = edge_os_hashtbl_find(NULL, NULL, NULL);
	if (data) {
	}
	ret = edge_os_hashtbl_foreach(NULL, NULL, NULL);
	ret = edge_os_hashtbl_free(NULL, NULL);

	int number = 1201;
	uint8_t ipv6[] = {0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	printf("real numhash : %u\n", edge_os_realnum_hash(&number));
	printf("ipaddr hash: %u\n", edge_os_ipaddr_hash(&number));
	printf("ipv6addr hash: %u\n", edge_os_ip6addr_hash(ipv6));

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


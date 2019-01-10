#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <edgeos_list.h>
#include <edgeos_hashtbl.h>

static uint32_t __edge_os_djb_hash_funct(void *data, int len)
{
    uint8_t *t = data;
    int i;
    uint32_t hash = 5381;

    for (i = 0; i < len; i ++)
        hash = ((hash << 5) + hash) + t[i];

    return hash;
}

// D.J . Bernstein hash funct
uint32_t edge_os_string_hash(void *data)
{
    char *str = data;
    int len = strlen(str);

    return __edge_os_djb_hash_funct(str, len);
}

uint32_t edge_os_realnum_hash(void *data)
{
    uint8_t *rn = data;

    return __edge_os_djb_hash_funct(rn, 4);
}

uint32_t edge_os_ipaddr_hash(void *data)
{
    return edge_os_realnum_hash(data);
}

uint32_t edge_os_ip6addr_hash(void *data)
{
    return __edge_os_djb_hash_funct(data, 16);
}

int edge_os_hashtbl_init(struct edge_os_hash_tbl_base *base, unsigned int buckets,
                            uint32_t (*hash_alg)(void *data))
{
    if (!base || !hash_alg) {
        return -1;
    }

    base->buckets = buckets;
    base->hash_alg = hash_alg;
    base->tables = calloc(buckets, sizeof(struct edge_os_list_base));
    if (!base->tables) {
        return -1;
    }

    return 0;
}

int edge_os_hashtbl_add(struct edge_os_hash_tbl_base *base, void *elem)
{
    if (!base) {
        return -1;
    }

    uint32_t hash_val;

    hash_val = base->hash_alg(elem) % base->buckets;

    edge_os_list_add_tail(&base->tables[hash_val], elem);

    return 0;
}

int edge_os_hashtbl_delete(struct edge_os_hash_tbl_base *base,
                           void (*del_cb)(void *data), void *item)
{
    if (!base || !item) {
        return -1;
    }

    uint32_t hash_val;

    hash_val = base->hash_alg(item) % base->buckets;

    return edge_os_list_delete(&base->tables[hash_val], item, del_cb);
}

void* edge_os_hashtbl_find(struct edge_os_hash_tbl_base *base,
                         int (*cmp_cb)(void *data, void *given),
                         void *given)
{
    if (!base || !cmp_cb) {
        return NULL;
    }

    uint32_t hash_val;

    hash_val = base->hash_alg(given) % base->buckets;

    return edge_os_list_find_elem(&base->tables[hash_val], cmp_cb, given);
}

int edge_os_hashtbl_foreach(struct edge_os_hash_tbl_base *base,
                           void (*foreach_cb)(void *data, void *priv),
                           void *priv)
{
    if (!base || !foreach_cb) {
        return -1;
    }

    uint32_t i;

    for (i = 0; i < base->buckets; i ++) {
        edge_os_list_for_each(&base->tables[i], foreach_cb, priv);
    }

    return 0;
}

int edge_os_hashtbl_free(struct edge_os_hash_tbl_base *base,
                         void (*free_cb)(void *data))
{
    if (!base) {
        return -1;
    }

    uint32_t i;

    for (i = 0; i < base->buckets; i ++) {
        edge_os_list_free(&base->tables[i], free_cb);
    }

    free(base->tables);

    return 0;
}



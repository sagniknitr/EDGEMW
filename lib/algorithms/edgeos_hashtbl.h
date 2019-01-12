#ifndef __EDGEOS_HASHTBL_H__
#define __EDGEOS_HASHTBL_H__

#include <edgeos_list.h>

struct edge_os_hash_tbl_struct {
    void *data;
};

struct edge_os_hash_tbl_base {
    struct edge_os_list_base *tables; // type of tbl_struct
    unsigned int buckets;
    uint32_t (*hash_alg)(void *data);
};

// all the below functions are based off of D.J . Bernstein hash funct
uint32_t edge_os_string_hash(void *data);

uint32_t edge_os_realnum_hash(void *data);

uint32_t edge_os_ipaddr_hash(void *data);

uint32_t edge_os_ip6addr_hash(void *data);

int edge_os_hashtbl_init(struct edge_os_hash_tbl_base *base, unsigned int buckets,
                            uint32_t (*hash_alg)(void *data));

int edge_os_hashtbl_add(struct edge_os_hash_tbl_base *base, void *elem);

int edge_os_hashtbl_delete(struct edge_os_hash_tbl_base *base,
                           void (*del_cb)(void *data), void *item);

int edge_os_hashtbl_foreach(struct edge_os_hash_tbl_base *base,
                           void (*foreach_cb)(void *data, void *priv),
                           void *priv);

void* edge_os_hashtbl_find(struct edge_os_hash_tbl_base *base,
                         int (*cmp_cb)(void *data, void *given),
                         void *given);

int edge_os_hashtbl_free(struct edge_os_hash_tbl_base *base,
                         void (*free_cb)(void *data));


#endif



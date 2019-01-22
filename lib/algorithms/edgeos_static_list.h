#ifndef __EDGEOS_STATIC_LIST_H__
#define __EDGEOS_STATIC_LIST_H__

struct edge_os_static_list {
    void *elem;
    int available;
};

struct edge_os_static_list_base {
    struct edge_os_static_list *list;
    int next_free;
    size_t count;
};

int edge_os_static_list_create(struct edge_os_static_list_base *base, size_t count);

int edge_os_static_list_add(struct edge_os_static_list_base *base, void *elem);

int edge_os_static_list_del(struct edge_os_static_list_base *base,
                            void (*del_cb)(void *data),
                            void *elem);

void edge_os_static_list_print(struct edge_os_static_list_base *base,
                                void (*print_cb)(void *data));

void edge_os_static_list_free_all(struct edge_os_static_list_base *base,
                                  void (*free_cb)(void *data));

void *edge_os_static_list_find(struct edge_os_static_list_base *base,
                               void *given,
                               int (*cmp_cb)(void *data, void *given));

#endif




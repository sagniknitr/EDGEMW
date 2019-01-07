#ifndef __EDGEOS_DLIST_H__
#define __EDGEOS_DLIST_H__

struct edge_os_dlist_struct {
    void *data;
    struct edge_os_dlist_struct *next;
    struct edge_os_dlist_struct *prev;
};

struct edge_os_dlist_base {
    struct edge_os_dlist_struct *head;
    struct edge_os_dlist_struct *tail;
};

int edge_os_dlist_init(struct edge_os_dlist_base *base);

int edge_os_dlist_add_head(struct edge_os_dlist_base *base, void *data);

int edge_os_dlist_add_tail(struct edge_os_dlist_base *base, void *data);

void edge_os_dlist_print_forward(struct edge_os_dlist_base *base,
                            void (*print_cb)(void *data));

void edge_os_dlist_print_backwards(struct edge_os_dlist_base *base,
                            void (*print_cb)(void *data));

void edge_os_dlist_free_all(struct edge_os_dlist_base *base,
                        void (*free_cb)(void *data));

void edge_os_dlist_for_each_forward(struct edge_os_dlist_base *base,
                        void (*for_each_cb)(void *data));

void edge_os_dlist_for_each_backwards(struct edge_os_dlist_base *base,
                        void (*for_each_cb)(void *data));

void *edge_os_dlist_find_elem(struct edge_os_dlist_base *base,
                        int (*cmp_cb)(void *ptr, void *given),
                        void *given);

int edge_os_dlist_delete(struct edge_os_dlist_base *base,
                    void (*delete_cb)(void *ptr),
                    void *given);

#endif


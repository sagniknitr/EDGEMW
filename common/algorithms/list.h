#ifndef __EDGE_LIST_H__
#define __EDGE_LIST_H__

struct edge_os_list {
    void *data;
    struct edge_os_list *next;
};

struct edge_os_list_base {
    struct edge_os_list *head;
    struct edge_os_list *tail;
};


/**
 * @brief - initialise an empty linked list
 *
 * base - passed from the caller. Must be valid.
 *
 * Description-
 * 
 * initialise the head and tail nodes to NULLs.
 *
 * notes:
 * ======
 *
 * library does not fail if nullptr is passed. Caller must be careful
 * to pass a valid pointer
 */
void edge_os_list_init(struct edge_os_list_base *base);
int edge_os_list_add_tail(struct edge_os_list_base *base, void *data);
void edge_os_list_free(struct edge_os_list_base *base,
                      void (*free_callback)(void *data));
int edge_os_list_for_each(struct edge_os_list_base *base,
                          void (*list_for_callback)(void *data, void *priv), void *priv);


#endif


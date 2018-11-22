#include <stdlib.h>
#include <stdio.h>
#include <list.h>

void edge_os_list_init(struct edge_os_list_base *base)
{
    base->tail = NULL;
    base->head = NULL;
}

int edge_os_list_add_tail(struct edge_os_list_base *base, void *data)
{
    struct edge_os_list *new;

    new = calloc(1, sizeof(struct edge_os_list));
    if (!new) {
        return -1;
    }

    new->data = data;
    new->next = NULL;

    if (base->head == NULL) {
        base->head = new;
        base->tail = new;
    } else {
        base->tail->next = new;
        base->tail = new;
    }

    return 0;
}

void edge_os_list_free(struct edge_os_list_base *base,
                      void (*free_callback)(void *data))
{
    struct edge_os_list *t, *t1;

    t = base->head;
    while (t) {
        t1 = t;
        free_callback(t->data);
        t = t->next;
        free(t1);
    }
}

int edge_os_list_for_each(struct edge_os_list_base *base,
                          void (*list_for_callback)(void *data, void *priv),
                          void *priv)
{
    struct edge_os_list *t  = base->head;

    while (t) {
        list_for_callback(t->data, priv);
        t = t->next;
    }

    return 0;
}


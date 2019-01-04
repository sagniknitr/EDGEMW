#include <stdlib.h>
#include <stdio.h>
#include <list.h>

void edge_os_list_init(struct edge_os_list_base *base)
{
    if (!base)
        return;

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

int edge_os_list_delete(struct edge_os_list_base *base,
                        void *item,
                        void (*free_callback)(void *data))
{
    struct edge_os_list *t;
    struct edge_os_list *t_old;

    t = t_old = base->head;

    if (t->data == item) {
        base->head = t->next;
        if (base->tail == t)
            base->tail = t->next;

        if (free_callback)
            free_callback(t->data);

        free(t);

        return 1;
    }

    t = t_old = base->head;

    while (t) {
        if (t->data == item) {
            t_old->next = t->next;

            if (t_old->next == NULL) {
                base->tail = t_old;
                base->tail->next = NULL;
            }

            if (free_callback)
                free_callback(t->data);

            free(t);

            return 1;
        }
        t_old = t;
        t = t->next;
    }

    return 0;
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

void *edge_os_list_find_elem(struct edge_os_list_base *base,
                           int (*cmpare_cb)(void *data, void *given),
                           void *given)
{
    struct edge_os_list *t = base->head;

    while (t) {
        if (cmpare_cb(t->data, given))
            return t->data;

        t = t->next;
    }

    return NULL;
}



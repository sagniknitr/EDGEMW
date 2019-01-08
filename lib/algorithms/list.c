#include <stdlib.h>
#include <stdio.h>
#include <edgeos_list.h>
#include <edgeos_logger.h>

void edge_os_list_init(struct edge_os_list_base *base)
{
    if (!base) {
        edge_os_error("list: invalid base ptr %p @ %s %u\n",
                            base, __func__, __LINE__);
        return;
    }

    base->tail = NULL;
    base->head = NULL;
}

int edge_os_list_add_tail(struct edge_os_list_base *base, void *data)
{
    struct edge_os_list *new;

    if (!base) {
        edge_os_error("list: invalid base ptr %p @ %s %u\n",
                            base, __func__, __LINE__);
        return -1;
    }

    new = calloc(1, sizeof(struct edge_os_list));
    if (!new) {
        edge_os_error("failed to allocate @ %s %u\n", __func__, __LINE__);
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

        // call free_callback() of the caller
        if (free_callback)
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

    if (!base) {
        edge_os_error("list: invalid base ptr %p @ %s %u\n",
                                base, __func__, __LINE__);
        return -1;
    }

    t = t_old = base->head;

    if (t->data == item) {
        base->head = t->next;
        if (base->tail == t)
            base->tail = t->next;

        // call the free_callback() of the call
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

    if (!base || !list_for_callback) {
        edge_os_error("list: invalid base ptr %p / list_for_callback ptr %p @ %s %u\n",
                            base, list_for_callback, __func__, __LINE__);
        return -1;
    }

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

    if (!base || !cmpare_cb) {
        edge_os_error("list: invalid base ptr %p / cmpare_cb ptr %p @ %s %u\n",
                            base, cmpare_cb, __func__, __LINE__);
        return NULL;
    }

    while (t) {
        if (cmpare_cb(t->data, given))
            return t->data;

        t = t->next;
    }

    return NULL;
}



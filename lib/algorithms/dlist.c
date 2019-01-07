#include <stdlib.h>
#include <stdio.h>
#include <edgeos_dlist.h>

int edge_os_dlist_init(struct edge_os_dlist_base *base)
{
    if (!base)
        return -1;

    base->head = NULL;
    base->tail = NULL;

    return 0;
}

int edge_os_dlist_add_head(struct edge_os_dlist_base *base, void *data)
{
    if (!base)
        return -1;

    struct edge_os_dlist_struct *t;

    t = calloc(1, sizeof(struct edge_os_dlist_struct));
    if (!t) {
        return -1;
    }

    t->data = data;

    if (!base->head) {
        base->head = t;
        base->tail = t;
    } else {
        t->next = base->head;
        base->head = t;
    }

    return 0;
}

int edge_os_dlist_add_tail(struct edge_os_dlist_base *base, void *data)
{
    if (!base)
        return -1;

    struct edge_os_dlist_struct *t;

    t = calloc(1, sizeof(struct edge_os_dlist_struct));
    if (!t) {
        return -1;
    }

    t->data = data;

    if (!base->head) {
        base->head = t;
        base->tail = t;
    } else {
        base->tail->next = t;
        t->prev = base->tail;
        base->tail = t;
    }

    return 0;
}

void edge_os_dlist_print_forward(struct edge_os_dlist_base *base,
                            void (*print_cb)(void *data))
{
    if (!base || !print_cb)
        return;

    struct edge_os_dlist_struct *t;

    for (t = base->head; t; t = t->next) {
        print_cb(t->data);
    }
}

void edge_os_dlist_print_backwards(struct edge_os_dlist_base *base,
                            void (*print_cb)(void *data))
{
    if (!base || !print_cb)
        return;

    struct edge_os_dlist_struct *t;

    for (t = base->tail; t; t = t->prev) {
        print_cb(t->data);
    }
}

void edge_os_dlist_free_all(struct edge_os_dlist_base *base,
                        void (*free_cb)(void *data))
{
    if (!base)
        return;

    struct edge_os_dlist_struct *t;
    struct edge_os_dlist_struct *t2;

    t = t2 = base->head;

    while (t) {
        t2 = t;
        t = t->next;
        if (free_cb)
            free_cb(t->data);

        free(t2);
    }
}

void edge_os_dlist_for_each_forward(struct edge_os_dlist_base *base,
                        void (*for_each_cb)(void *data))
{
    if (!base || !for_each_cb)
        return;

    struct edge_os_dlist_struct *t;

    for (t = base->head; t; t = t->next) {
        for_each_cb(t->data);
    }
}

void edge_os_dlist_for_each_backwards(struct edge_os_dlist_base *base,
                        void (*for_each_cb)(void *data))
{
    if (!base || !for_each_cb)
        return;

    struct edge_os_dlist_struct *t;

    for (t = base->tail; t; t = t->next) {
        for_each_cb(t->data);
    }
}

void *edge_os_dlist_find_elem(struct edge_os_dlist_base *base,
                        int (*cmp_cb)(void *ptr, void *given),
                        void *given)
{
    if (!base || !cmp_cb)
        return NULL;

    struct edge_os_dlist_struct *t;

    for (t = base->head; t;  t = t->next) {
        if (cmp_cb(t->data, given))
            return t->data;
    }

    return NULL;
}

int edge_os_dlist_delete(struct edge_os_dlist_base *base,
                    void (*delete_cb)(void *ptr),
                    void *given)
{
    if (!base)
        return 0;

    struct edge_os_dlist_struct *t;
    struct edge_os_dlist_struct *t2;

    t = t2 = base->head;

    if (t->data == given) {
        if (delete_cb)
            delete_cb(t->data);

        base->head = base->head->next;
        // only first element in the list
        if (base->tail == base->head) {
            base->tail = base->head->next;
        }

        free(t);

        return 1;
    }

    while (t) {
        if (t->data == given) {
            if (delete_cb)
                delete_cb(t->data);

            t2->next = t->next;
            if (t->next)
                t->next->prev = t2;

            if (t == base->tail) {
                base->tail = t->prev;
                base->tail->next = NULL;
            }

            free(t);

            return 1;
        }
        t2 = t;
        t = t->next;
    }

    return 0;
}



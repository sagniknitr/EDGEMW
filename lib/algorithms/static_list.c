#include <stdlib.h>
#include <stdio.h>
#include <edgeos_static_list.h>

int edge_os_static_list_create(struct edge_os_static_list_base *base, size_t count)
{
    size_t i;

    base->list = calloc(count, sizeof(struct edge_os_static_list));
    if (!base->list) {
        return -1;
    }

    for (i = 0; i < count ; i ++) {
        base->list[i].available = 1;
        base->list[i].elem = NULL;
    }

    base->count = count;
    base->next_free = 0;

    return 0;
}

int edge_os_static_list_add(struct edge_os_static_list_base *base, void *elem)
{
    size_t i;
    int item = -1;

    if (base->next_free != -1) {
        item = base->next_free;
    } else {
        for (i = 0; i < base->count; i ++) {
            if (base->list[i].available) {
                item = i;
                break;
            }
        }
    }

    if (item == -1)
        return -1;

    base->list[item].elem = elem;
    base->list[item].available = 0;

    base->next_free = (base->next_free + 1) % base->count;
    if (base->list[base->next_free].available) {
        return 0;
    }

    base->next_free = -1;

    if (((size_t)(item + 1) < base->count) &&
        ((item - 1) > 0)) {
        if (base->list[item + 1].available) {
            base->next_free = item + 1;
            return 0;
        } else {
            base->next_free = -1;
        }

        if (base->list[item - 1].available) {
            base->next_free = item - 1;
            return 0;
        } else {
            base->next_free = -1;
        }
    }

    return 0;
}

int edge_os_static_list_del(struct edge_os_static_list_base *base,
                            void (*del_cb)(void *data),
                            void *elem)
{
    size_t i;

    for (i = 0; i < base->count; i ++) {
        if (!base->list[i].available && (base->list[i].elem == elem)) {
            if (del_cb)
                del_cb(base->list[i].elem);

            base->list[i].available = 1;
            base->list[i].elem = NULL;
            base->next_free = i;

            return 0;
        }
    }

    return -1;
}

void edge_os_static_list_print(struct edge_os_static_list_base *base,
                                void (*print_cb)(void *data))
{
    size_t i;

    if (!base || !print_cb)
        return;

    for (i = 0; i < base->count; i ++) {
        if (!base->list[i].available)
            print_cb(base->list[i].elem);
    }
}

void edge_os_static_list_free_all(struct edge_os_static_list_base *base,
                                  void (*free_cb)(void *data))
{
    size_t i;

    if (!base)
        return;

    for (i = 0; i < base->count; i ++) {
        if (free_cb && !base->list[i].available)
            free_cb(base->list[i].elem);

        base->list[i].available = 1;
        base->list[i].elem = NULL;
    }

    base->next_free = 0;
    free(base->list);
}

void *edge_os_static_list_find(struct edge_os_static_list_base *base,
                               void *given,
                               int (*cmp_cb)(void *data, void *given))
{
    size_t i;

    for (i = 0; i < base->count; i ++) {
        if (!base->list[i].available && cmp_cb(base->list[i].elem, given))
            return base->list[i].elem;
    }

    return NULL;
}



#include <stdlib.h>
#include <stdio.h>
#include <edgeos_queue.h>

int edge_os_queue_init(struct edge_os_queue_base *base)
{
    if (!base)
        return -1;

    base->head = NULL;
    base->tail = NULL;

    return 0;
}

int edge_os_queue_enque(struct edge_os_queue_base *base, void *data)
{
    if (!base)
        return -1;

    struct edge_os_queue_struct *t;

    t = calloc(1, sizeof(struct edge_os_queue_struct));
    if (!t) {
        return -1;
    }

    t->data = data;

    if (!base->head) {
        base->head = t;
        base->tail = t;
    } else {
        base->tail->next = t;
        base->tail = t;
    }

    return 0;
}

void *edge_os_queue_deque(struct edge_os_queue_base *base)
{
    if (!base)
        return NULL;

    struct edge_os_queue_struct *t;
    void *data;

    if (!base->head)
        return NULL;

    data = base->head->data;

    t = base->head;
    base->head = base->head->next;
    if (base->head == NULL)
        base->tail = NULL;

    free(t);

    return data;
}


#include <stdlib.h>
#include <stdio.h>
#include <edgeos_stack.h>

int edge_os_stack_init(struct edge_os_stack_base *base)
{
    if (!base)
        return -1;

    base->head = NULL;
    base->tail = NULL;

    return 0;
}

int edge_os_stack_push(struct edge_os_stack_base *base, void *data)
{
    if (!base)
        return -1;

    struct edge_os_stack_ptr *t;

    t = calloc(1, sizeof(struct edge_os_stack_ptr));
    if (!t)
        return -1;

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

void* edge_os_stack_pop(struct edge_os_stack_base *base)
{
    struct edge_os_stack_ptr *t;

    if (!base)
        return NULL;

    if (!base->tail)
        return NULL;

    void *ptr = base->tail->data;

    t = base->tail;


    base->tail = base->tail->prev;

    if (base->tail == NULL)
        base->head = NULL;

    free(t);

    return ptr;
}




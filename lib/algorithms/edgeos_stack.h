#ifndef __EDGEOS_STACK_H__
#define __EDGEOS_STACK_H__


struct edge_os_stack_ptr {
    void *data;
    struct edge_os_stack_ptr *next;
    struct edge_os_stack_ptr *prev;
};

struct edge_os_stack_base {
    struct edge_os_stack_ptr *head;
    struct edge_os_stack_ptr *tail;
};

int edge_os_stack_init(struct edge_os_stack_base *base);

int edge_os_stack_push(struct edge_os_stack_base *base, void *data);

void* edge_os_stack_pop(struct edge_os_stack_base *base);



#endif



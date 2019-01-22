#ifndef __EDGEOS_QUEUE_H__
#define __EDGEOS_QUEUE_H__

struct edge_os_queue_struct {
    void *data;
    struct edge_os_queue_struct *next;
};

struct edge_os_queue_base {
    struct edge_os_queue_struct *head;
    struct edge_os_queue_struct *tail;
};


int edge_os_queue_init(struct edge_os_queue_base *base);

int edge_os_queue_enque(struct edge_os_queue_base *base, void *data);

void *edge_os_queue_deque(struct edge_os_queue_base *base);

#endif



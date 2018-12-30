#include <stdio.h>

struct queue_struct {
    void *base;
    struct queue_struct *next;
};

struct queue_base {
    struct queue_struct *head;
    struct queue_struct *tail;
};


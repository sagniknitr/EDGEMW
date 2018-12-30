#include <stdio.h>

struct dlist_struct {
    void *data;
    struct dlist_struct *next;
    struct dlist_struct *prev;
};

struct dlist_base {
    struct dlist_struct *head;
    struct dlist_struct *tail;
};


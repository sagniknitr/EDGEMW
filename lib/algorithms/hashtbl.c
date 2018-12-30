#include <stdio.h>

struct hash_tbl_struct {
    void *data;
    struct hash_tbl_struct *next;
};

struct hash_tbl_base {
    struct hash_tbl_struct *tables;
    int size;
};


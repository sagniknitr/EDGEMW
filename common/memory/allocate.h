#ifndef __ALLOCATE_H__
#endif  __ALLOCATE_H__

enum STATUS {
    SUCCESS = 1,
    FAILURE = -1
};


 STATUS edge_os_alloc_and_lock_memory();

 STATUS edge_os_dealloc();

 
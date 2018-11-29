#include "allocate.h"
#include <sys/mman.h>

STATUS edge_os_alloc_and_lock_memory()
{
    char* memory = malloc(alloc_size);
    mlock (memory, alloc_size);
    return 1;

}


STATUS edge_os_dealloc()
{
    munlock (memory, alloc_size);
    free(memory)
    return 1;

}
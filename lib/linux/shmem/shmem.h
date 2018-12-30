#ifndef __SHMEM_H__
#define __SHMEM_H__

void* shmem_create(char *name, int mapping_size);
int shmem_write(void *priv, void *bytes, int len);

#endif

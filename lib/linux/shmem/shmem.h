#ifndef __SHMEM_H__
#define __SHMEM_H__

typedef enum {
    SHMEM_FILE_FULL = 1,
} shmem_file_types_t;

void* shmem_create(char *name, int mapping_size);
void* shmem_create_file_mmap(const char *filename, const char *mode, int file_size);
void* shmem_open_file_mmap(const char *filename, const char *mode, int file_size);
int shmem_write(void *priv, void *bytes, int len);
void* shmem_read(void *priv, int *len);
int shmem_close(void *priv);

#endif

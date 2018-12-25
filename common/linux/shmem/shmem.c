#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

typedef enum {
    SHMEM_MODE_RDONLY    = 1,
    SHMEM_MODE_RDWR      = 2,
} shmem_mode_t;

struct shmem_priv {
    int shmfd;
    void *map;
    int off;
    int mapping_size;
};

void* shmem_create(char *name, int mapping_size)
{
    struct shmem_priv *priv;
    int ret;

    priv = calloc(1, sizeof(struct shmem_priv));
    if (!priv) {
        return NULL;
    }

    priv->shmfd = shm_open(name, O_RDWR | O_CREAT, S_IRWXU);
    if (priv->shmfd < 0) {
        return NULL;
    }

    ret = ftruncate(priv->shmfd, mapping_size);
    if (ret < 0) {
        return NULL;
    }

    priv->map = mmap(NULL, mapping_size, PROT_READ | PROT_WRITE,
                     MAP_SHARED, priv->shmfd, 0);
    if (!priv->map) {
        return NULL;
    }

    priv->mapping_size = mapping_size;
    priv->off = 0;

    return priv;
}

// link this with locks !
int shmem_write(void *priv, void *bytes, int len)
{
    struct shmem_priv *handle = priv;

    if (handle->off + len > handle->mapping_size) {
        return -1;
    }

    memcpy(handle->map + handle->off, bytes, len);
    handle->off += len;

    return len;
}

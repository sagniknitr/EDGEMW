#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <edgeos_logger.h>

typedef enum {
    SHMEM_MODE_RDONLY    = 1,
    SHMEM_MODE_RDWR      = 2,
} shmem_mode_t;

struct shmem_priv {
    int shmfd;
    int fd;
    void *map;
    int off;
    int mapping_size;
};

void* __shmem_create(const char *name, int new_file, const char *mode, int mapping_size)
{
    struct shmem_priv *priv;
    int ret;

    if (!name || !mode || (mapping_size <= 0)) {
        edge_os_error("shmem: invalid name / mode / mapping_size @ %s %u\n",
                                __func__, __LINE__);
        return NULL;
    }

    priv = calloc(1, sizeof(struct shmem_priv));
    if (!priv) {
        edge_os_error("shmem: failed to allocate @ %s %u\n",
                                __func__, __LINE__);
        return NULL;
    }

    int open_flags = 0;

    if (new_file)
        open_flags |= O_CREAT;

    if (!strcmp(mode, "r")) {
        open_flags |= O_RDONLY;
    } else if (!strcmp(mode, "w")) {
        open_flags |= O_WRONLY;
    } else if (!strcmp(mode, "rw")) {
        open_flags |= O_RDWR;
    } else if (!strcmp(mode, "a")) {
        open_flags |= O_APPEND;
    } else {
        goto bad;
    }

    if (new_file) {
        priv->fd = open(name, open_flags, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    } else {
        priv->fd = open(name, open_flags);
    }

    if (priv->fd < 0) {
        edge_os_log_with_error(errno, "shmem: failed to open file @ %s %u ",
                                    __func__, __LINE__);
        goto bad;
    }

    ret = ftruncate(priv->fd, mapping_size);
    if (ret < 0) {
        edge_os_log_with_error(errno, "shmem: failed to ftruncate @ %s %u ",
                                __func__, __LINE__);
        goto bad;
    }

    priv->map = mmap(NULL, mapping_size, PROT_READ | PROT_WRITE,
                     MAP_SHARED, priv->fd, 0);
    if (!priv->map) {
        edge_os_log_with_error(errno, "shmem: failed to mmap @ %s %u ",
                                __func__, __LINE__);
        goto bad;
    }

    priv->mapping_size = mapping_size;
    priv->off = 0;

    return priv;

bad:

    if (priv->fd > 0)
        close(priv->fd);

    free(priv);
    return NULL;
}

void* shmem_create_file_mmap(const char *filename, const char *mode, int file_size)
{
    return __shmem_create(filename, 1, mode, file_size);
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


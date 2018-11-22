#include <stdio.h>
#include <net_socket.h>
#include <shmem.h>
#include <list.h>
#include <stdlib.h>
#include <string.h>
#include <evtloop.h>

struct shm_transport_pub_priv {
    char *shmem_name;
    char *pubname;
    void *shmem;
    int netfd;
};

struct shm_transport_priv {
    int fd;
    struct edge_os_evtloop_base base;
    struct edge_os_list_base *pub_list_head;
};

void *shmtransport_init()
{
    struct shm_transport_priv *priv;
    int ret;

    priv = calloc(1, sizeof(struct shm_transport_priv));
    if (!priv) {
        return NULL;
    }

    ret = edge_os_evtloop_init(&priv->base, NULL);
    if (ret) {
        return NULL;
    }

    return priv;
}

void *shmtransport_create_pub(void *tr_priv, char *shmem_name, char *pub_name, int mapping_size)
{
    struct shm_transport_priv *priv = tr_priv;
    struct shm_transport_pub_priv *pub;

    pub = calloc(1, sizeof(struct shm_transport_pub_priv));
    if (!pub) {
        return NULL;
    }

    pub->shmem = shmem_create(shmem_name, mapping_size);
    if (!pub->shmem) {
        return NULL;
    }

    pub->pubname = strdup(pub_name);

    edge_os_list_add_tail(priv->pub_list_head, pub);
    return pub;
}

int shmtransport_publish(void *tr_pub, void *data, int len)
{
    struct shm_transport_pub_priv *pub = tr_pub;

    return shmem_write(pub->shmem, data, len);
}

static void shm_transport_callback(void *callback_data)
{

}

int main()
{
    struct shm_transport_priv *priv;

    priv = shmtransport_init();
    if (!priv) {
        return -1;
    }

    priv->fd = create_unix_server("/tmp/shm_controller");
    if (priv->fd < 0) {
        return -1;
    }

    edge_os_evtloop_register_socket(&priv->base, priv, priv->fd, shm_transport_callback);
    
    return 0;
}

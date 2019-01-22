#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <mqueue.h>

struct edge_os_mq_priv {
    char *queue_id;
    int the_owner;
    mqd_t q;
};

void *edge_os_mq_create(const char *name, size_t queue_length, size_t msg_size)
{
    struct mq_attr attr;
    struct edge_os_mq_priv *priv;

    priv = calloc(1, sizeof(struct edge_os_mq_priv));
    if (!priv) {
        return NULL;
    }


    if ((queue_length > 0) && (msg_size > 0)) {
        memset(&attr, 0, sizeof(attr));

        attr.mq_flags = 0;
        attr.mq_maxmsg = queue_length;
        attr.mq_msgsize = msg_size;

        priv->q = mq_open(name, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP, &attr);
    } else {
        priv->q = mq_open(name, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP, NULL);
    }

    if (priv->q == (mqd_t)-1) {
        goto bad;
    }

    priv->the_owner = 1;

    priv->queue_id = strdup(name);

    return priv;

bad:
    free(priv);

    return NULL;
}

struct edge_os_mqattr_r {
    // the nonblock is removed
    size_t mq_maxmsgs;
    size_t mq_msgsize;
    size_t mq_curmsgs;
};

int edge_os_get_mq_wait_fd(void *priv)
{
    struct edge_os_mq_priv *q = priv;

    return (int)(q->q);
}

void *edge_os_mq_open(const char *name)
{
    struct edge_os_mq_priv *priv;

    priv = calloc(1, sizeof(struct edge_os_mq_priv));
    if (!priv) {
        return NULL;
    }

    priv->q = mq_open(name, O_RDWR);
    if (priv->q == (mqd_t)-1) {
        goto bad;
    }

    priv->the_owner = 0;

    return priv;

bad:
    free(priv);
    return NULL;
}

int edge_os_mq_getattr(void *priv, struct edge_os_mqattr_r *attr)
{
    int ret;
    struct mq_attr qattr;
    struct edge_os_mq_priv *q = priv;

    ret = mq_getattr(q->q, &qattr);
    if (ret < 0) {
        return -1;
    }

    attr->mq_maxmsgs = qattr.mq_maxmsg;
    attr->mq_msgsize = qattr.mq_msgsize;
    attr->mq_curmsgs = qattr.mq_curmsgs;

    return 0;
}

int edge_os_mq_send(void *priv, const char *data, size_t length, uint32_t prio)
{
    struct edge_os_mq_priv *q = priv;
    int ret;

    ret = mq_send(q->q, data, length, prio);
    if (ret < 0) {
        return -1;
    }

    return 0;
}

int edge_os_mq_receive(void *priv, char *data, size_t length, uint32_t *prio)
{
    struct edge_os_mq_priv *q = priv;
    int ret;

    ret = mq_receive(q->q, data, length, prio);
    if (ret < 0) {
        return -1;
    }

    return 0;
}

void edge_os_mq_delete(void *priv)
{
    struct edge_os_mq_priv *q = priv;

    mq_close(q->q);
    mq_unlink(q->queue_id);
    free(q->queue_id);
    free(q);
}




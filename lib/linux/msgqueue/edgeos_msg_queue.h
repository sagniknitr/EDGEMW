#ifndef __EDGEOS_MSG_QUEUE_H__
#define __EDGEOS_MSG_QUEUE_H__

struct edge_os_mqattr_r {
    // the nonblock is removed
    size_t mq_maxmsgs;
    size_t mq_msgsize;
    size_t mq_curmsgs;
};

void *edge_os_mq_create(const char *name, size_t queue_length, size_t msg_size);

int edge_os_get_mq_wait_fd(void *priv);

void *edge_os_mq_open(const char *name);

int edge_os_mq_getattr(void *priv, struct edge_os_mqattr_r *attr);

int edge_os_mq_send(void *priv, const char *data, size_t length, uint32_t prio);

int edge_os_mq_receive(void *priv, char *data, size_t length, uint32_t *prio);

void edge_os_mq_delete(void *priv);


#endif




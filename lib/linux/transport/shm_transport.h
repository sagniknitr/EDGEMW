#ifndef __SH_TSPORT_H__
#define __SH_TSPORT_H__

typedef enum {
    SHMCTRL_CREATE_SHMEM_REQ,
    SHMCTRL_CREATE_SHMEM_RESP,

    SHMCTRL_OPEN_SHMEM_REQ,
    SHMCTRL_OPEN_SHMEM_RESP,

    SHMCTRL_READ_SHMEM_REQ,
    SHMCTRL_READ_SHMEM_RESP,

    SHMCTRL_WRITE_SHMEM_REQ,
    SHMCTRL_WRITE_SHMEM_RESP,

    SHMCTRL_DESTROY_SHMEM_REQ,
    SMHCTRL_DESTROY_SHMEM_RESP,

    SHMCTRL_DIST_LOCK_REQ,
    SHMCTRL_DIST_LOCK_RESP,

    SHMCTRL_DIST_UNLOCK_REQ,
    SHMCTRL_DIST_UNLCOK_RESP,
} transport_ctrl_t;

struct shm_tsport_create_mem_req {
    char name[20];
    int memsize_bytes;
} __attribute__((__packed__));

struct shm_tsport_create_mem_resp {
    char name[20];
    long memaddr;
} __attribute__((__packed__));

struct shm_tsport_ctrl_msg {
    transport_ctrl_t transport_ctrl;
    uint8_t data[0];
} __attribute__((__packed__));

#endif

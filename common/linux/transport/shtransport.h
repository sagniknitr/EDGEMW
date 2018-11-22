#ifndef __SH_TSPORT_H__
#define __SH_TSPORT_H__

typedef enum {
    SHMCTRL_DIST_LOCK,
    SHMCTRL_DIST_UNLOCK,
} transport_ctrl_t;

struct sh_tsport_ctrl_msg {
    transport_ctrl_t transport_ctrl;
} __attribute__((__packed__));

#endif

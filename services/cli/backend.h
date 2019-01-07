#ifndef __EDGE_OS_CLI_BACKEND_H__
#define __EDGE_OS_CLI_BACKEND_H__

#include <edge_os.h>

struct edge_os_cli_service_priv {
    int fd;
    struct edge_os_evtloop_base base;
};

#endif


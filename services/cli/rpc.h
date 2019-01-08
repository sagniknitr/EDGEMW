#ifndef __EDGEOS_CLI_RPC_H__
#define __EDGEOS_CLI_RPC_H__

typedef enum {
    EDGE_OS_CLI_RPC_CLI_VERSION_REQ = 1,
    EDGE_OS_CLI_RPC_CLI_VERSION_RESP,
} edge_os_cli_command_t;

struct edge_os_cli_rpc {
    edge_os_cli_command_t command;
    char value[0];
} __attribute__((__packed__));

#endif


#ifndef __EOS_CONFIG_H__
#define __EOS_CONFIG_H__

struct edge_os_logger_config {
    char logger_ip[80];
    int logger_port;
};

struct edge_os_config {
    struct edge_os_logger_config logger_config;
};

#endif


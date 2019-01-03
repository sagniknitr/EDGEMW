#ifndef __EDGEOS_CONFIG_PARSER_H__
#define __EDGEOS_CONFIG_PARSER_H__

struct config_parse_set {
    char var[64];
    char val[256];
    struct config_parse_set *next;
};

void edge_os_config_free(struct config_parse_set *set);

struct config_parse_set *edge_os_config_parse(const char *filename);

void edge_os_config_parser_print(struct config_parse_set *set);

#endif


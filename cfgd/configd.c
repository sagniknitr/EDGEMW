#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "debug.h"

struct configd_config {
    char *var_val;
    struct configd_config *next;
};

struct configd_priv {
    struct configd_config *config_head;
};

#define CONFIGD_CONFIG_FILE_PATH "./config.ds"

static int configd_parse_ds(char *config_path)
{
    FILE *fp;

    fp = fopen(config_path, "r");
    if (!fp) {
        MWOS_ERR("configd: failed to open config file %s @ %s %u\n",
                         config_path, __func__, __LINE__);
        return -1;
    }

    struct configd_config *config_head = NULL, *config_tail = NULL;
    char line[2000];

    while (fgets(line, sizeof(line), fp)) {
        struct configd_config *config_n;

        line[strlen(line) - 1] = '\0';

        config_n = calloc(1, sizeof(struct configd_config));
        if (!config_n) {
            MWOS_ERR("configd: failed to allocate @ %s %u\n",
                          __func__, __LINE__);
            return -1;
        }
        config_n->var_val = calloc(1, strlen(line) + 1);
        if (!config_n->var_val) {
            MWOS_ERR("configd: failed to allocate @ %s %u\n",
                          __func__, __LINE__);
            return -1;
        }

        strcpy(config_n->var_val, line);

        if (!config_head) {
            config_head = config_n;
            config_tail = config_n;
        } else {
            config_tail->next = config_n;
            config_tail = config_n;
        }
    }

    fclose(fp);

    return 0;
}

int main(int argc, char **argv)
{
    char *config_path = CONFIGD_CONFIG_FILE_PATH;
    int ret;

    if (argc == 2) {
        config_path = argv[1];
    }

    ret = configd_parse_ds(config_path);
    if (ret != 0) {
        MWOS_ERR("configd: failed to parse config %s @ %s %u\n",
                                   config_path, __func__, __LINE__);
        return ret;
    }

    return 0;
}


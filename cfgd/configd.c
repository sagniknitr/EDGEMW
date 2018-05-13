#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "debug.h"

struct configd_config {
    char *var;
    char *val;
    struct configd_config *next;
};

struct configd_priv {
    struct configd_config *config_head;
};

#define CONFIGD_CONFIG_FILE_PATH "./config.ds"

/**
 * @brief - parse a configuration database store
 */
static int configd_parse_ds(char *config_path, struct configd_priv *priv)
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

    memset(line, 0, sizeof(line));
    while (fgets(line, sizeof(line), fp)) {
        struct configd_config *config_n;
        char var[200], val[200];
        int i = 0, j = 0;

        line[strlen(line) - 1] = '\0';

        // ignore the comments
        if (line[0] == '#') {
            continue;
        }

        // parse var section
        memset(var, 0, sizeof(var));
        while (line[i] != '\0') {
            if (((line[i] == '=') || (line[i] == ' '))) {
                break;
            }
            var[i] = line[i];
            i ++;
        }
        var[i] = '\0';
        i ++;

        // strip space
        while (line[i] == ' ') {
            i ++;
        }

        // parse val section
        memset(val, 0, sizeof(val));
        while (line[i] != '\0') {
            if ((line[i] == ' ') || (line[i] == '#')) {
                break;
            }
            val[j] = line[i];
            j ++;
            i ++;
        }
        val[j] = '\0';

        //printf("var '%s' val '%s'\n", var, val);

        // setup database into memory
        config_n = calloc(1, sizeof(struct configd_config));
        if (!config_n) {
            MWOS_ERR("configd: failed to allocate @ %s %u\n",
                          __func__, __LINE__);
            return -1;
        }
        config_n->var = calloc(1, strlen(var) + 1);
        if (!config_n->var) {
            MWOS_ERR("configd: failed to allocate @ %s %u\n",
                          __func__, __LINE__);
            return -1;
        }

        config_n->val = calloc(1, strlen(val) + 1);
        if (!config_n->val) {
            MWOS_ERR("configd: failed to allocate @ %s %u\n",
                          __func__, __LINE__);
            return -1;
        }

        strcpy(config_n->var, var);
        strcpy(config_n->val, val);

        if (!config_head) {
            config_head = config_n;
            config_tail = config_n;
        } else {
            config_tail->next = config_n;
            config_tail = config_n;
        }
        memset(line, 0, sizeof(line));
    }

    priv->config_head = config_head;
    fclose(fp);

    return 0;
}

void configd_print_db(struct configd_priv *priv)
{
    struct configd_config *config;

    for (config = priv->config_head; config; config = config->next) {
        printf("var '%s' val '%s'\n", config->var, config->val);
    }
}

int main(int argc, char **argv)
{
    struct configd_priv *priv;
    char *config_path = CONFIGD_CONFIG_FILE_PATH;
    int ret;

    priv = calloc(1, sizeof(struct configd_priv));
    if (!priv) {
        MWOS_ERR("configd: failed to allocate @ %s %u\n",
                    __func__, __LINE__);
        return -1;
    }

    if (argc == 2) {
        config_path = argv[1];
    }

    ret = configd_parse_ds(config_path, priv);
    if (ret != 0) {
        MWOS_ERR("configd: failed to parse config %s @ %s %u\n",
                                   config_path, __func__, __LINE__);
        return ret;
    }

    //configd_print_db(priv);

    return 0;
}


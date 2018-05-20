extern "C" {
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include "debug.h"
#include "perf.h"

struct configd_config {
    char *var;
    char *val;
    struct configd_config *next;
};

struct configd_priv {
    void *perf_handle;
    void *cfg_context;
    struct configd_config *config_head;
};

static int test_mode = 0;

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
            memset(line, 0, sizeof(line));
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
        while ((line[i] == ' ') || (line[i] == '=')) {
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
        config_n = (struct configd_config *)calloc(1, sizeof(struct configd_config));
        if (!config_n) {
            MWOS_ERR("configd: failed to allocate @ %s %u\n",
                          __func__, __LINE__);
            return -1;
        }
        config_n->var = (char *)calloc(1, strlen(var) + 1);
        if (!config_n->var) {
            MWOS_ERR("configd: failed to allocate @ %s %u\n",
                          __func__, __LINE__);
            return -1;
        }

        config_n->val = (char *)calloc(1, strlen(val) + 1);
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
    char config_path[200] = "./config.ds";
    char perf_event_config_read[] = "cfg_read";
    int ret;

    while ((ret = getopt(argc, argv, "tf:")) != -1) {
        switch (ret) {
            case 't':
                test_mode = 1;
            break;
            case 'f':
                strncpy(config_path, optarg, sizeof(config_path));
            break;
        }
    }

    priv = (struct configd_priv *)calloc(1, sizeof(struct configd_priv));
    if (!priv) {
        MWOS_ERR("configd: failed to allocate @ %s %u\n",
                    __func__, __LINE__);
        return -1;
    }

    priv->perf_handle = mwos_perf_init(2);
    if (!priv->perf_handle) {
        return -1;
    }

    priv->cfg_context = mwos_perf_create_context(priv->perf_handle, perf_event_config_read);
    if (!priv->cfg_context) {
        return -1;
    }

    mwos_perf_ctx_record_start(priv->cfg_context);
    ret = configd_parse_ds(config_path, priv);
    if (ret != 0) {
        MWOS_ERR("configd: failed to parse config %s @ %s %u\n",
                                   config_path, __func__, __LINE__);
        return ret;
    }
    mwos_perf_ctx_record_end(priv->cfg_context);

    struct perf_stats stats;

    mwos_perf_stats_get(priv->cfg_context, &stats);

    printf("last sample: sec: %ju nsec: %ju mean: %f variance: %f stddev: %f\n",
                    stats.last_sample.tv_sec, stats.last_sample.tv_nsec,
                    stats.mean, stats.variance, stats.standard_devi);

    if (test_mode) {
        configd_print_db(priv);
    }

    return 0;
}

}


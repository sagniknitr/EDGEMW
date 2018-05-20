extern "C" {

#include <math.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include "perf.h"

struct perf_context {
    int available;
    int counter;
    char name[80];
    struct timespec start;
    struct timespec end;
    struct timespec deltas[2000];
};

struct perf_private {
    int n_counters;
    struct perf_context *context;
};

/**
 * @brief - create performance context ..
 */
void* mwos_perf_init(int n_counters) // num conunters
{
    struct perf_private *priv;

    priv = (struct perf_private *)calloc(1, sizeof(struct perf_private));
    if (!priv) {
        return NULL;
    }

    priv->context = (struct perf_context *)calloc(n_counters, sizeof(struct perf_context));
    if (!priv->context) {
        return NULL;
    }

    // clear off memory area
    int i;

    for (i = 0; i < n_counters; i ++) {
        priv->context[i].available = 1;
    }

    priv->n_counters = n_counters;

    return priv;
}

void* mwos_perf_create_context(void *handle, char *name)
{
    int i;
    struct perf_private *priv = (struct perf_private *)handle;

    for (i = 0; i < priv->n_counters; i ++) {
        if (priv->context[i].available) {
            // set the area being used
            priv->context[i].available = 0;
            priv->context[i].counter = 0;
            strcpy(priv->context[i].name, name);
            return priv->context + i;
        }
    }

    return NULL;
}

void mwos_perf_ctx_record_start(void *context)
{
    struct perf_context *perf_c = (struct perf_context *)context;

    clock_gettime(CLOCK_MONOTONIC, &perf_c->start);
}

void mwos_perf_ctx_record_end(void *context)
{
    struct perf_context *perf_c = (struct perf_context *)context;

    clock_gettime(CLOCK_MONOTONIC, &perf_c->end);

    // drop recording any starts anymore
    if ((uint32_t)(perf_c->counter) > (sizeof(perf_c->deltas) / sizeof(perf_c->deltas[0]))) {
        return;
    }

    if ((perf_c->end.tv_nsec - perf_c->start.tv_nsec) < 0) {
        perf_c->deltas[perf_c->counter].tv_sec = perf_c->end.tv_sec - perf_c->start.tv_sec - 1;
        perf_c->deltas[perf_c->counter].tv_nsec = perf_c->end.tv_nsec - perf_c->start.tv_nsec + 1000000000ULL;
    } else {
        perf_c->deltas[perf_c->counter].tv_sec = perf_c->end.tv_sec - perf_c->start.tv_sec;
        perf_c->deltas[perf_c->counter].tv_nsec = perf_c->end.tv_nsec - perf_c->start.tv_nsec;
    }
    perf_c->counter ++;
}

void mwos_perf_stats_get(void *context, struct perf_stats *stats)
{
    struct perf_context *perf_c = (struct perf_context *)context;
    int i;
    double sum = 0;
    double delta_ns;
    int n_size;

    n_size = sizeof(perf_c->deltas) / sizeof(perf_c->deltas[0]);
    for (i = 0; i < perf_c->counter; i ++) {
        stats->last_sample = perf_c->deltas[i];
        delta_ns = (perf_c->deltas[i].tv_sec * 1000000000ULL) + (perf_c->deltas[i].tv_nsec);
        sum += delta_ns;
    }

    stats->mean = (sum/ n_size);

    double sqdiff = 0;

    for (i = 0; i < perf_c->counter; i ++) {
        delta_ns = (perf_c->deltas[i].tv_sec * 1000000000ULL) + (perf_c->deltas[i].tv_nsec);
        sqdiff += ((delta_ns - stats->mean) * (delta_ns - stats->mean));
    }

    stats->variance = sqdiff / n_size;

    stats->standard_devi = sqrt(stats->variance);
}

}

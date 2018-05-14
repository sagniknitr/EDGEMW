#ifndef __MWOS_PERF_H__
#define __MWOS_PERF_H__

struct perf_stats {
    struct timespec last_sample;
    double mean;
    double variance;
    double standard_devi;
};

void* mwos_perf_init(int n_counters);
void* mwos_perf_create_context(void *handle, char *name);
void mwos_perf_ctx_record_start(void *context);
void mwos_perf_ctx_record_end(void *context);
void mwos_perf_stats_get(void *context, struct perf_stats *stats);

#endif


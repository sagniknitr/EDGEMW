#ifndef __EDGEOS_PTHREADS_H__
#define __EDGEOS_PTHREADS_H__

void * edgeos_thread_create(void (*thread_callback)(void *data), void *data, int *cpulist, int cpulist_len);

int edgeos_thread_execute(void *tr_priv);

void * edgeos_thread_create_detached(void (*thread_callback)(void *data), void *data, int *cpulist, int cpulist_len);

int edgeos_threads_set_cpu(void *tr_priv, int *cpulist, int cpulist_len);

void * edge_os_threadpool_create(int n_threads);

void edge_os_threadpool_schedule_work(void *tr_priv, void (*work)(void *data));

#endif


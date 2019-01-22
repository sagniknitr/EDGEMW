#ifndef __EDGEOS_PTHREADS_H__
#define __EDGEOS_PTHREADS_H__

void * edge_os_thread_create(void (*thread_callback)(void *data), void *data, int *cpulist, int cpulist_len);

int edge_os_thread_execute(void *tr_priv);

void * edge_os_thread_create_detached(void (*thread_callback)(void *data), void *data, int *cpulist, int cpulist_len);

int edge_os_threads_set_cpu(void *tr_priv, int *cpulist, int cpulist_len);

void * edge_os_threadpool_create(int n_threads);

void edge_os_threadpool_schedule_work(void *tr_priv, void (*work)(void *data));

void edge_os_thread_join(void *tr_priv);
void edge_os_thread_stop(void *tr_priv);

#ifdef CONFIG_OS_HAS_PTHREADS

#include <pthread.h>

typedef pthread_mutex_t crit_sec_t;

#define DEFINE_CRIT_SECTION(__sec) pthread_mutex_init(&__sec, NULL)

#define CRIT_SECTION_LOCK(__sec) pthread_mutex_lock(&__sec)

#define CRIT_SECTION_UNLOCK(__sec) pthread_mutex_unlock(&__sec)

#endif

#endif


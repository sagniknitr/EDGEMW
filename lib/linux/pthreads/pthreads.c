#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sched.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <edgeos_logger.h>
#include <edgeos_list.h>

struct edge_os_threadpool_work_priv {
    void (*work)(void *data);
    void *data;
};

struct edge_os_thread_priv {
    pthread_t tid;
    pthread_attr_t attr;
    int started;
    pthread_mutex_t start_up_lock;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    void *data;
    uint64_t exec_time_ns_last;

    // threads with less (average time * task_complete_count) / pending will get more work
    uint64_t exec_time_ns_avg;
    int n_work_complete;
    int n_work_pending;
    int is_stop_thread;
#define EDGEOS_EXEC_TIME_COUNT 1000
    pthread_mutex_t work_mutex;
    struct edge_os_list_base work_set;
};

struct edge_os_thread_pool_priv {
    struct edge_os_thread_priv *threads;
    int n_threads;
};

void * thread_func_(void *data)
{
    struct edge_os_thread_priv *tpriv = data;

    while (1) {
        struct edge_os_list *list_item;
        struct edge_os_threadpool_work_priv *work_item;


        pthread_mutex_lock(&tpriv->start_up_lock);
        tpriv->started = 1;
        pthread_mutex_unlock(&tpriv->start_up_lock);

        pthread_mutex_lock(&tpriv->mutex);

        // jobs will run upon a signal from a caller
        // thread will complete all the jobs and waits for the signal again
        //
        // this means that the caller must ensure the jobs are being queued
        // and using the thread
        pthread_cond_wait(&tpriv->cond, &tpriv->mutex);

        if (tpriv->is_stop_thread) {
            return NULL;
        }

        for (list_item = tpriv->work_set.head; list_item != NULL; list_item = list_item->next) {
            // each worker thread will have readonly access to their worksets
            pthread_mutex_lock(&tpriv->work_mutex); // add only at the end when scheduling jobs !
            work_item = list_item->data;
            if (work_item) {
                work_item->work(work_item->data);
                if (tpriv->is_stop_thread) {
                    return NULL;
                }
            }
            pthread_mutex_unlock(&tpriv->work_mutex);
        }

        pthread_mutex_unlock(&tpriv->mutex);
    }

    return NULL;
}

void * edge_os_thread_create(void (*thread_callback)(void *data), void *data, int *cpulist, int cpulist_len)
{
    struct edge_os_threadpool_work_priv *work_priv = NULL;
    struct edge_os_thread_priv *tpriv;
    int ret;

    tpriv = calloc(1, sizeof(struct edge_os_thread_priv));
    if (!tpriv) {
        edge_os_error("pthreads: failed to allocate @ %s %u\n",
                                __func__, __LINE__);
        return NULL;
    }

    ret = pthread_attr_init(&tpriv->attr);
    if (ret < 0)
        goto bad;

    ret = pthread_attr_setdetachstate(&tpriv->attr, PTHREAD_CREATE_JOINABLE);
    if (ret < 0)
        goto bad;

    ret = pthread_mutex_init(&tpriv->mutex, NULL);
    if (ret < 0)
        goto bad;

    ret = pthread_cond_init(&tpriv->cond, NULL);
    if (ret < 0)
        goto bad;

    tpriv->data = data;

    ret = pthread_mutex_init(&tpriv->work_mutex, NULL);
    if (ret < 0)
        goto bad;

    edge_os_list_init(&tpriv->work_set);

    work_priv = calloc(1, sizeof(struct edge_os_threadpool_work_priv));
    if (!work_priv)
        goto bad;

    work_priv->work = thread_callback;
    work_priv->data = data;

    edge_os_list_add_tail(&tpriv->work_set, work_priv);

    ret = pthread_create(&tpriv->tid, &tpriv->attr, thread_func_, tpriv);
    if (ret < 0)
        goto bad;

    if (cpulist) {
        cpu_set_t cpu_ids;
        int j;

        CPU_ZERO(&cpu_ids);
        for (j = 0; j < cpulist_len; j ++) {
            CPU_SET(cpulist[j], &cpu_ids);
        }

        ret = pthread_setaffinity_np(tpriv->tid, sizeof(cpu_set_t), &cpu_ids);
        if (ret < 0)
            goto bad;
    }

    // schedule the caller out .. :( 
    //
    // problem is that when thread_execute is called right immediately the thread never gets a signal

    return tpriv;

bad:

    if (work_priv)
        free(work_priv);

    free(tpriv);
    return NULL;
}

int edge_os_thread_execute(void *tr_priv)
{
    struct edge_os_thread_priv *tpriv = tr_priv;

    while (1) {
       pthread_mutex_lock(&tpriv->start_up_lock);
       if (tpriv->started) {
          pthread_mutex_unlock(&tpriv->start_up_lock);
          break;
       }
       pthread_mutex_unlock(&tpriv->start_up_lock);
    }

    pthread_mutex_lock(&tpriv->mutex);
    pthread_cond_signal(&tpriv->cond);
    pthread_mutex_unlock(&tpriv->mutex);

    return 0;
}

void * edge_os_thread_create_detached(void (*thread_callback)(void *data), void *data, int *cpulist, int cpulist_len);

int edge_os_threads_set_cpu(void *tr_priv, int *cpulist, int cpulist_len);

void * edge_os_threadpool_create(int n_threads);

void edge_os_threadpool_schedule_work(void *tr_priv, void (*work)(void *data));


void edge_os_thread_stop(void *tr_priv)
{
   struct edge_os_thread_priv *tpriv = tr_priv;

//    pthread_kill(tpriv->tid, SIGINT);
    pthread_mutex_lock(&tpriv->mutex);
    tpriv->is_stop_thread = 1;
    pthread_cond_signal(&tpriv->cond);
    pthread_mutex_unlock(&tpriv->mutex);
}



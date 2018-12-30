#ifndef __EOS_INIT_H__
#define __EOS_INIT_H__

#include <edgeos_config.h>

void *eos_init_lib(struct edge_os_config *config);

void edgeos_log_info(void *handle, char *fmt, ...);

void edgeos_log_warn(void *handle, char *fmt, ...);

void edgeos_log_err(void *handle, char *fmt, ...);

#endif


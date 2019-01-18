#ifndef __EDGE_OS_H__
#define __EDGE_OS_H__

#include <sys/select.h>
#include <edgeos_list.h>
#include <edgeos_dlist.h>
#include <edgeos_queue.h>
#include <edgeos_stack.h>
#include <edgeos_static_list.h>
#include <edgeos_hashtbl.h>
#include <edgeos_evtloop.h>
#include <edgeos_crypto.h>
#include <edgeos_netapi.h>
#include <distcom.h>
#include <edgeos_fsapi.h>
#include <edgeos_sched.h>
#include <edgeos_fifo.h>
#include <edgeos_prng.h>
#include <edgeos_pthreads.h>
#include <edgeos_logger.h>
#include <edgeos_config_parser.h>
#include <edgeos_utils.h>
#include <edgeos_process.h>
#include <edgeos_monitor.h>
#include <edgeos_msg_queue.h>
#include <edgeos_datetime.h>
#include <edgeos_conv.h>
#include <edgeos_tokparse.h>
#include <edgeos_ioctl.h>

#ifdef OS_LINUX
// QNX declares getopt() in unistd.h
#include <getopt.h>
#endif

#endif


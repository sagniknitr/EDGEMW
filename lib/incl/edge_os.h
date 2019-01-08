#ifndef __EDGE_OS_H__
#define __EDGE_OS_H__

#include <sys/select.h>
#include <edgeos_list.h>
#include <edgeos_evtloop.h>
#include <edgeos_crypto.h>
#include <edgeos_netapi.h>
#include <distcom.h>
#include <edgeos_fsapi.h>
#include <edgeos_sched.h>
#include <edgeos_prng.h>
#include <edgeos_logger.h>
#include <edgeos_config_parser.h>
#include <edgeos_conv.h>
#include <edgeos_tokparse.h>

#ifdef OS_LINUX
// QNX declares getopt() in unistd.h
#include <getopt.h>
#endif

#endif


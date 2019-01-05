#ifndef __EDGE_OS_H__
#define __EDGE_OS_H__

#include <edgeos_list.h>
#include <edgeos_evtloop.h>
#include <edgeos_crypto.h>
#include <edgeos_netapi.h>
#include <distcom.h>
#include <fsapi.h>
#include <edgeos_sched.h>
#include <prng.h>
#include <edgeos_logger.h>
#include <config_parser.h>
#include <edgeos_conv.h>
#include <edgeos_tokparse.h>

#ifdef OS_LINUX
// QNX declares getopt() in unistd.h
#include <getopt.h>
#endif

#endif


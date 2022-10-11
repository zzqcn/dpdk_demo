#ifndef __COMMON_H__
#define __COMMON_H__

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <rte_log.h>

#define STATS
#define DRAIN
#define LOG_LEVEL RTE_LOG_DEBUG

#ifndef TAILQ_FOREACH_SAFE
#  define TAILQ_FOREACH_SAFE(var, head, field, tvar)                                   \
    for ((var) = TAILQ_FIRST((head)); (var) && ((tvar) = TAILQ_NEXT((var), field), 1); \
         (var) = (tvar))
#endif

#define RTE_LOGTYPE_FILTER RTE_LOGTYPE_USER1

#endif

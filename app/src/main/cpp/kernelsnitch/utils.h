#pragma once
/* Minimal shim replacing the Payload's kernelsnitch/utils.h for our app
 * build: logging goes to logcat, SYSCHK never exits (the exploit must
 * survive transient errors), pin_to_core is our own. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <errno.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

void ks_log(const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#ifndef MIN
#define MIN(X,Y) (((X) < (Y)) ? (X) : (Y))
#endif
#ifndef MAX
#define MAX(X,Y) (((X) > (Y)) ? (X) : (Y))
#endif

#define pr_info(fmt, ...)    ks_log("[ks] " fmt "\n", ##__VA_ARGS__)
#define pr_warning(fmt, ...) ks_log("[ks] WARN " fmt "\n", ##__VA_ARGS__)
#define pr_error(fmt, ...)   ks_log("[ks] ERR " fmt "\n", ##__VA_ARGS__)
#define pr_success(fmt, ...) ks_log("[ks] OK " fmt "\n", ##__VA_ARGS__)

#define SYSCHK(x) ({ \
        __typeof__(x) __res = (x); \
        if (__res == (__typeof__(x))-1) \
            pr_warning("SYSCHK(" #x ") errno=%d", errno); \
        __res; \
    })

#define ASSERT(cond) do { \
        if (!(cond)) pr_warning("assert(%s)", #cond); \
    } while (0)

#define ASSERT_pr(cond, fmt, ...) do { \
        if (!(cond)) pr_warning("assert(%s): " fmt, #cond, ##__VA_ARGS__); \
    } while (0)

static inline void reset_cpu_pin(void) {
    cpu_set_t set;
    CPU_ZERO(&set);
    for (int i = 0; i < 8; i++) CPU_SET(i, &set);
    sched_setaffinity(0, sizeof(set), &set);
}

static inline void pin_to_core(int core) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(core, &set);
    sched_setaffinity(0, sizeof(set), &set);
}

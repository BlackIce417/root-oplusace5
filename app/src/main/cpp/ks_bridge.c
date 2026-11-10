/* ks_bridge.c — compiles the KernelSnitch engine as C (its headers are
 * C-dialect: anonymous union members, void* initializations) and exposes
 * a tiny C ABI for page_engine.cpp. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stddef.h>
#include <android/log.h>
#include <stdarg.h>

#include "kernelsnitch/utils.h"

#define __ARM 1
#include "kernelsnitch/kernelsnitch.h"

void ks_log(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    __android_log_print(ANDROID_LOG_INFO, "gl_page", "%s", buf);
}

void *ks_setup(size_t mm_sz, size_t order, size_t threads, size_t collisions) {
    return kernelsnitch_setup(mm_sz, order, threads, collisions, 0, 0);
}

void ks_find_collisions(void *ks) {
    kernelsnitch_find_collisions((struct kernelsnitch_shared_state *) ks);
}

int ks_found(void *ks) {
    return (int) kernelsnitch_found_collisions(
        (struct kernelsnitch_shared_state *) ks);
}

void ks_bruteforce(void *ks) {
    kernelsnitch_bruteforce((struct kernelsnitch_shared_state *) ks);
}

uintptr_t ks_mm(void *ks) {
    return (uintptr_t)
        ((struct kernelsnitch_shared_state *) ks)->mm_struct;
}

void ks_cleanup(void *ks) {
    kernelsnitch_cleanup((struct kernelsnitch_shared_state *) ks);
}

void ks_pin(int core) { pin_to_core(core); }
void ks_reset_pin(void) { reset_cpu_pin(); }

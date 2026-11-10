#ifndef ROOT_OPLUS_ACE5_PIPE_PHYS_H
#define ROOT_OPLUS_ACE5_PIPE_PHYS_H

#include <cstddef>
#include <cstdint>

namespace pe {

// Upgrade the configfs channel to the upstream pipe_buffer page primitive.
// The function performs read/write self-tests on the already-owned fake page
// and does not touch task_struct/cred unless both tests pass.
bool install_pipe_physrw();

bool phys_read(uint64_t direct_addr, void *out, size_t len);
bool phys_write(uint64_t direct_addr, const void *data, size_t len);
uint64_t phys_read64(uint64_t direct_addr);
bool phys_write64(uint64_t direct_addr, uint64_t value);

}  // namespace pe

#endif

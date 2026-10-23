#pragma once

// KVM lifecycle helpers shared across the syz_kvm$* handlers.
//
// The host-side code mirrors syzkaller's common_kvm_amd64.h setup flow:
// setup_syzos_vm maps the full syzOS GPA layout, installs the vendored guest
// section, add_vcpu creates a vCPU, copies caller kvm_text into the per-CPU
// user-code slot, and initializes long-mode registers for guest_main().

#include "worker/backend/pseudo/kvm/kvm_layout.hpp"

#include <cstddef>
#include <cstdint>

namespace refuzz::worker::pseudo {

struct KvmState;

// Open /dev/kvm (O_RDWR | O_CLOEXEC) and store fd in state.kvm_root_fd.
// Idempotent: if already open, returns 0 immediately. Returns -1+errno
// on failure (handler caller surfaces that as PseudoResult.err).
int KvmOpenRoot(KvmState& state);

// Create the per-program VM. Idempotent (returns 0 if vm_fd already
// set). Implies KvmOpenRoot. Returns -1+errno on failure.
int KvmCreateVm(KvmState& state);

// Map syzkaller's syzOS GPA layout. NO_HOST_MEM rows intentionally skip
// KVM_SET_USER_MEMORY_REGION so guest writes to X86_SYZOS_ADDR_UEXIT surface
// as KVM_EXIT_MMIO. The trailing unused host memory is mapped at
// X86_SYZOS_ADDR_UNUSED, matching upstream setup_vm().
int KvmMapRegions(KvmState& state,
                  const kvm_layout::MemRegion* regions,
                  std::size_t count);

// Create the next vCPU, mmap its kvm_run page, and update latest-vCPU fields.
int KvmCreateVcpu(KvmState& state);

// Issue KVM_RUN on the most-recent vcpu_fd. Updates state.last_exit_reason
// from the kvm_run mmap after each call. Returns 0 on KVM_RUN success
// (regardless of guest exit reason), -1+errno on KVM_RUN failure (e.g.,
// EINTR retry exhaustion or fd invalid).
int KvmRunVcpu(KvmState& state);

// Copy the vendored syzOS AMD64 guest section into the EXECUTOR_CODE region.
int KvmInstallSyzosGuest(KvmState& state);

// Copy caller-supplied kvm_text bytes to the per-vCPU user-code page and set
// long-mode sregs/regs so KVM_RUN enters syzOS guest_main(). Does not call
// KVM_RUN.
int KvmInstallUserCode(KvmState& state,
                       const void* text,
                       std::size_t text_size);

void* KvmHostAddrForGpa(const KvmState& state, std::uint64_t gpa);

} // namespace refuzz::worker::pseudo

#pragma once

#include "refuzz/program/syz/pseudo/target_view.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>

namespace refuzz::worker {

// [v1 PseudoContext aggregate POD — ROLLBACK: uncomment below and remove v2]
// struct PseudoContext {
//     const refuzz::fuzzer::syz::PseudoMetaTable* table = nullptr;
//     uint32_t available_caps = refuzz::fuzzer::syz::kCapNone;
// };

// [v2 PseudoContext 加 virtual lifecycle hooks (PR-A1 §5.0) — 当前版本]
// Lifecycle hooks (RegisterCleanup / RegisterOwnedFd / RegisterNamedRegion
// / LookupNamedRegion) are virtual + const so that handlers receiving
// `const PseudoContext&` can register per-program cleanup actions and
// shared mmap regions through virtual dispatch on a PseudoRuntimeContext.
// Default impls are no-ops; PseudoRuntimeContext overrides them.
struct PseudoContext {
    const refuzz::fuzzer::syz::PseudoMetaTable* table = nullptr;

    // Runtime execution slot identity assigned by the channel layer / worker
    // placement. **Not** a program/payload attribute: it is NOT serialized in
    // SerializeForExec output and NOT part of corpus or seed identity. The
    // program is dispatched to a worker slot N; from inside the handler this
    // value identifies which slot the call is executing on.
    //
    // Handlers that mirror upstream syzkaller's per-process resource naming
    // (procid in common_linux.h — e.g. /dev/loop<procid> in syz_mount_image at
    // :3129, syz_read_part_table at :3054, network helper ifname suffixes,
    // KVM CPU index, etc.) read this field. Default 0 is the single-slot
    // smoke / unit-test value; production uses the active domain's proc_id and the
    // KernelThreadPool propagates the same value to every WorkerThread so a
    // pool shares one slot identity (matches upstream "one executor proc
    // covers all its threads").
    //
    // For oracle replay, the replayer is expected to set the channel's
    // target_proc_id from the captured trace's Executing.proc_id. The channel
    // routes that resource ID to a stable worker lane; it is not payload data.
    uint32_t proc_slot_id = 0;

    // Match syzkaller's fixed /dev/loop<procid> ownership. All threads in one
    // executor process share the channel-assigned proc slot.
    uint32_t EffectiveLoopSlot() const
    {
        return proc_slot_id;
    }

    // [R1 mount/loop teardown locus] true ⇔ this Execute runs in a fork-per-
    // program child (DoubleFork topology) whose loop_child parent performs the
    // authoritative post-reap teardown (RemoveDirRecursive plus the next
    // iteration's fixed-slot loop reset in loop_runtime.cpp). When set,
    // MountState::Cleanup skips in-child umount/LOOP_CLR_FD entirely: the child
    // is about to _exit, so umount-in-child can only EBUSY on the dirfd + the
    // program's own still-open fds and degrade to a lazy MNT_DETACH that defeats
    // the parent's *synchronous* post-reap umount. Set by KernelWireDriver from
    // ExecMode.scratch_reset==kForkClean. Inline/Reusable topology leaves it
    // false → MountState::Cleanup does the full in-process teardown (there is no
    // reap boundary there to ride).
    bool defer_mount_teardown = false;

    PseudoContext() = default;
    PseudoContext(const refuzz::fuzzer::syz::PseudoMetaTable* t,
                  uint32_t slot_id = 0)
        : table(t), proc_slot_id(slot_id) {}

    virtual ~PseudoContext() = default;

    PseudoContext(const PseudoContext&) = default;
    PseudoContext& operator=(const PseudoContext&) = default;

    virtual void RegisterCleanup(std::function<void()> cleanup) const {
        (void)cleanup;
    }
    virtual void RegisterOwnedFd(int fd) const {
        (void)fd;
    }
    virtual void RegisterNamedRegion(uint64_t key,
                                     void* base,
                                     std::size_t len) const {
        (void)key;
        (void)base;
        (void)len;
    }
    virtual void* LookupNamedRegion(uint64_t key,
                                    std::size_t* len_out = nullptr) const {
        (void)key;
        (void)len_out;
        return nullptr;
    }

    // [PR-C0 §5.1] Tier 2 net-stack lazy infrastructure surface — virtual
    // so handlers receiving `const PseudoContext&` can call them without
    // downcast. Bare PseudoContext defaults to "-1 / not available";
    // PseudoRuntimeContext overrides with caching + lazy init.
    virtual int tun_fd() const {
        return -1;
    }
    virtual int init_net_socket(int domain, int type, int protocol) const {
        (void)domain;
        (void)type;
        (void)protocol;
        return -1;
    }

    // [PR-B4] Lazy /dev/vhci open for Bluetooth HCI injection. Returns
    // cached fd or -1 if hci_vhci kernel module not loaded / device
    // node missing. Operator-preload pattern (plan §10 Q6 generalization).
    virtual int vhci_fd() const {
        return -1;
    }

    // Mid-call KCOV cursor reset — mirror upstream syzkaller's
    // `cover_reset(0)` discipline at common_linux.h:3064 (syz_read_part_table)
    // and :3171 (syz_mount_image). Pseudo handlers that do user-mode prep
    // touching the kernel (e.g. setup_loop_device → memfd write loop →
    // shmem/folio/page-fault PCs) call this AFTER the prep phase and BEFORE
    // the syscall whose coverage the call should be attributed to. The
    // upstream driver discards everything captured before the reset, so the
    // per-call kcov slice contains only the mount(2)/LOOP_SET_STATUS64 body
    // PCs. Default no-op for plain PseudoContext (tests + non-runtime
    // dispatch paths); PseudoRuntimeContext overrides to forward to the
    // worker thread's KcovCollector cursor.
    virtual void KcovCursorReset() const {
    }

    // Diagnostic-only executor id for correlating worker-side timing logs with
    // ref_result/oracle rows. It is not program identity and must not affect
    // handler behavior. Plain PseudoContext returns 0 (unknown).
    virtual uint64_t DiagnosticExecutorId() const {
        return 0;
    }

    // Record /dev/loop<proc_slot_id> as a cleanup candidate before entering
    // SetupLoopDevice. Publishing before the helper closes the timeout window
    // between LOOP_SET_FD and helper return. A failed setup may cause one extra
    // foreign-mount sweep, while fixed-slot loop cleanup remains bounded.
    //
    // Default no-op for plain PseudoContext (tests / DefaultPseudoContext);
    // PseudoRuntimeContext overrides to OR into loop_devices_used_mask_.
    // proc_slot_id >= 32 → publish UINT32_MAX because this diagnostic mask
    // cannot represent the fixed slot; cleanup still uses proc_slot_id. In practice
    // proc_slot_id is bounded by the fixed 32-slot resource ABI.
    virtual void RecordLoopDeviceUsed(uint32_t /*proc_slot_id*/) const {
    }
};

PseudoContext DefaultPseudoContext();

} // namespace refuzz::worker

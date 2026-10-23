// PR-D2 — KVM sub-context implementation.

#include "worker/backend/pseudo/kvm/kvm_state.hpp"

#include <memory>
#include <mutex>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>
#include <unordered_map>

namespace refuzz::worker::pseudo {

namespace {

std::mutex g_kvm_state_mutex;
std::unordered_map<const PseudoContext*, std::unique_ptr<KvmState>> g_kvm_state_by_ctx;

// [fork-safety 2026-08-08] Defensive atfork protection for forks made while
// pseudo state is being updated. The normal program fork precedes lazy driver
// and pool construction, but keeping this invariant makes future call paths
// safe too. The prepare lock is released by both parent and child; do not
// reinitialize the already-constructed std::mutex in the child.
void PseudoStateAtForkPrepare()
{
    g_kvm_state_mutex.lock();
}

void PseudoStateAtForkParent()
{
    g_kvm_state_mutex.unlock();
}

void PseudoStateAtForkChild()
{
    g_kvm_state_mutex.unlock();
}

struct PseudoStateAtForkRegistrar {
    PseudoStateAtForkRegistrar()
    {
        (void)pthread_atfork(&PseudoStateAtForkPrepare,
                             &PseudoStateAtForkParent,
                             &PseudoStateAtForkChild);
    }
};
const PseudoStateAtForkRegistrar g_pseudo_state_atfork_registrar;

// PR-D1 review fix C9 pattern: extract under lock, then run Cleanup
// outside the lock so KVM ioctls + munmap don't block other workers.
std::unique_ptr<KvmState> ExtractKvmStateForTeardown(const PseudoContext* ctx_ptr)
{
    std::lock_guard<std::mutex> lock(g_kvm_state_mutex);
    auto it = g_kvm_state_by_ctx.find(ctx_ptr);
    if (it == g_kvm_state_by_ctx.end()) {
        return nullptr;
    }
    auto extracted = std::move(it->second);
    g_kvm_state_by_ctx.erase(it);
    return extracted;
}

} // namespace

void* KvmState::guest_mem() const noexcept
{
    // Back-compat accessor: return host_addr of the GPA-0 row if present.
    // Returning the GPA-0 row preserves the historical "guest memory is mapped
    // at GPA 0" accessor contract.
    if (regions.empty()) return nullptr;
    return regions.front().host_addr;
}

std::size_t KvmState::guest_mem_size() const noexcept
{
    if (regions.empty()) return 0;
    return regions.front().size_bytes;
}

void KvmState::Cleanup()
{
    // Reverse creation order: vCPU slots (each: run mmap → fd) → region
    // mmaps (in reverse of creation) → vm fd → root fd. The "latest"
    // pointer triple becomes invalid after we pop slots; reset it explicitly.
    while (!vcpu_slots.empty()) {
        auto& slot = vcpu_slots.back();
        if (slot.run_mmap != nullptr && slot.run_mmap != MAP_FAILED &&
            slot.run_mmap_size > 0) {
            ::munmap(slot.run_mmap, slot.run_mmap_size);
        }
        if (slot.fd >= 0) {
            ::close(slot.fd);
        }
        vcpu_slots.pop_back();
    }
    vcpu_fd       = -1;
    vcpu_run      = nullptr;
    vcpu_run_size = 0;

    // KVM_SET_USER_MEMORY_REGION slots are not explicitly torn down here.
    // KVM detaches them on VM close; only host-side mappings need munmap.
    // [carve_from_host_mem] In carve mode every region host_addr is a slice of
    // the single host_arena (non-owning) — free only the arena, once. (A migrated
    // thread has regions_carved=false + host_arena=nullptr, so it frees nothing.)
    if (regions_carved) {
        regions.clear();
        if (host_arena != nullptr && host_arena != MAP_FAILED &&
            host_arena_size > 0) {
            ::munmap(host_arena, host_arena_size);
        }
        host_arena      = nullptr;
        host_arena_size = 0;
        arena_offset    = 0;
        regions_carved  = false;
    } else {
        while (!regions.empty()) {
            auto& slot = regions.back();
            if (slot.host_addr != nullptr && slot.host_addr != MAP_FAILED &&
                slot.size_bytes > 0) {
                ::munmap(slot.host_addr, slot.size_bytes);
            }
            regions.pop_back();
        }
    }
    syz_vm = {};
    syz_vm_ready = false;
    user_text = nullptr;
    gpa0_mem = nullptr;
    syzos_guest_installed = false;

    // [R3] A borrowed vm_fd (recovered from another thread's setup) is not owned
    // here — closing it would double-close the setup thread's / executor's fd.
    if (vm_fd >= 0 && !vm_fd_borrowed) {
        ::close(vm_fd);
    }
    vm_fd = -1;
    vm_fd_borrowed = false;
    if (kvm_root_fd >= 0) {
        ::close(kvm_root_fd);
        kvm_root_fd = -1;
    }
}

KvmState& GetOrCreateKvmState(const PseudoContext& ctx)
{
    std::lock_guard<std::mutex> lock(g_kvm_state_mutex);
    const PseudoContext* key = &ctx;
    auto it = g_kvm_state_by_ctx.find(key);
    if (it != g_kvm_state_by_ctx.end()) {
        return *it->second;
    }
    auto state = std::make_unique<KvmState>();
    KvmState& ref = *state;
    g_kvm_state_by_ctx[key] = std::move(state);

    ctx.RegisterCleanup([key]() {
        auto extracted = ExtractKvmStateForTeardown(key);
        if (extracted != nullptr) {
            extracted->Cleanup();
        }
    });
    return ref;
}

} // namespace refuzz::worker::pseudo

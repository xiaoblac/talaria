// PR-D4 — USB sub-context implementation.

#include "worker/backend/pseudo/usb/usb_state.hpp"

#include <cstdint>
#include <memory>
#include <mutex>
#include <pthread.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <unordered_map>

namespace refuzz::worker::pseudo {

namespace {

// [ep_write per-thread-UsbState fix 2026-05-24] Keyed by proc_slot_id, NOT the
// per-thread PseudoContext*. In threaded mode each worker thread has its own
// PseudoContext; the gadget is created on the connect thread's context, so when
// a blocking call (e.g. IN-endpoint ep_write) forces the next USB call onto a
// different thread, that thread's per-ctx UsbState had no gadget → "gadget not
// running" EINVAL instead of syzkaller's EBUSY (shared usb_devices[]). Keying by
// proc_slot_id makes gadget state TASK-shared across the program's threads
// (mirrors syz process-global usb_devices[]). One program runs at a time per
// slot and the entry is erased at EndTask, so it stays per-task. The mutex
// guards only the map; GetOrCreateUsbState returns the reference and unlocks
// before any (blocking) EP ioctl — the lock is never held across EP_WRITE.
// See docs/plans/hiddev-gadget-lifetime-dossier.md (ep_write section).
std::mutex g_usb_state_mutex;
std::unordered_map<uint32_t, std::unique_ptr<UsbState>> g_usb_state_by_slot;

// [fork-safety 2026-08-08] Defensive atfork protection for forks made while
// pseudo state is being updated. The normal program fork precedes lazy driver
// and pool construction, but keeping this invariant makes future call paths
// safe too. The prepare lock is released by both parent and child; do not
// reinitialize the already-constructed std::mutex in the child.
void PseudoStateAtForkPrepare()
{
    g_usb_state_mutex.lock();
}

void PseudoStateAtForkParent()
{
    g_usb_state_mutex.unlock();
}

void PseudoStateAtForkChild()
{
    g_usb_state_mutex.unlock();
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

// PR-D1 review fix C9 pattern: extract under lock, run Cleanup outside.
// Idempotent: when several threads of the same program registered a cleanup,
// the first to run extracts+cleans, the rest get nullptr.
std::unique_ptr<UsbState> ExtractUsbStateForTeardown(uint32_t slot)
{
    std::lock_guard<std::mutex> lock(g_usb_state_mutex);
    auto it = g_usb_state_by_slot.find(slot);
    if (it == g_usb_state_by_slot.end()) {
        return nullptr;
    }
    auto extracted = std::move(it->second);
    g_usb_state_by_slot.erase(it);
    return extracted;
}

} // namespace

void UsbState::Cleanup()
{
    // USBIP server fd first (separate file).
    if (usbip_server_fd >= 0) {
        ::close(usbip_server_fd);
        usbip_server_fd = -1;
    }
    // Raw-gadget cleanup. If gadget was running, the kernel's raw-gadget
    // driver disconnects + frees the device on fd close — no explicit
    // ioctl needed. Just close.
    if (raw_gadget_fd >= 0) {
        ::close(raw_gadget_fd);
        raw_gadget_fd = -1;
    }
    gadget_running = false;

    // [PR-5.2 2026-05-20] device_index points into the previous program's
    // scratch buffer (which may be reused / overwritten by the next
    // program). Reset eagerly so a partial / failed connect can't leak a
    // parsed=true flag and stale ep handles into a subsequent program
    // that bypasses UsbConnect (handler order is fuzzer-controlled).
    //
    // The current ownership model (UsbState extracted from the map +
    // destroyed in the cleanup callback) makes this redundant in practice
    // — but the cost is one struct-assign and the safety is real if the
    // ownership ever loosens.
    device_index = {};
}

UsbState& GetOrCreateUsbState(const PseudoContext& ctx)
{
    std::lock_guard<std::mutex> lock(g_usb_state_mutex);
    // Task-shared key: all worker threads of one program carry the same
    // proc_slot_id, so they share the gadget created by the connect thread.
    const uint32_t key = ctx.proc_slot_id;
    auto it = g_usb_state_by_slot.find(key);
    if (it != g_usb_state_by_slot.end()) {
        return *it->second;
    }
    auto state = std::make_unique<UsbState>();
    UsbState& ref = *state;
    g_usb_state_by_slot[key] = std::move(state);

    // Cleanup registered on the creating thread's ctx; runs at its EndTask and
    // erases the shared entry (idempotent), so the next program on this slot
    // starts with a fresh gadget.
    ctx.RegisterCleanup([key]() {
        auto extracted = ExtractUsbStateForTeardown(key);
        if (extracted != nullptr) {
            extracted->Cleanup();
        }
    });
    return ref;
}

} // namespace refuzz::worker::pseudo

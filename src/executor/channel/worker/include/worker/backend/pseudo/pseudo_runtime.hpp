#pragma once

#include "worker/backend/pseudo/pseudo_context.hpp"
#include "worker/backend/pseudo/pseudo_result.hpp"
#include "refuzz/program/syz/pseudo/target_view.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace refuzz::worker {

class KcovCollector;  // fwd-decl — concrete include in pseudo_runtime.cpp only.

struct PseudoRuntimeContext : public PseudoContext {
    const refuzz::fuzzer::syz::SyzTargetTables* target =
        &refuzz::fuzzer::syz::kDefaultSyzTarget;
    std::string temp_root;

    // [v1 cleanup_callbacks / owned_fds non-mutable — ROLLBACK: uncomment below and remove v2]
    // std::vector<std::function<void()>> cleanup_callbacks;
    // std::vector<int> owned_fds;

    // [v2 升 mutable storage + 加 named_regions (PR-A1 §5.0) — 当前版本]
    mutable std::vector<std::function<void()>> cleanup_callbacks;
    mutable std::vector<int> owned_fds;
    struct NamedRegion {
        void* base = nullptr;
        std::size_t len = 0;
    };
    mutable std::map<uint64_t, NamedRegion> named_regions;

    // [PR-C0 §5.1] Lazy Tier 2 net-stack caches. -2 = not tried, -1 = tried
    // and failed, >=0 = open fd (also pushed into owned_fds).
    mutable int  tun_fd_cached_           = -2;
    mutable int  vhci_fd_cached_          = -2;
    mutable bool pre_program_setup_done_  = false;
    // [B5 review fix 2026-05-06] Operator-supplied input state — NOT a
    // cache. Drop `mutable` and the const setter; expose non-const
    // setter on PseudoRuntimeContext only (handlers receive const
    // PseudoContext& which can't reach this field anyway). Default = -1
    // (uninitialized → init_net_socket falls back to current-ns socket
    // creation, mirroring upstream's `SYZ_NET_INJECTION` OFF path).
    int          init_netns_fd_for_pseudo_ = -1;

    // [Step A 2026-05-20] Per-program /dev/loop usage bitmask. Each
    // syz_mount_image / syz_read_part_table records its proc_slot_id bit before
    // entering SetupLoopDevice; the loop child reads it from ProgramResultPageV3
    // and only sweeps those cleanup candidates. mask == 0 → no sweep needed; mask ==
    // UINT32_MAX → unknown (proc_slot_id >= 32 cannot fit the diagnostic mask).
    //
    // mutable because RecordLoopDeviceUsed is called via const PseudoContext&
    // surface (handlers see const ctx). Lives on PseudoRuntimeContext only —
    // bare PseudoContext stays a POD-like value type.
    mutable uint32_t loop_devices_used_mask_ = 0;
    uint32_t* loop_devices_used_mask_cursor_ = nullptr;

    // Diagnostic-only executor id supplied by ProgramRuntime/KernelWireDriver
    // for log correlation. Not program semantics.
    uint64_t diagnostic_executor_id_ = 0;

    // Worker thread's KCOV collector for mid-call cursor resets (mirror of
    // upstream syzkaller's `cover_reset(0)` discipline; see PseudoContext::
    // KcovCursorReset doc). Non-owning. nullptr in tests / dispatch paths
    // without a driver-bound collector; KcovCursorReset() is a no-op in
    // that case. Serial KernelWireDriver::Execute binds collector 0 once
    // per program; WorkerThread::Run binds the current thread's collector
    // once at thread start. The pointer is stable for the relevant lifetime
    // (kcov_provider pool is stable, per kernel_thread_pool.hpp).
    KcovCollector* kcov_collector_ = nullptr;

    uint32_t open_mounts = 0;
    uint32_t open_sockets = 0;

    explicit PseudoRuntimeContext(
        const refuzz::fuzzer::syz::SyzTargetTables* target_tables =
            &refuzz::fuzzer::syz::kDefaultSyzTarget,
        uint32_t proc_slot_id = 0);

    ~PseudoRuntimeContext();

    PseudoRuntimeContext(const PseudoRuntimeContext&) = delete;
    PseudoRuntimeContext& operator=(const PseudoRuntimeContext&) = delete;
    PseudoRuntimeContext(PseudoRuntimeContext&&) = delete;
    PseudoRuntimeContext& operator=(PseudoRuntimeContext&&) = delete;

    // [v1 non-virtual non-const — ROLLBACK: uncomment below and remove v2]
    // void RegisterCleanup(std::function<void()> cleanup);
    // void RegisterOwnedFd(int fd);

    // [v2 虚方法 const override + 加 RegisterNamedRegion / LookupNamedRegion (PR-A1 §5.0) — 当前版本]
    void RegisterCleanup(std::function<void()> cleanup) const override;
    void RegisterOwnedFd(int fd) const override;
    void RegisterNamedRegion(uint64_t key,
                             void* base,
                             std::size_t len) const override;
    void* LookupNamedRegion(uint64_t key,
                            std::size_t* len_out = nullptr) const override;

    // [PR-C0 §5.1] Tier 2 net-stack lazy infrastructure.
    //
    // tun_fd(): cached open of /dev/net/tun + ioctl(TUNSETIFF, IFF_TAP|IFF_NO_PI).
    // Returns the cached TAP fd or -1 if open/ioctl failed (no CAP_NET_ADMIN,
    // /dev/net/tun missing, etc. — graceful degrade, handler returns -1
    // upstream when tunfd<0). Lazy: first call opens; subsequent calls return
    // cache. Cleanup() closes the fd (registered via RegisterOwnedFd).
    //
    // init_net_socket(domain, type, proto): per-call mirror of upstream
    // syz_init_net_socket — open("/proc/self/ns/net") → setns(init_netns_fd)
    // → socket(domain, type, proto) → setns(worker_netns) → close(worker_netns).
    // The worker netns fd is opened AND closed every call (not cached), so the
    // fs/inode-evict + fs/file_table + fs/open path on close matches syz.
    // init_netns is operator-provided via init_netns_fd_for_pseudo() — defaults
    // to the worker's own netns when uninitialized, which means the handler
    // degrades to "current-ns socket" instead of failing — closer to upstream's
    // no-SYZ_NET_INJECTION fallback.
    //
    // run_pre_program_setup(): one-shot idempotent pre-program hook. Tier 2
    // families currently rely on lazy-init (each family opens its resource
    // at first call), so this is a no-op surface for future use. Called
    // exactly once per program by DispatchPseudo before first handler.
    int tun_fd() const override;
    int init_net_socket(int domain, int type, int protocol) const override;
    int vhci_fd() const override;
    void KcovCursorReset() const override;
    uint64_t DiagnosticExecutorId() const override;
    void RecordLoopDeviceUsed(uint32_t proc_slot_id) const override;
    // [#15 threaded loop-mask aggregation] 读 / 清本 ctx 累积的 loop mask
    // (bit = proc_slot_id)。Cleanup() 不清它,跨 program 累积,故由 pool 每
    // program 聚合后显式清零。mutable 字段,故 const 也能清。
    uint32_t LoopDevicesUsedMask() const { return loop_devices_used_mask_; }
    void ClearLoopDevicesUsedMask() const { loop_devices_used_mask_ = 0; }
    void run_pre_program_setup() const;

    // Wire the worker thread's KCOV collector for mid-call cursor resets.
    // Called by serial KernelWireDriver::Execute after collector 0 is fetched,
    // and by KernelThreadPool::WorkerThread::Run after the per-thread collector
    // is fetched. Tests can also call this to inject a fake collector.
    // Non-virtual + non-const — matches set_init_netns_fd_for_pseudo pattern
    // (operator-supplied state).
    void set_kcov_collector(KcovCollector* collector);
    void set_diagnostic_executor_id(uint64_t executor_id);
    void set_loop_devices_used_mask_cursor(uint32_t* cursor);

    // Init-netns descriptor. Default = -1 (uninitialized →
    // init_net_socket falls back to current-ns socket creation, mirroring
    // upstream's `SYZ_NET_INJECTION` OFF path). The constructor auto-detects
    // syzkaller fixed fd 201 when SandboxCommon has populated it; tests can
    // still override via this setter. [B5 review fix 2026-05-06] Setter is
    // non-const + non-virtual on PseudoRuntimeContext only — handlers see only
    // `const PseudoContext&` so can't reach this; tests + worker bootstrap
    // manipulate the non-const PseudoRuntimeContext instance directly.
    void set_init_netns_fd_for_pseudo(int fd);

    void Cleanup();
};

PseudoResult ExecuteNrOrPseudo(PseudoRuntimeContext& ctx,
                               uint64_t nr,
                               const intptr_t* args,
                               uint32_t argc);

bool WritePseudoOwnershipMarker(const std::string& path,
                                const std::string& run_id,
                                int pid);

uint32_t ReclaimStalePseudoRuntimeRoots(const std::string& root,
                                        const std::string& current_run_id);

} // namespace refuzz::worker

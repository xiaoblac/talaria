// SnapshotDataPlane — IDataPlane that wraps an inner ivshmem data plane and adds
// the QEMU savevm/loadvm snapshot cycle around each Submit. Lets the existing
// Channel + FuzzerLoop drive snapshot fuzzing unchanged (snapshot is just a
// different data-plane role impl, selected by the qemu_ivshmem_snapshot_linux
// backend). See docs/plans/snapshot-session-integration.md.
//
// Per-Submit cycle (the inner plane writes/reads the ivshmem slots; this plane
// only orchestrates the VM around it):
//   [first Submit: qmp_capabilities + x-ignore-shared + savevm S0]
//   stop → inner.ResetWorker(wid) → inner.Submit(req) → loadvm S0 → cont → kSent
// Poll delegates to inner; a completion clears the global 1-in-flight gate.
//
// CRITICAL (review): (a) ResetWorker before every inner.Submit — loadvm rolls back
// the worker exec_seq, so without it the inner plane drops the post-restore
// completion as stale. (b) Global 1-in-flight, NOT per-worker — loadvm rolls back
// the whole VM; v1 uses n_workers=1.

#pragma once

#include "refuzz/channel/data/data_plane.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace refuzz::channel::data {

class SnapshotDataPlane : public IDataPlane {
public:
    // monitor_endpoint_fn is evaluated lazily (after StartVM) to get the QMP
    // "host:port"; it must capture the concrete Runtime* (MonitorEndpoint is not
    // on ISubstrate).
    // [Brick 4a step 3] vmlinux_path enables VMI-on-wedge: when a program does
    // not complete within wedge_threshold_ms (a silent hang — where syz's
    // console-only ContainsCrash is blind and ssh is dead), the host reads guest
    // state directly via QMP — the printk ring (__log_buf, resolved from the
    // System.map alongside vmlinux) + the stuck kernel PC (info registers, resolved
    // via addr2line) — and emits it as wedge evidence. Empty path / 0 threshold
    // disables it (e.g. the standalone driver tool).
    SnapshotDataPlane(std::unique_ptr<IDataPlane> inner,
                      std::function<std::string()> monitor_endpoint_fn,
                      std::string snapshot_tag = "S0",
                      std::string vmlinux_path = {},
                      uint32_t wedge_threshold_ms = 0);
    ~SnapshotDataPlane() override;

    // Lifecycle — delegate to inner; QMP connects in Prepare (VM is up by then).
    Result<void> StartServer() override;
    Result<void> Prepare() override;
    void         Close() override;
    void         Pause() override;
    void         Resume() override;

    // The snapshot cycle.
    SubmitOutcome Submit(const SubmitInput& req) override;
    void          Poll(std::vector<DispatchOutcome>& out,
                       std::chrono::microseconds timeout) override;
    void          WakePoller() noexcept override;

    void ResetWorker(uint32_t worker_id) override;
    void ResetAll() override;
    std::vector<InflightEntry> SnapshotInflight() const override;

    bool     IsPaused() const noexcept override;
    bool     IsClosed() const noexcept override;
    uint32_t MaxWorkerSlots() const noexcept override;
    bool     IsWorkerSendable(uint32_t worker_id) const override;  // !busy && inner
    uint32_t CountSendableWorkers() const override;

    // [Brick 4a step 3b — recovery-on-wedge] Atomic test-and-clear: returns true
    // iff a silent wedge was latched (in Poll) since the last call. A
    // WedgeRelaySensor on the health monitor polls this and publishes a crash
    // event → SnapshotRecovery(kReloadSnapshot) → ResetAll → the next Submit's
    // loadvm S0 unsticks the wedged VM. Mirrors the XiUOS wedge-relay path.
    bool ConsumeWedgePending() noexcept { return wedge_pending_.exchange(false); }

private:
    struct Qmp;
    bool EnsureQmpConnected();      // lazy connect via monitor_endpoint_fn_
    bool EnsureSnapshotSaved();     // first time: qmp_capabilities + x-ignore-shared + savevm

    // [Brick 4a step 3] VMI-on-wedge: read printk ring + stuck PC from guest RAM.
    void ResolveLogBufVaddr();      // read __log_buf vaddr from the System.map (once)
    void ReadWedgeEvidence(uint64_t executor_id);  // QMP pmemsave __log_buf + info registers

    std::unique_ptr<IDataPlane>  inner_;
    std::function<std::string()> monitor_endpoint_fn_;
    std::string                  tag_;
    std::string                  vmlinux_path_;     // for System.map + addr2line
    uint32_t                     wedge_threshold_ms_ = 0;  // 0 = VMI-on-wedge disabled
    uint64_t                     log_buf_vaddr_ = 0;       // resolved from System.map
    bool                         log_buf_resolved_ = false;
    std::unique_ptr<Qmp>         qmp_;
    bool                         s0_saved_ = false;
    std::atomic<bool>            busy_{false};  // global 1-in-flight gate
    // In-flight wedge tracking (drives VMI-on-wedge + recovery-on-wedge).
    std::chrono::steady_clock::time_point inflight_start_tp_{};
    uint64_t                     inflight_executor_id_ = 0;
    bool                         wedge_reported_ = false;  // fire VMI once per program
    std::atomic<bool>            wedge_pending_{false};    // latched for the WedgeRelaySensor
};

}  // namespace refuzz::channel::data

#include "refuzz/channel/control/control_plane.hpp"
#include "refuzz/channel/data/data_plane.hpp"
#include "refuzz/channel/recovery/fault_policy.hpp"
#include "refuzz/channel/recovery/recovery_exe.hpp"
#include "refuzz/channel/substrate/substrate_contract.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <initializer_list>
#include <string>
#include <utility>
#include <vector>

namespace cc = refuzz::core::channel_contract;
namespace ch = refuzz::channel;
namespace control = refuzz::channel::control;
namespace data = refuzz::channel::data;
namespace rec = refuzz::channel::recovery;
namespace runtime = refuzz::channel::runtime;

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__); \
            std::abort();                                                          \
        }                                                                          \
    } while (false)

#define RUN_TEST(fn)                                                               \
    do {                                                                           \
        fn();                                                                      \
        std::fprintf(stderr, "[PASS] %s\n", #fn);                                  \
    } while (false)

void CheckCalls(const std::vector<std::string>& actual,
                std::initializer_list<const char*> expected)
{
    if (actual.size() != expected.size()) {
        std::fprintf(stderr, "call count mismatch: got %zu expected %zu\n",
                     actual.size(), expected.size());
        std::abort();
    }

    size_t i = 0;
    for (const char* want : expected) {
        if (actual[i] != want) {
            std::fprintf(stderr, "call[%zu] mismatch: got %s expected %s\n",
                         i, actual[i].c_str(), want);
            std::abort();
        }
        ++i;
    }
}

class RecordingSubstrate final : public runtime::ISubstrate {
public:
    explicit RecordingSubstrate(std::vector<std::string>* calls) : calls_(calls) {}

    ch::Result<void> StartVM(uint32_t) override { return Record("substrate.StartVM"); }
    void StopVM(uint32_t) override { calls_->push_back("substrate.StopVM"); }
    ch::Result<void> RebootVM(uint32_t) override { return Record("substrate.RebootVM"); }
    bool IsVMAlive(uint32_t) const override { return true; }
    ch::Result<void> Close() override { return Record("substrate.Close"); }

    ch::Result<void> CopyFileTo(uint32_t, const std::string&, const std::string&,
                                std::chrono::milliseconds) override
    {
        return Record("substrate.CopyFileTo");
    }

    ch::Result<std::string> RunCommand(uint32_t, const std::string&,
                                       std::chrono::milliseconds) override
    {
        calls_->push_back("substrate.RunCommand");
        if (fail_op_ == "substrate.RunCommand") {
            return ch::Error{fail_kind_, "injected substrate.RunCommand failure"};
        }
        return ch::Result<std::string>::Ok("ok");
    }

    ch::Result<void> DeployArtifacts(uint32_t, const runtime::DeployBundle&) override
    {
        return Record("substrate.DeployArtifacts");
    }

    ch::Result<void> StartAllWorkers(uint32_t) override
    {
        return Record("substrate.StartAllWorkers");
    }

    ch::Result<void> StopAllWorkers(uint32_t) override
    {
        return Record("substrate.StopAllWorkers");
    }

    ch::Result<void> StartWorker(uint32_t, uint32_t worker_id) override
    {
        return Record("substrate.StartWorker[" + std::to_string(worker_id) + "]");
    }

    ch::Result<void> StopWorker(uint32_t, uint32_t) override
    {
        return Record("substrate.StopWorker");
    }

    refuzz::channel::evidence::ConsoleEndpoint
    DefaultConsoleEndpoint(uint32_t) const override
    {
        return {};
    }

    runtime::VendorHints Hints(uint32_t) const override { return {}; }
    std::string Diagnose(uint32_t) const override { return "recording-substrate"; }

    void Fail(std::string op, ch::ErrorKind kind)
    {
        fail_op_ = std::move(op);
        fail_kind_ = kind;
    }

private:
    ch::Result<void> Record(const std::string& op)
    {
        calls_->push_back(op);
        if (fail_op_ == op) {
            return ch::Error{fail_kind_, "injected " + op + " failure"};
        }
        return ch::Result<void>::Ok();
    }

    std::vector<std::string>* calls_ = nullptr;
    std::string fail_op_;
    ch::ErrorKind fail_kind_ = ch::ErrorKind::kRecovery;
};

class RecordingControlPlane final : public control::IControlPlane {
public:
    explicit RecordingControlPlane(std::vector<std::string>* calls) : calls_(calls) {}

    ch::Result<void> BeginSession() override { return Record("control.BeginSession"); }
    ch::Result<void> WaitAllWorkersReady(std::chrono::milliseconds) override
    {
        return Record("control.WaitAllWorkersReady");
    }
    ch::Result<void> WaitWorkerReady(uint32_t worker_id,
                                     std::chrono::milliseconds) override
    {
        return Record("control.WaitWorkerReady[" +
                      std::to_string(worker_id) + "]");
    }
    ch::Result<void> ResetSession() override { return Record("control.ResetSession"); }
    ch::Result<void> ResetWorkerSession(uint32_t) override
    {
        return Record("control.ResetWorkerSession");
    }
    ch::Result<void> ClearProcIsolationState() override
    {
        return Record("control.ClearProcIsolationState");
    }
    ch::Result<void> EndSession() override { return Record("control.EndSession"); }

    control::SessionState CurrentState() const override { return control::SessionState::kReady; }
    uint32_t RegisteredWorkerCount() const override { return worker_count_; }
    bool IsWorkerRegistered(uint32_t worker_id) const override { return worker_id < worker_count_; }
    void RevokeWorker(uint32_t) override {}

    control::WorkerHeartbeatSample SampleHeartbeat(uint32_t worker_id) override
    {
        return control::WorkerHeartbeatSample{
            .worker_id = worker_id,
            .counter = 1,
            .sampled_ts_us = 1,
            .valid = worker_id < worker_count_,
        };
    }

    ch::Result<void> RequestCancel(uint32_t, uint64_t) override
    {
        return ch::Result<void>::Ok();
    }
    bool ReadCancelAck(uint32_t, uint64_t) override { return false; }

    control::SendabilityView GetSendabilityView() override
    {
        return control::SendabilityView{
            .is_registered = [this](uint32_t worker_id) {
                return IsWorkerRegistered(worker_id);
            },
            .registered_worker_count = [this]() {
                return RegisteredWorkerCount();
            },
        };
    }

    control::RegistrationControlHook GetRegistrationHook() override { return {}; }
    uint32_t MaxWorkerSlots() const noexcept override { return worker_count_; }
    uint32_t WorkerCount() const noexcept override { return worker_count_; }

    void Fail(std::string op, ch::ErrorKind kind)
    {
        fail_op_ = std::move(op);
        fail_kind_ = kind;
    }

private:
    ch::Result<void> Record(const std::string& op)
    {
        calls_->push_back(op);
        if (fail_op_ == op) {
            return ch::Error{fail_kind_, "injected " + op + " failure"};
        }
        return ch::Result<void>::Ok();
    }

    std::vector<std::string>* calls_ = nullptr;
    uint32_t worker_count_ = 4;
    std::string fail_op_;
    ch::ErrorKind fail_kind_ = ch::ErrorKind::kRecovery;
};

class RecordingDataPlane final : public data::IDataPlane {
public:
    explicit RecordingDataPlane(std::vector<std::string>* calls) : calls_(calls) {}

    ch::Result<void> StartServer() override { return Record("data.StartServer"); }
    ch::Result<void> Prepare() override { return Record("data.Prepare"); }
    void Close() override { calls_->push_back("data.Close"); }
    void Pause() override { calls_->push_back("data.Pause"); }
    void Resume() override { calls_->push_back("data.Resume"); }

    data::SubmitOutcome Submit(const data::IDataPlane::SubmitInput&) override
    {
        return data::SubmitOutcome::kSent;
    }

    void Poll(std::vector<data::DispatchOutcome>&, std::chrono::microseconds) override {}
    void WakePoller() noexcept override {}

    void ResetWorker(uint32_t) override { calls_->push_back("data.ResetWorker"); }
    void ResetAll() override { calls_->push_back("data.ResetAll"); }

    std::vector<data::InflightEntry> SnapshotInflight() const override
    {
        return {
            data::InflightEntry{
                .worker_id = 0,
                .executor_id = 101,
                .dispatch_gen = 1,
                .cancel_requested = false,
                .cancel_observed_seq = 0,
            },
        };
    }

    bool IsPaused() const noexcept override { return false; }
    bool IsClosed() const noexcept override { return false; }
    uint32_t MaxWorkerSlots() const noexcept override { return 4; }
    bool IsWorkerSendable(uint32_t worker_id) const override { return worker_id < 4; }

private:
    ch::Result<void> Record(const std::string& op)
    {
        calls_->push_back(op);
        return ch::Result<void>::Ok();
    }

    std::vector<std::string>* calls_ = nullptr;
};

void TestWorkerFaultUsesSingleWorkerWhileAttemptsRemain()
{
    rec::EscalationPolicy policy;

    rec::FaultContext context;
    context.source_worker_id = 1;
    context.total_workers = 4;
    context.unusable_workers = 1;

    rec::FaultHistory history;
    history.source_worker_failed_recovery_count = 2;

    auto decision = policy.Decide(cc::ChannelFaultReason::kWorkerHeartbeatLost,
                                  history,
                                  context);
    CHECK(decision.action == cc::RecoveryAction::kRestartSingleWorker);
    CHECK(decision.abort_scope == cc::ChannelAbortScope::kSlot);
    CHECK(decision.target_worker_id == 1);
}

void TestWorkerFaultAttemptsExhaustedBelowRatioRunsDegraded()
{
    // 单 worker 重试预算用尽，但掉的 worker 占比未到阈值（1/4=25% < 50%）：
    //   不再 kRestartAllWorkers（旧行为，会误伤健康 worker），改为 kNone——隔离该
    //   worker、跑降级 N-1，等掉够阈值再一次 reboot 收回全队。
    rec::EscalationPolicy::Config cfg;
    cfg.max_single_worker_restart_attempts = 3;
    cfg.unusable_ratio_reboot_threshold_pct = 50;
    rec::EscalationPolicy policy(cfg);

    rec::FaultContext context;
    context.source_worker_id = 1;
    context.total_workers = 4;
    context.unusable_workers = 1;

    rec::FaultHistory history;
    history.source_worker_failed_recovery_count = 3;

    auto decision = policy.Decide(cc::ChannelFaultReason::kWorkerHeartbeatLost,
                                  history,
                                  context);
    CHECK(decision.action == cc::RecoveryAction::kNone);
    CHECK(decision.abort_scope == cc::ChannelAbortScope::kNone);
}

void TestWorkerFaultInRecoveryWindowAbsorbs()
{
    // 保护窗内（reboot 刚完成、workers 还在重新注册）：心跳 miss 是预期的，
    //   一律 kNone，连单 worker 重启都不做。即使重试预算还在也吸收。
    rec::EscalationPolicy policy;

    rec::FaultContext context;
    context.source_worker_id = 1;
    context.total_workers = 4;
    context.unusable_workers = 1;

    rec::FaultHistory history;
    history.source_worker_failed_recovery_count = 0;  // 预算充足
    history.in_recovery_window = true;                // 但在保护窗内

    auto decision = policy.Decide(cc::ChannelFaultReason::kWorkerHeartbeatLost,
                                  history,
                                  context);
    CHECK(decision.action == cc::RecoveryAction::kNone);
}

void TestHarnessFatalBypassesRecoveryWindow()
{
    rec::EscalationPolicy policy;

    rec::FaultContext context;
    context.source_worker_id = 1;
    context.total_workers = 4;
    context.unusable_workers = 1;

    rec::FaultHistory history;
    history.in_recovery_window = true;

    auto decision = policy.Decide(cc::ChannelFaultReason::kWorkerHarnessFatal,
                                  history,
                                  context);
    CHECK(decision.action == cc::RecoveryAction::kRestartSingleWorker);
    CHECK(decision.abort_scope == cc::ChannelAbortScope::kSlot);
    CHECK(decision.target_worker_id == 1);
}

void TestHarnessFatalEscalatesAfterWorkerBudget()
{
    rec::EscalationPolicy::Config cfg;
    cfg.max_single_worker_restart_attempts = 3;
    cfg.max_vm_reboot_attempts = 2;
    cfg.cascade_reboot_budget = 2;
    rec::EscalationPolicy policy(cfg);

    rec::FaultContext context;
    context.source_worker_id = 1;
    context.total_workers = 4;
    context.unusable_workers = 1;

    rec::FaultHistory history;
    history.source_worker_failed_recovery_count = 3;
    history.in_recovery_window = true;

    auto decision = policy.Decide(cc::ChannelFaultReason::kWorkerHarnessFatal,
                                  history,
                                  context);
    CHECK(decision.action == cc::RecoveryAction::kRebootVm);
    CHECK(decision.abort_scope == cc::ChannelAbortScope::kChannel);

    history.vm_reboot_count = 2;
    decision = policy.Decide(cc::ChannelFaultReason::kWorkerHarnessFatal,
                             history,
                             context);
    CHECK(decision.action == cc::RecoveryAction::kFailChannel);
    CHECK(decision.abort_scope == cc::ChannelAbortScope::kChannel);
}

void TestExecutionDomainHangRebootsWithoutWorkerRestart()
{
    rec::EscalationPolicy::Config cfg;
    cfg.max_single_worker_restart_attempts = 3;
    cfg.max_vm_reboot_attempts = 2;
    cfg.cascade_reboot_budget = 2;
    rec::EscalationPolicy policy(cfg);

    rec::FaultContext context;
    context.source_worker_id = 1;
    context.total_workers = 4;
    context.unusable_workers = 1;

    rec::FaultHistory history;
    history.in_recovery_window = true;

    auto decision = policy.Decide(
        cc::ChannelFaultReason::kExecutionDomainHung, history, context);
    CHECK(decision.action == cc::RecoveryAction::kRebootVm);
    CHECK(decision.abort_scope == cc::ChannelAbortScope::kChannel);

    history.vm_reboot_count = 2;
    decision = policy.Decide(
        cc::ChannelFaultReason::kExecutionDomainHung, history, context);
    CHECK(decision.action == cc::RecoveryAction::kFailChannel);
    CHECK(decision.abort_scope == cc::ChannelAbortScope::kChannel);
}

void TestCorroboratedVmDeadBypassesWindowRespectsCeiling()
{
    // 佐证型 VM 死（qemu 退 / console panic）:预算内立即 reboot,绕过 recovery-window
    //   *延迟*（确凿故障不该被自我放大的 liveness 保护窗拖）——但 cascade/reboot 硬上限
    //   **仍适用**:反复确凿死亡 = reboot 治不好它 → kFailChannel,不是无限 reboot
    //   (旧实现 corroborated 无条件 reboot,正是 4516 次风暴的末端放大器)。
    rec::EscalationPolicy::Config cfg;
    cfg.cascade_reboot_budget = 2;
    cfg.max_vm_reboot_attempts = 2;
    rec::EscalationPolicy policy(cfg);

    rec::FaultContext context;
    context.source_worker_id = UINT32_MAX;
    context.total_workers = 4;

    // ① 预算内 + 在保护窗内:佐证型绕过窗延迟 → 立即 kRebootVm
    rec::FaultHistory in_window;
    in_window.in_recovery_window = true;       // 保护窗内
    in_window.reboots_in_cascade_window = 1;   // 预算内 (< 2)
    in_window.vm_reboot_count = 1;             // 上限内 (< 2)
    context.corroborated = true;
    auto bypass = policy.Decide(cc::ChannelFaultReason::kVmDead, in_window, context);
    CHECK(bypass.action == cc::RecoveryAction::kRebootVm);
    // 对照:同状态推断型在保护窗内被压成 kNone
    context.corroborated = false;
    auto inferred_in_window = policy.Decide(cc::ChannelFaultReason::kVmDead, in_window, context);
    CHECK(inferred_in_window.action == cc::RecoveryAction::kNone);

    // ② cascade 预算耗尽:佐证型也不再无限 reboot → kFailChannel(放弃通道)
    rec::FaultHistory exhausted;
    exhausted.reboots_in_cascade_window = 5;   // >= budget 2
    exhausted.vm_reboot_count = 0;
    context.corroborated = true;
    auto capped = policy.Decide(cc::ChannelFaultReason::kVmDead, exhausted, context);
    CHECK(capped.action == cc::RecoveryAction::kFailChannel);
    // 对照:推断型在预算耗尽时退避成 kNone(隔离/降级,不放弃通道)
    context.corroborated = false;
    auto inferred_exhausted = policy.Decide(cc::ChannelFaultReason::kVmDead, exhausted, context);
    CHECK(inferred_exhausted.action == cc::RecoveryAction::kNone);

    // ③ reboot 一直失败(vm_reboot_count 涨满,失败不清零)的佐证型也封顶 → kFailChannel
    rec::FaultHistory reboot_failing;
    reboot_failing.reboots_in_cascade_window = 0;
    reboot_failing.vm_reboot_count = 2;        // >= max 2
    context.corroborated = true;
    auto failing = policy.Decide(cc::ChannelFaultReason::kVmDead, reboot_failing, context);
    CHECK(failing.action == cc::RecoveryAction::kFailChannel);
}

void TestKernelCrashBypassesCascadeBudget()
{
    // 真 kernel crash（console panic/BUG/KASAN）是"发现"不是基础设施故障：
    //   cascade budget / 保护窗都不拦它，立即 reboot（对齐 syzkaller，不熔断）。
    //   唯一保留的封顶是 reboot 机制连续失败（vm_reboot_count，成功才清零）。
    rec::EscalationPolicy::Config cfg;
    cfg.cascade_reboot_budget = 2;
    cfg.max_vm_reboot_attempts = 2;
    rec::EscalationPolicy policy(cfg);

    rec::FaultContext context;
    context.source_worker_id = UINT32_MAX;
    context.total_workers = 4;
    context.corroborated = true;  // console 命中的 kKernelCrash 恒为佐证

    // ① cascade 预算已耗尽 + 保护窗内：真 crash 仍立即 kRebootVm
    rec::FaultHistory exhausted;
    exhausted.in_recovery_window = true;
    exhausted.reboots_in_cascade_window = 5;  // >= budget 2，但真 crash 不受限
    exhausted.vm_reboot_count = 0;
    auto reboot = policy.Decide(cc::ChannelFaultReason::kKernelCrash,
                                exhausted, context);
    CHECK(reboot.action == cc::RecoveryAction::kRebootVm);
    CHECK(reboot.abort_scope == cc::ChannelAbortScope::kChannel);

    // kNoOutput = 推断型 forward-progress frozen（inferred=true）：可汇报 finding，
    // 但 reboot 准入与推断型 kVmDead 一致 —— 保护窗内 / cascade 耗尽都必须被阻尼，
    // 不能像 kKernelCrash 那样无预算直通（否则连续冻结会变成无封顶 reboot 循环）。
    rec::FaultContext no_output_ctx;
    no_output_ctx.source_worker_id = UINT32_MAX;
    no_output_ctx.total_workers = 4;
    no_output_ctx.corroborated = false;  // frozen 恒为推断
    auto no_output = policy.Decide(cc::ChannelFaultReason::kNoOutput,
                                   exhausted, no_output_ctx);
    CHECK(no_output.action == cc::RecoveryAction::kNone);

    rec::FaultHistory fresh;
    fresh.in_recovery_window = false;
    fresh.reboots_in_cascade_window = 0;
    fresh.vm_reboot_count = 0;
    auto no_output_fresh = policy.Decide(cc::ChannelFaultReason::kNoOutput,
                                         fresh, no_output_ctx);
    CHECK(no_output_fresh.action == cc::RecoveryAction::kRebootVm);
    CHECK(no_output_fresh.abort_scope == cc::ChannelAbortScope::kChannel);

    // ② reboot 机制连续失败（vm_reboot_count 涨满，成功才清零）：仍封顶 → kFailChannel
    rec::FaultHistory reboot_failing;
    reboot_failing.reboots_in_cascade_window = 0;
    reboot_failing.vm_reboot_count = 2;  // >= max 2
    auto failing = policy.Decide(cc::ChannelFaultReason::kKernelCrash,
                                 reboot_failing, context);
    CHECK(failing.action == cc::RecoveryAction::kFailChannel);
    auto no_output_failing = policy.Decide(cc::ChannelFaultReason::kNoOutput,
                                           reboot_failing, no_output_ctx);
    CHECK(no_output_failing.action == cc::RecoveryAction::kFailChannel);

    // ③ 对照：同状态 kVmDead（基础设施故障）cascade 耗尽 → kFailChannel，
    //    证明预算约束对基础设施路径仍然生效。
    auto infra = policy.Decide(cc::ChannelFaultReason::kVmDead,
                               exhausted, context);
    CHECK(infra.action == cc::RecoveryAction::kFailChannel);
}

void TestWorkerFaultAttemptsExhaustedAtRatioReboots()
{
    rec::EscalationPolicy::Config cfg;
    cfg.max_single_worker_restart_attempts = 3;
    cfg.unusable_ratio_reboot_threshold_pct = 50;
    rec::EscalationPolicy policy(cfg);

    rec::FaultContext context;
    context.source_worker_id = 1;
    context.total_workers = 4;
    context.unusable_workers = 2;

    rec::FaultHistory history;
    history.source_worker_failed_recovery_count = 3;

    auto decision = policy.Decide(cc::ChannelFaultReason::kWorkerHeartbeatLost,
                                  history,
                                  context);
    CHECK(decision.action == cc::RecoveryAction::kRebootVm);
    CHECK(decision.abort_scope == cc::ChannelAbortScope::kChannel);
}

void TestVmDeadChoosesRebootUntilBudgetExhausted()
{
    rec::EscalationPolicy::Config cfg;
    cfg.max_vm_reboot_attempts = 2;
    rec::EscalationPolicy policy(cfg);

    rec::FaultContext context;
    context.source_worker_id = UINT32_MAX;
    context.total_workers = 4;
    context.unusable_workers = 4;

    rec::FaultHistory first;
    first.vm_reboot_count = 0;
    auto decision = policy.Decide(cc::ChannelFaultReason::kVmDead, first, context);
    CHECK(decision.action == cc::RecoveryAction::kRebootVm);
    CHECK(decision.abort_scope == cc::ChannelAbortScope::kChannel);

    rec::FaultHistory exhausted;
    exhausted.vm_reboot_count = 2;
    decision = policy.Decide(cc::ChannelFaultReason::kVmDead, exhausted, context);
    CHECK(decision.action == cc::RecoveryAction::kFailChannel);
    CHECK(decision.abort_scope == cc::ChannelAbortScope::kChannel);
}

void TestRestartAllRecoverySequenceBeginsSessionBeforeDeploy()
{
    std::vector<std::string> calls;
    RecordingSubstrate substrate(&calls);
    RecordingControlPlane cp(&calls);
    RecordingDataPlane dp(&calls);
    rec::RecoveryExe exe(&substrate, runtime::DeployBundle{}, &cp, &dp, nullptr);

    rec::ExecPlan plan;
    plan.session = rec::SessionAction::kRestartAllWorkers;

    auto result = exe.Execute(plan);
    CHECK(result.ok());
    CHECK(result.value().action == cc::RecoveryAction::kRestartAllWorkers);
    CHECK(result.value().inflight_executor_ids.size() == 1);
    CHECK(result.value().inflight_executor_ids[0] == 101);
    CheckCalls(calls, {
        "substrate.StopAllWorkers",
        "data.ResetAll",
        "control.ResetSession",
        "control.BeginSession",
        "substrate.DeployArtifacts",
        "substrate.StartWorker[0]",
        "control.WaitWorkerReady[0]",
        "substrate.StartWorker[1]",
        "control.WaitWorkerReady[1]",
        "substrate.StartWorker[2]",
        "control.WaitWorkerReady[2]",
        "substrate.StartWorker[3]",
        "control.WaitWorkerReady[3]",
        "control.WaitAllWorkersReady",
    });
}

void TestRebootRecoverySequenceRebuildsDataPlaneBeforeSession()
{
    std::vector<std::string> calls;
    RecordingSubstrate substrate(&calls);
    RecordingControlPlane cp(&calls);
    RecordingDataPlane dp(&calls);
    rec::RecoveryExe exe(&substrate, runtime::DeployBundle{}, &cp, &dp, nullptr);

    rec::ExecPlan plan;
    plan.session = rec::SessionAction::kRestartAllWorkers;
    plan.substrate = rec::SubstrateAction::kRebootInstance;

    auto result = exe.Execute(plan);
    CHECK(result.ok());
    CHECK(result.value().action == cc::RecoveryAction::kRebootVm);
    CHECK(result.value().inflight_executor_ids.size() == 1);
    CHECK(result.value().inflight_executor_ids[0] == 101);
    CheckCalls(calls, {
        "data.ResetAll",
        "control.ResetSession",
        "data.StartServer",
        "substrate.RebootVM",
        "control.ClearProcIsolationState",
        "data.Prepare",
        "control.BeginSession",
        "substrate.DeployArtifacts",
        "substrate.StartWorker[0]",
        "control.WaitWorkerReady[0]",
        "substrate.StartWorker[1]",
        "control.WaitWorkerReady[1]",
        "substrate.StartWorker[2]",
        "control.WaitWorkerReady[2]",
        "substrate.StartWorker[3]",
        "control.WaitWorkerReady[3]",
        "control.WaitAllWorkersReady",
    });
}

void TestSequentialWorkerStartupRollsBackOnReadyFailure()
{
    std::vector<std::string> calls;
    RecordingSubstrate substrate(&calls);
    RecordingControlPlane cp(&calls);
    RecordingDataPlane dp(&calls);
    cp.Fail("control.WaitWorkerReady[2]", ch::ErrorKind::kTimeout);
    rec::RecoveryExe exe(&substrate, runtime::DeployBundle{}, &cp, &dp, nullptr);

    rec::ExecPlan plan;
    plan.session = rec::SessionAction::kRestartAllWorkers;

    auto result = exe.Execute(plan);
    CHECK(!result.ok());
    CHECK(result.error().kind == ch::ErrorKind::kTimeout);
    CHECK(result.error().message.find("worker[2]") != std::string::npos);
    CheckCalls(calls, {
        "substrate.StopAllWorkers",
        "data.ResetAll",
        "control.ResetSession",
        "control.BeginSession",
        "substrate.DeployArtifacts",
        "substrate.StartWorker[0]",
        "control.WaitWorkerReady[0]",
        "substrate.StartWorker[1]",
        "control.WaitWorkerReady[1]",
        "substrate.StartWorker[2]",
        "control.WaitWorkerReady[2]",
        "substrate.StopAllWorkers",
    });
}

void TestRecoveryExePreservesTimeoutKind()
{
    std::vector<std::string> calls;
    RecordingSubstrate substrate(&calls);
    RecordingControlPlane cp(&calls);
    RecordingDataPlane dp(&calls);
    substrate.Fail("substrate.DeployArtifacts", ch::ErrorKind::kTimeout);
    rec::RecoveryExe exe(&substrate, runtime::DeployBundle{}, &cp, &dp, nullptr);

    rec::ExecPlan plan;
    plan.session = rec::SessionAction::kRestartAllWorkers;

    auto result = exe.Execute(plan);
    CHECK(!result.ok());
    CHECK(result.error().kind == ch::ErrorKind::kTimeout);
    CHECK(result.error().message.find("DeployArtifacts failed") != std::string::npos);
}

void TestRecoveryExePreservesConnectionKind()
{
    std::vector<std::string> calls;
    RecordingSubstrate substrate(&calls);
    RecordingControlPlane cp(&calls);
    RecordingDataPlane dp(&calls);
    substrate.Fail("substrate.RebootVM", ch::ErrorKind::kConnection);
    rec::RecoveryExe exe(&substrate, runtime::DeployBundle{}, &cp, &dp, nullptr);

    rec::ExecPlan plan;
    plan.session = rec::SessionAction::kRestartAllWorkers;
    plan.substrate = rec::SubstrateAction::kRebootInstance;

    auto result = exe.Execute(plan);
    CHECK(!result.ok());
    CHECK(result.error().kind == ch::ErrorKind::kConnection);
    CHECK(result.error().message.find("RebootVM failed") != std::string::npos);
}

int main()
{
    RUN_TEST(TestWorkerFaultUsesSingleWorkerWhileAttemptsRemain);
    RUN_TEST(TestWorkerFaultAttemptsExhaustedBelowRatioRunsDegraded);
    RUN_TEST(TestWorkerFaultInRecoveryWindowAbsorbs);
    RUN_TEST(TestHarnessFatalBypassesRecoveryWindow);
    RUN_TEST(TestHarnessFatalEscalatesAfterWorkerBudget);
    RUN_TEST(TestExecutionDomainHangRebootsWithoutWorkerRestart);
    RUN_TEST(TestCorroboratedVmDeadBypassesWindowRespectsCeiling);
    RUN_TEST(TestKernelCrashBypassesCascadeBudget);
    RUN_TEST(TestWorkerFaultAttemptsExhaustedAtRatioReboots);
    RUN_TEST(TestVmDeadChoosesRebootUntilBudgetExhausted);
    RUN_TEST(TestRestartAllRecoverySequenceBeginsSessionBeforeDeploy);
    RUN_TEST(TestRebootRecoverySequenceRebuildsDataPlaneBeforeSession);
    RUN_TEST(TestSequentialWorkerStartupRollsBackOnReadyFailure);
    RUN_TEST(TestRecoveryExePreservesTimeoutKind);
    RUN_TEST(TestRecoveryExePreservesConnectionKind);
    return 0;
}

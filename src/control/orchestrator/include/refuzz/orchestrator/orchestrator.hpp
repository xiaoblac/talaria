// Copyright 2026 reFuzz project author -------youngkk.

#pragma once

#include "refuzz/feedback/engine/feedback_engine_catalog.hpp"
#include "refuzz/orchestrator/orchestrator_config.hpp"
#include "refuzz/orchestrator/profile_registry.hpp"
#include "refuzz/resolver/resolver.hpp"
#include "refuzz/startup/launch_plan.hpp"

#include <memory>
#include <optional>
#include <string>

namespace refuzz::orchestrator {

// Orchestrator:fuzzing 编排器 —— 从 LaunchPlan 走完 Resolver/Assembler,
// 装配运行时骨架(Executor/FuzzerLoop/Telemetry/CrashPipeline/ReproManager/
// ServiceRegistry)并管理其 Start/Stop 生命周期。
//
// 典型流程(见 tools/refuzz_main.cpp):
//   auto parsed = startup::ParseLaunchPlan(cfg_path);
//   Orchestrator orch;
//   if (!orch.Build(std::move(parsed->plan),
//                   std::move(parsed->ad_hoc_feedback_spec))) return 1;
//   if (!orch.Start()) return 1;
//   orch.WaitForCompletion();
//   return orch.Stop();
class Orchestrator {
public:
    Orchestrator();
    ~Orchestrator();

    Orchestrator(const Orchestrator&) = delete;
    Orchestrator& operator=(const Orchestrator&) = delete;

    // 按新架构装配:Startup → Resolver → Assembler → Runtime。
    //
    // 参数:
    //   plan         ParseLaunchPlan 产物,承载用户意图 + OrchestratorConfig
    //   spec         可选 ad-hoc FeedbackEngineSpec(Startup 的 feedback_engine_spec 段)
    //   profile_reg  可选 profile registry 注入(单测用 mock profile 注入);
    //                nullptr 时 Orchestrator 内部自建并调 RegisterBuiltinProfiles()
    //   resolve_opts 传给 Resolver 的选项(当前仅为占位,后续可扩展)
    // 返回 false:resolver/assembler/资源校验失败;失败时 impl_ 已 reset。
    bool Build(refuzz::startup::LaunchPlan plan,
               std::optional<fuzzer::FeedbackEngineSpec> spec = std::nullopt,
               ProfileRegistry* profile_reg = nullptr,
               refuzz::resolver::ResolveOptions resolve_opts = {});

    // 启动所有后台线程（executor、fuzzer loop、telemetry、coverage）。
    // Build() 成功后调用，返回 false 表示启动失败。
    bool Start();

    // 等待运行完成（达到运行上限，或 executor 请求停止）。
    // 运行上限由 cfg.run_limit_mode 决定：runtime / total_tasks / both。
    // 阻塞直到 fuzzer loop 线程退出。
    void WaitForCompletion();

    // [v2 PR-K-E2 — graceful shutdown 当前版本]
    // 异步停机请求:翻 impl_->stop_requested,fuzzer_thread 下一次循环 check
    // 命中后退出,WaitForCompletion() 解阻塞,后续 Stop() 跑完 final flush
    // (coverage SaveToFile / admit_worker StopAndDrain / metrics 收尾)。
    //
    // 调用约束:
    //   - 必须在 Start() 之后、Stop() 之前;Build 失败/未跑过 Start 时 no-op
    //   - signal-safe:仅做 lock-free atomic store,可在 SIGINT handler 内直调
    //   - 幂等:多次调用等价于一次
    void RequestStop();

    // 优雅关停所有子系统，输出最终指标，返回退出码（0 = 有进度，1 = 无进度）。
    int Stop();

private:
    // Pimpl：隐藏所有子系统实例，避免头文件依赖爆炸。
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace refuzz::orchestrator

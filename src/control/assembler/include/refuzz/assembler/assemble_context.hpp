// Copyright 2026 reFuzz project author -------youngkk.
//
// AssembleContext
//
// Assembler 的横切依赖注入点。所有"装配期需要、但生命周期归外部"
// 的资源通过此结构传入(by pointer,nullable 语义见各字段注释)。
//
// Assembler 本身是纯函数:同输入 → 同输出。AssembleContext 中的指针
// 在 Assembler::Assemble 返回后 **必须继续有效至少到 AssembledBundle
// 析构**,因为 feedback engine 等 bundle 内部组件会捕获指针。

#pragma once

#include "refuzz/orchestrator/profile_registry.hpp"


namespace refuzz::core::metrics { class MetricRegistry; }

namespace refuzz::assembler {

struct AssembleContext {
    // 用于拿 profile.derive_repro_channel_cfg(Assembler 不存 profile defaults
    // 里的 lambda,通过 registry 按名查)。non-null 约定。
    const orchestrator::ProfileRegistry* profile_registry = nullptr;

    // [v2 metric bus — Step 5a] MetricRegistry 注入点。
    // * nullptr = 不绑定 ChannelMetrics (降级为旧行为)
    // * non-null 时,Orchestrator 必须保证其生命周期晚于 AssembledBundle。
    core::metrics::MetricRegistry* metric_registry = nullptr;
};

} // namespace refuzz::assembler

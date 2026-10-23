// Copyright 2026 reFuzz project author -------youngkk.
//
// builtin_profiles.hpp
//
// 统一注册内置 profile(目前仅 "kernel")的入口。由 Orchestrator::Build() 在
// 装配早期显式调用,替代旧的 REGISTER_PROFILE 静态初始化 + --whole-archive
// 链接 hack。

#pragma once

#include "refuzz/orchestrator/profile_registry.hpp"

namespace refuzz::profile {

// 把所有内置 ProfileDefaults 注册到 registry。
// 同名 profile 会被覆盖——允许测试 / 用户覆盖默认 kernel profile。
void RegisterBuiltinProfiles(orchestrator::ProfileRegistry& registry);

// 内置 profile 构造函数(导出供测试单独调用)。
//
// [2026-05-08 swap rename] 历史名 MakeKernelProfile / MakeKernelProfileWithTriage 已
// swap:"kernel" 现在 = syzkaller-equivalent default(triage chain 启用),
// "kernel_no_triage" 是显式 opt-out 退化版。改动来源 docs/admit-pipeline-alignment/100_batch1_default_triage.md

// 显式 opt-out 退化版 profile(name="kernel_no_triage"):
//   producer:[gen_p, mut_p]
//   consumer:[mut_c]
// 无 triage / minimize / smash / hints / fault chain。仅供已知不需要 deflake 的场景使用。
ProfileDefaults MakeKernelNoTriageProfile();

// reFuzz 一等公民 default profile(name="kernel"):在 MakeKernelNoTriageProfile() 基础上把 chain 升级为
//   producer:[min_p, triage_p, smash_p, hints_p, fault_p, gen_p, mut_p]
//   consumer:[triage_c, min_c, hints_c, fault_c, mut_c]
// 并把 mutational_consumer.triage_enabled=true、triage_reexec_producer.count=3、
// minimize_producer.attempts=3+mode=kCallsOnly、
// hints_producer.enabled / fault_injection_producer.enabled = "auto"
// (Resolver 按 feedback_engine / target 自动 flip)。
// **default profile**:用户 LaunchPlan 不指定 profile 字段时落到此处。
ProfileDefaults MakeKernelProfile();

// [v2 Phase 4 Step 4.4 — 当前版本]
// 可选 opt-in profile(name="kernel_full"):以 MakeKernelProfile()(swap 后已含
// smash/hints/fault stage)为 base 拷贝。chain 字面与 default kernel 等价:
//   producer:[min_p, triage_p, smash_p, hints_p, fault_p, gen_p, mut_p]
//   consumer:[triage_c, min_c, hints_c, fault_c, mut_c]    (沿用 default kernel chain 不变)
// 注:swap rename 后 kernel_full 跟 default kernel 实质等价 — 待 follow-up
// 整改 kernel_full 真实增量内容(批次 4 / 7-family review)。
// smash = 固定 25 变体的 emit job(= syz `const iters = 25`),逐变体 fire-and-forget,
// 经 arbiter 的 request-window 自然节流(无 window 耦合 invariant、无 assembler 校验)。
// **不替换默认 kernel profile**。
ProfileDefaults MakeKernelProfileFull();

// [Stage 3 去山头] XiUOS RTOS profile(name="xiuos"):
//   channel=qemu_uart_xiuos / toolkit=xiuos / mutator=xiuos / feedback=xiuos_kcov /
//   corpus=in_memory(LenientBytes,bytes-only) / chain producer:[mut_p] consumer:[mut_c]。
// 把 XiuosFuzzSession 私有闭环收敛进 FuzzerLoop + stage + feedback + crash_pipeline。
ProfileDefaults MakeXiuosProfile();


} // namespace refuzz::profile

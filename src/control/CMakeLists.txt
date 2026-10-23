cmake_minimum_required(VERSION 3.15)
project(refuzz_control CXX)

# P6: config_parser 先于 refuzz_control,供其链接 refuzz_config_parser。
add_subdirectory(config_parser)

# [syscall-support-detection] host-side support detection (syz pkg/vminfo
# analog); linked by refuzz_assembler + refuzz_profile. Owns the machine_check
# sub-library (execution-based detection) via its own add_subdirectory.
add_subdirectory(support)

add_library(refuzz_control
    src/loop/fuzzer_loop.cpp
    src/loop/elaboration_dispatch.cpp  # [Step 4d] 富化触发 wiring(flag-gate: push follow-up ↔ spawn job/无栈 op)
    src/loop/async_admit_worker.cpp
    src/loop/minimize_admit.cpp  # minimize 完成 admit + RunOnce demux 投影(loop-home;拆自 minimize_support)
    # [mab-stage-selection] task-MAB 决策协调器(复用 core 的 refuzz::mab::Exp3Bandit +
    # MabReward;那两个共享原语已下沉 refuzz_core,见根 CMakeLists)。
    src/mab/mab_task_selector.cpp
    # [Step 6 stage 清场] stage framework + 全部 stage 类 .cpp 已物删。幸存的两个 framework-free
    #   算法单元(core-path job / minimize 复用)留在原路径:
    src/stage/triage_deflake.cpp   # pure deflake analysis(core-path job 复用)
    src/stages/minimize_driver.cpp # MinimizeDriver(core-path job minimize)
    # [job-loop 重设计 Step 1] JobContext + exec() choke point + N-job strict-alternation 调度器。
    # 隔离建立,暂不接 FuzzerLoop(Step 2 迁 minimize 时才 wire)。见 docs/job-loop-redesign/。
    src/job/job.cpp
    src/job/job_scheduler.cpp
    src/job/core_path_job.cpp  # [Step 3 Slice C3] 融合 deflake+minimize 的 core-path job(RunInline → 1 线程/job)
    src/job/fault_job.cpp  # [Step 4a] fault-inject 依赖循环 job(nth=1..100,复用 MakeFaultInjectVariant)
    src/job/hints_job.cpp  # [Step 4b/5] hints mixed job(collect-comps exec + hint variant emit)
    src/job/smash_op.cpp  # [Step 4c] smash 无栈定向 op(burst submit N 变体,非 job,结果回 catch-all)
    src/job/explore_job.cpp  # [Step 5] explore job(⑤ = syz genFuzz):while-emit,produce/归因经 seam 注入
    src/job/candidate_job.cpp  # [Step 3] candidate feeder job(② = syz candidateQueue 喂入)
    # [fixed request stream, Step 4] docs/plans/fixed-request-stream-performance-replay.md.
    # request stream 输入是 fuzz loop 的一种 producer 变体,故落在 control 内,不设独立 module:
    #   reader(v1 schema 解析)+ FixedInputProducerJob(唯一提交口 emit,不自愈重 spawn)。
    src/request_stream_reader.cpp
    src/request_stream_sink.cpp
    src/job/fixed_input_producer_job.cpp
    orchestrator/src/profile_registry.cpp
    orchestrator/src/orchestrator.cpp
    orchestrator/src/builtins.cpp

    # Phase 2 §C #22 follow-up — XiuosFuzzSession (lightweight closed-loop
    # session over XiUOS Channel + admission + scheduler + mutator + bucket).
    # Not part of the production FuzzerLoop; the entry point for the
    # XiUOS test harness + ad-hoc stress runs.
    src/xiuos/xiuos_fuzz_session.cpp
)

target_include_directories(refuzz_control
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        # Phase 0 重构:从 PRIVATE 改为 PUBLIC。新架构下 OrchestratorConfig
        # 嵌入 LaunchPlan/ResolvedPlan 并被 refuzz_startup/profile/resolver/
        # assembler 4 个子库复用,其 header 路径必须对外可见。
        ${CMAKE_CURRENT_SOURCE_DIR}/orchestrator/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/..
        ${CMAKE_CURRENT_SOURCE_DIR}/../executor/channel/runtime/src/substrate/vm
        ${CMAKE_CURRENT_SOURCE_DIR}/../executor/channel/worker/include
)

target_link_libraries(refuzz_control
    PUBLIC
        refuzz_config_parser
        refuzz_program
        refuzz_mutator
        refuzz_feedback
        refuzz_corpus
        refuzz_queue
        refuzz_channel
        refuzz_crash
        refuzz_telemetry
        refuzz_core
        refuzz_proto_domain
        refuzz_proto_wire
    PRIVATE
        refuzz_logging
        # [machine-check C4.6 ③] orchestrator runs RunMachineCheck at startup;
        # transitively brings refuzz_support (resolve_enabled_calls / SupportEnv).
        refuzz_machine_check
        # [job-loop] each Job runs as a libaco stackful coroutine (job.cpp),
        # not an OS thread. Vendored under third_party/libaco.
        aco
)

add_subdirectory(orchestrator)
# P6: startup 在 profile 之前;config_parser 已先于本库。
add_subdirectory(startup)
add_subdirectory(profile)
add_subdirectory(resolver)
add_subdirectory(assembler)

target_link_libraries(refuzz_control PRIVATE refuzz_assembler)

# orchestrator/profile_registry.hpp 是 refuzz_control 的 PUBLIC header,
# 其中 include 了 refuzz/profile/profile_defaults.hpp——所以 refuzz_control
# 的消费者必须能找到 refuzz_profile 的 include 路径。PUBLIC 链接即可。
target_link_libraries(refuzz_control PUBLIC refuzz_profile)

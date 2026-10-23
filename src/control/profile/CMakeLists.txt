cmake_minimum_required(VERSION 3.15)
project(refuzz_profile CXX)

# P3 起改为 STATIC:除 profile_defaults.hpp 外,还承载内置 profile 的定义
# (MakeKernelProfile / RegisterBuiltinProfiles)。显式调 RegisterBuiltinProfiles()
# 替代了旧的 REGISTER_PROFILE 静态初始化宏 + --whole-archive 链接 hack。
add_library(refuzz_profile STATIC
    src/profiles/kernel_profile.cpp
    src/profiles/xiuos_profile.cpp
    src/builtin_profiles.cpp
)

target_include_directories(refuzz_profile PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    # OrchestratorConfig / SessionLayout 位于 control/orchestrator/include;
    # refuzz_profile 仅对其做 header-only 引用(字段访问、lambda 签名),
    # 不调任何非 inline 成员——因此只加 include 路径、不链接 refuzz_control,
    # 避免 refuzz_control ↔ refuzz_profile 静态库循环依赖。
    ${CMAKE_CURRENT_SOURCE_DIR}/../orchestrator/include
)

target_link_libraries(refuzz_profile
    PUBLIC
        refuzz_startup
        refuzz_channel    # channel_backend_id 常量 + QemuIvshmemLinuxProfile 符号
        refuzz_core
        # [v2 PR2 — Corpus Generation Adaptation] CorpusPrepConfig 引用
        # corpus 侧 CorpusLoadPolicy + program 侧 ArtifactMaterializerFn。
        # corpus → program 已是 PUBLIC 依赖，但 profile 直接引这两类型，
        # 显式列出避免传递依赖在未来变更时被破坏。
        refuzz_corpus
        refuzz_program
        # [syscall-support-detection] resolve_enabled_calls for the corpus filter
        refuzz_support
)

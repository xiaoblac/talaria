cmake_minimum_required(VERSION 3.15)
project(refuzz_tests CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
add_compile_options(-Wall -Wextra -Werror)
# Tests intentionally use assert() as the lightweight harness. Keep those
# assertions enabled even when the parent build type defines NDEBUG; otherwise
# tests compile into no-ops and local variables used only by assert trip
# -Werror=unused-variable.
add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-UNDEBUG>)

# 约定:所有测试文件使用裸 CHECK + RUN_TEST 宏(参见
# mutator_manager_layering_test.cpp / resolver_test.cpp / assembler_test.cpp
# 等),不引入 googletest/gmock。这样避免网络拉取、保持构建确定性。

set(REFUZZ_PSEUDO_KVM_SYZOS_SOURCE
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/kvm/syzos_guest_amd64.cpp
)
set(REFUZZ_PSEUDO_WIFI_DEVICE_INIT_SOURCES
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/sandbox/device_init/netlink_helpers.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/sandbox/device_init/wifi.cpp
)
set_source_files_properties(
    ${REFUZZ_PSEUDO_KVM_SYZOS_SOURCE}
    PROPERTIES
        COMPILE_OPTIONS
            "-Wno-unused-function;-Wno-address-of-packed-member;-Wno-ignored-qualifiers;-Wno-deprecated-volatile;-Wno-unused-parameter;-Wno-missing-field-initializers"
)

# ──────────────────────────────────────────────────────────────
# Channel-related tests were removed as part of v3.5 decoupling.
# They will be rewritten after the new architecture stabilizes
# (see docs/channel-redesign/v3.5/000_roadmap.md).
#
# Non-channel tests are retained below.
# ──────────────────────────────────────────────────────────────

add_executable(core_metadata_test
    core_metadata_test.cpp
)

# [v2 batch 3 PR-W2] ExecutionObservation 薄 wrapper 单测。

# [v2 batch 3 PR-W3] SeedMetadataSerdeRegistry 单测。
add_executable(seed_metadata_serde_registry_test
    seed_metadata_serde_registry_test.cpp
)

# [v2 batch 3 PR-X] head+tail decode helper 单测(per-call coverage tail)。
add_executable(syz_exec_result_decode_per_call_cov_test
    syz_exec_result_decode_per_call_cov_test.cpp
)

add_executable(linux_amd64_call_table_test
    linux_amd64_call_table_test.cpp
)
target_compile_definitions(linux_amd64_call_table_test
    PRIVATE
        REFUZZ_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

# [v2 batch 3 G6] corpus_verify stage + 相关接口单测。
add_executable(corpus_store_update_metadata_test
    corpus_store_update_metadata_test.cpp
)
add_executable(priority_scheduler_invalidate_test
    priority_scheduler_invalidate_test.cpp
)
add_executable(boot_inactive_seed_skips_scheduler_test
    boot_inactive_seed_skips_scheduler_test.cpp
)

# [value-weighted experiment] selection-policy bias gate (size vs rarity vs uniform).
add_executable(scheduler_policy_bias_test
    scheduler_policy_bias_test.cpp
)
target_link_libraries(scheduler_policy_bias_test
    PRIVATE
        refuzz_corpus
        refuzz_program
        refuzz_core
        refuzz_logging
        pthread
)
add_test(NAME scheduler_policy_bias_test COMMAND scheduler_policy_bias_test)

# [v2 batch 3 G5 follow-up-2] RateWindowTracker(LibAFL afl_exec_sec equiv)单测。
add_executable(rate_window_tracker_test
    rate_window_tracker_test.cpp
)

# [v2 batch 3 G5] saturation filter + KcovCoverageSignal pipeline 单测。
add_executable(kernel_coverage_saturation_filter_test
    kernel_coverage_saturation_filter_test.cpp
)
add_executable(noop_saturation_filter_test
    noop_saturation_filter_test.cpp
)
add_executable(kcov_coverage_signal_saturation_pipeline_test
    kcov_coverage_signal_saturation_pipeline_test.cpp
)

# [v2 batch 3 PR-Y] SyzkallerPriorityCalculator 4-case truth table 单测。
add_executable(syzkaller_priority_calculator_test
    syzkaller_priority_calculator_test.cpp
)

# [v2 batch 3 PR-Y] HashFeedbackStore prio merge / persistence 单测。
add_executable(hash_feedback_store_prio_merge_test
    hash_feedback_store_prio_merge_test.cpp
)

# [seed-future-value §5.1] per-base-seed lineage downstream-yield accumulator unit test.
add_executable(seed_lineage_yield_store_test
    seed_lineage_yield_store_test.cpp
)

# [variant-handler-binding 2026-06-18] live per_call variant->handler accumulator unit test.
add_executable(variant_handler_map_test
    variant_handler_map_test.cpp
)

# [v2 batch 3 PR-Y] KcovCoverageSignal::Sample priority_calculator 集成单测。
add_executable(kcov_coverage_signal_priority_test
    kcov_coverage_signal_priority_test.cpp
)

add_executable(coverage_filter_signal_test
    coverage_filter_signal_test.cpp
)

add_executable(core_bus_test
    core_bus_test.cpp
)

add_executable(core_engine_handle_test
    core_engine_handle_test.cpp
)

add_executable(service_registry_test
    service_registry_test.cpp
)

add_executable(metric_registry_test
    metric_registry_test.cpp
)

# [job-loop Step 5a] 2-tier priority-at-Pop (High=continuation / Low=exploration,
# 1-in-3 Alternate) + single-tier FIFO parity.
add_executable(task_queue_tier_test
    task_queue_tier_test.cpp
)
add_executable(job_arbitration_test
    job_arbitration_test.cpp
)

# [job-loop] libaco stackful-coroutine Job runtime smoke test (job.cpp).
add_executable(job_coroutine_smoke_test
    job_coroutine_smoke_test.cpp
)

# [fixed request stream, Step 4] FixedInputProducerJob Gate 4 test: sequence
# order + payload fidelity, ExecFlag translation, no self-respawn, drain-signal
# correctness, cancellation safety. docs/plans/fixed-request-stream-performance-replay.md
add_executable(fixed_input_producer_job_test
    fixed_input_producer_job_test.cpp
)

add_executable(host_logger_test
    host_logger_test.cpp
)


add_executable(telemetry_projector_test
    telemetry_projector_test.cpp
)

# [v2 PR-K-A] coverage series substrate ctest, see kcov-coverage-curve.md §5.4
add_executable(coverage_series_buffer_test
    coverage_series_buffer_test.cpp
)

add_executable(coverage_series_concurrent_test
    coverage_series_concurrent_test.cpp
)

# [v2 PR-K-B] descriptor-driven render ctest, see kcov-coverage-curve.md §6.1
add_executable(coverage_series_render_test
    coverage_series_render_test.cpp
)

# [v2 PR-K-D] kcov_cmp empty-slot end-to-end ctest, see kcov-coverage-curve.md §6.3
add_executable(coverage_series_register_two_test
    coverage_series_register_two_test.cpp
)

# [v2 PR-K-E1] disk-export opt-in gate ctest, see kcov-coverage-curve.md rev 0.3 §1
add_executable(coverage_export_optin_test
    coverage_export_optin_test.cpp
)

add_executable(periodic_metric_sink_test
    periodic_metric_sink_test.cpp
)

# [v2 Epic 5 PR-5-A] kcov_cmp wire round-trip ctest, see
# docs/plans/syzkaller-capability-closure-epic-5.md §4.1
add_executable(feedback_cmp_wire_round_trip_test
    feedback_cmp_wire_round_trip_test.cpp
)

# [v2 Epic 5 PR-5-B] kcov_cmp wire flag + signal + telemetry ctest cluster
add_executable(kcov_cmp_wire_flag_test           kcov_cmp_wire_flag_test.cpp)
add_executable(kcov_cmp_signal_decode_test       kcov_cmp_signal_decode_test.cpp)
add_executable(kcov_cmp_signal_dedupe_test       kcov_cmp_signal_dedupe_test.cpp)
add_executable(kcov_cmp_two_series_active_test   kcov_cmp_two_series_active_test.cpp)
# [v2 Epic 5 PR-5-B fix #1] worker-local cmp filter regression ctest.
add_executable(kcov_cmp_worker_filter_test       kcov_cmp_worker_filter_test.cpp)

# [v2 Epic 5 PR-5-C] hints algorithm port — 9 upstream-fixture ctests
# (mirror prog/hints_test.go).
add_executable(hints_inplace_intersect_test   hints_inplace_intersect_test.cpp)
add_executable(hints_limiter_test             hints_limiter_test.cpp)
add_executable(hints_shrink_expand_test       hints_shrink_expand_test.cpp)
add_executable(hints_check_const_arg_test     hints_check_const_arg_test.cpp)
add_executable(hints_check_data_arg_test      hints_check_data_arg_test.cpp)
add_executable(hints_compressed_image_test    hints_compressed_image_test.cpp)
add_executable(hints_call_test                hints_call_test.cpp)
add_executable(hints_data_test                hints_data_test.cpp)
add_executable(hints_random_smoke_test        hints_random_smoke_test.cpp)
# [v2 Epic 5 PR-5-C fix #1] artifact-first SyzV2MutatorEngine.MutateWithHints
add_executable(hints_artifact_first_test      hints_artifact_first_test.cpp)

add_executable(session_layout_test
    session_layout_test.cpp
)

add_executable(mutator_manager_layering_test
    mutator_manager_layering_test.cpp
)



# [Step 6 stage 清场] follow_up_dispatcher / stage_catalog / fuzzer_loop_double_chain_smoke
#   tests 已删(stage framework 退役)。
add_executable(config_parser_test
    config_parser_test.cpp
)

# [Step 6 stage 清场] orchestrator_build_wiring_test 已删(用退役的 StageSpec/chain 装配)。
add_executable(scheduler_manager_layering_test
    scheduler_manager_layering_test.cpp
)


add_executable(corpus_manager_admission_test
    corpus_manager_admission_test.cpp
)

# [v2 SubT-B] SyzkallerRetryPolicy 数值匹配 syzkaller 单测。
add_executable(syzkaller_retry_policy_test
    syzkaller_retry_policy_test.cpp
)

# [k-of-n 去抖] SignalVotingStabilityOracle 投票语义单测。
add_executable(signal_voting_stability_oracle_test
    signal_voting_stability_oracle_test.cpp
)

# [dense mount image] zstd FFI round-trip — validates the self-declared zstd
# prototypes (no -dev headers) used by the dense mount-image fast path. Self-
# contained: links only libzstd.so.1 (runtime soname; no dev package needed).
add_executable(zstd_mount_image_roundtrip_test
    zstd_mount_image_roundtrip_test.cpp
)
find_library(REFUZZ_TEST_ZSTD_LIB NAMES zstd libzstd.so.1
             PATHS /usr/lib/x86_64-linux-gnu /lib/x86_64-linux-gnu)
if(NOT REFUZZ_TEST_ZSTD_LIB)
    set(REFUZZ_TEST_ZSTD_LIB /lib/x86_64-linux-gnu/libzstd.so.1)
endif()
target_link_libraries(zstd_mount_image_roundtrip_test PRIVATE ${REFUZZ_TEST_ZSTD_LIB})
add_test(NAME zstd_mount_image_roundtrip_test COMMAND zstd_mount_image_roundtrip_test)

# [v2 admit-worker async] InMemoryCorpusStore 并发安全 + AsyncAdmitWorker batch 合并。
add_executable(in_memory_corpus_concurrent_test
    in_memory_corpus_concurrent_test.cpp
)
add_executable(async_admit_worker_test
    async_admit_worker_test.cpp
)

# [harness-fatal 语义修正] 跨层回归：FuzzerLoop 收到 kHarnessFatal 后必须继续
# 运行（历史 bug：第一次 error 14 就 latch 整轮 Stop，即使 channel 恢复仍会成功）。
add_executable(fuzzer_loop_harness_fatal_continue_test
    fuzzer_loop_harness_fatal_continue_test.cpp
)

add_executable(corpus_metadata_persistence_test
    corpus_metadata_persistence_test.cpp
)

# PR1 — Corpus Prep Smoothing：StrictTyped fail-closed + LenientBytes 对照。
# 直接守护这次 932 全 abnormal 的根因（bytes-only 僵尸 seed 阻断 bootstrap）。
add_executable(corpus_disk_io_strict_drop_test
    corpus_disk_io_strict_drop_test.cpp
)

add_executable(xiuos_wire_corpus_loader_test
    xiuos_wire_corpus_loader_test.cpp
)

# §3.9 v2 IR round-trip — generate v2 payload through SyzV2MutatorEngine,
# write/read through CorpusDiskIO, decode + validate after reload.
add_executable(corpus_v2_persistence_test
    corpus_v2_persistence_test.cpp
)

# §3.10 step-1 — neutral ProgramArtifact boundary + materializer +
# codec counter wiring. Pure program/-side test.
add_executable(program_artifact_test
    program_artifact_test.cpp
)

# Epic 2 step-2 — SyscallMeta pseudo identity fields (kPseudoNrBase /
# is_pseudo) match the worker-side kLinuxAmd64PseudoMeta count.
add_executable(syscall_meta_pseudo_fields_test
    syscall_meta_pseudo_fields_test.cpp
)

# [syscall-enable-whitelist] match_syscall + compute_enabled_calls + ChoiceTable mask
add_executable(syscall_enable_whitelist_test
    syscall_enable_whitelist_test.cpp
)

# [syscall-support-detection] control/support: is_supported + resolve_enabled_calls
add_executable(support_checker_test
    support_checker_test.cpp
)

# [machine-check C4.4] transitive-resource closure (program/syz pure function)
add_executable(transitive_enabled_calls_test
    transitive_enabled_calls_test.cpp
)
target_link_libraries(transitive_enabled_calls_test
    PRIVATE
        refuzz_program
        refuzz_core
        pthread
)

# [syscall-support-detection Step C] proto/wire EnvFeatures contract compile + helpers
add_executable(env_features_test
    env_features_test.cpp
)

# [syscall-support-detection Step C] guest env probe /proc/filesystems parser.
# Compiles the worker's env_probe.cpp directly (no need to link the whole worker).
add_executable(env_probe_test
    env_probe_test.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/env/env_probe.cpp
)
target_include_directories(env_probe_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/executor/channel/worker/include
)
target_link_libraries(env_probe_test
    PRIVATE
        refuzz_proto_wire
        pthread
)

# [machine-check C4.2] probe-program builder (default-arg call → exec-wire payload)
add_executable(probe_program_test
    probe_program_test.cpp
)
target_link_libraries(probe_program_test
    PRIVATE
        refuzz_machine_check
        refuzz_program
        refuzz_core
        pthread
)

# [machine-check C4.2b] trial-exec runner primitives (HostFuzzTask carrier +
# per-call errno decode). Needs the worker include dir for SyzExecResult, which
# the test hand-builds into a completion output buffer.
add_executable(probe_runner_test
    probe_runner_test.cpp
)
target_include_directories(probe_runner_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/executor/channel/worker/include
)
target_link_libraries(probe_runner_test
    PRIVATE
        refuzz_machine_check
        refuzz_program
        refuzz_feedback
        refuzz_core
        pthread
)

# [machine-check C4.6] phase driver (EnvFeatures→SupportEnv + standard-data-plane
# probe run + resolve). Fake-Executor thread, no VM.
add_executable(machine_check_test
    machine_check_test.cpp
)
target_include_directories(machine_check_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/executor/channel/worker/include
)
target_link_libraries(machine_check_test
    PRIVATE
        refuzz_machine_check
        refuzz_support
        refuzz_program
        refuzz_queue
        refuzz_proto_wire
        refuzz_core
        pthread
)


# PR-D1 — mount-image handler behavioral test (per-fs adjuster cases +
# zlib decompress round-trip + DispatchMountPseudo arg validation +
# MountState lifecycle).
add_executable(pseudo_mount_handler_test
    pseudo_mount_handler_test.cpp
)

add_executable(pseudo_state_fork_safety_test
    pseudo_state_fork_safety_test.cpp
)

# PR-D1 / PR-D1.O' — mount-image source-derived semantic oracle.
# Pins per-fs adjuster output and phase contracts against goldens
# transcribed from common_linux.h/common_zlib.h per plan §7.1.
add_executable(pseudo_mount_image_oracle_test
    pseudo_mount_image_oracle_test.cpp
)

# PR-D2 — KVM family handler test (6 syz_kvm$* pseudos: setup_syzos_vm /
# add_vcpu / setup_cpu$x86 + ppc64 + 2 assert_*). Cap-gate cases always
# run; /dev/kvm-dependent cases skip when kernel module unavailable.
add_executable(pseudo_kvm_handler_test
    pseudo_kvm_handler_test.cpp
)

# PR-D2 — KVM oracle (mechanism b hand-derive per plan §7.1). Pins
# state-transition invariants: KVM_EXIT_* exit-reason classification
# for assert_syzos_uexit + assert_syzos_kvm_exit + ppc64-on-amd64
# returns ENOSYS.
add_executable(pseudo_kvm_oracle_test
    pseudo_kvm_oracle_test.cpp
)

# PR-D2.A slice 1 — KVM ABI/layout pin test. Cross-source byte-equal
# pinning of X86_SYZOS_ADDR_* / MEM_REGION_FLAG_* values + struct
# offsets/sizes + reFuzz-owned guest stub byte sequences. Hand-assert
# only — always runs in CI without /dev/kvm.
add_executable(pseudo_kvm_layout_test
    pseudo_kvm_layout_test.cpp
)

# [v3 P1 review finding-1] ReusableChildTopology recycle_after enforcement
# regression test. Runs on host (no /dev/kvm, no root). Verifies that
# stdio profile's default recycle_after=1 actually respawns the worker
# child after every program — otherwise fd/mmap/signal state leaks across
# programs and oracle expected_divergence_hits explodes (see oracle report
# 1778573939.json vs 1778569761.json baseline for the symptom).
add_executable(topology_recycle_after_test
    topology_recycle_after_test.cpp
)

# [v3 P3] ChildWaiter (pidfd_open + waitpid fallback) regression test.
# 4 subtests: long-lived child / short-lived normal exit / signal kill /
# Reset+reuse. Runs on host, no /dev/kvm, no root.
add_executable(child_waiter_test
    child_waiter_test.cpp
)

add_executable(fork_server_reaper_test
    fork_server_reaper_test.cpp
)

# [v3 P4] DoubleForkTopology host smoke (NEWPID 在 non-root 通常 fallback,
# 这里 verify 接合点不 panic + loop child 长期活的不变量)
add_executable(topology_double_fork_test
    topology_double_fork_test.cpp
)

add_executable(topology_exec_double_fork_test
    topology_exec_double_fork_test.cpp
)
add_dependencies(topology_exec_double_fork_test refuzz_executor)
target_compile_definitions(topology_exec_double_fork_test PRIVATE
    REFUZZ_EXECUTOR_TEST_PATH="$<TARGET_FILE:refuzz_executor>")

# [fix: production staging activation -- pure-memory verification] Verifies
# via /proc/<pid>/maps only (no WorkerLog/serial-device dependency, see the
# file header) that the production ExecDoubleForkTopology path actually
# stages the worker's data window instead of leaving it BAR/memfd-mapped and
# inherited by every program-child fork.
add_executable(fork_window_staging_memory_test
    fork_window_staging_memory_test.cpp
)
add_dependencies(fork_window_staging_memory_test refuzz_executor)
target_compile_definitions(fork_window_staging_memory_test PRIVATE
    REFUZZ_EXECUTOR_TEST_PATH="$<TARGET_FILE:refuzz_executor>")

add_executable(loop_worker_boot_config_test
    loop_worker_boot_config_test.cpp
)

add_executable(net_namespace_reset_test
    net_namespace_reset_test.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/sandbox/device_init/net_reset.cpp
)
target_include_directories(net_namespace_reset_test PRIVATE
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/include
)
target_compile_definitions(net_namespace_reset_test PRIVATE
    REFUZZ_LOOP_RUNTIME_SOURCE="${CMAKE_SOURCE_DIR}/executor/channel/worker/src/engine/loop_runtime.cpp"
    REFUZZ_SNAPSHOT_ENGINE_SOURCE="${CMAKE_SOURCE_DIR}/executor/channel/worker/src/engine/snapshot_engine.cpp"
)
target_link_options(net_namespace_reset_test PRIVATE
    "-Wl,--wrap=socket"
    "-Wl,--wrap=getsockopt"
    "-Wl,--wrap=setsockopt"
    "-Wl,--wrap=close"
    "-Wl,--wrap=read"
)

add_executable(net_namespace_runtime_integration_test
    net_namespace_runtime_integration_test.cpp
)
target_link_options(net_namespace_runtime_integration_test PRIVATE
    "-Wl,--wrap=_ZN6refuzz6worker12ApplySandboxENS0_11SandboxModeERKNS0_13SandboxSizingE"
    "-Wl,--wrap=_ZN6refuzz6worker25PreallocateSyzExecScratchEv"
    "-Wl,--wrap=_ZN6refuzz6worker6engine34ProgramRuntimeInstallCrashHandlersEPNS0_15IObservationBusE"
    "-Wl,--wrap=_ZN6refuzz6worker7sandbox11device_init16SetupCgroupsLoopEm"
    "-Wl,--wrap=_ZN6refuzz6worker7sandbox11device_init22CheckpointNetNamespaceEv"
    "-Wl,--wrap=_ZN6refuzz6worker7sandbox11device_init17ResetNetNamespaceEv"
    "-Wl,--wrap=_exit"
)

add_executable(device_network_init_test
    device_network_init_test.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/sandbox/device_init/tun.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/sandbox/device_init/netdevsim.cpp
)
target_include_directories(device_network_init_test PRIVATE
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/include
)
target_link_options(device_network_init_test PRIVATE
    "-Wl,--wrap=stat"
    "-Wl,--wrap=unlink"
    "-Wl,--wrap=mkdir"
    "-Wl,--wrap=mknod"
    "-Wl,--wrap=chmod"
    "-Wl,--wrap=open"
    "-Wl,--wrap=write"
    "-Wl,--wrap=close"
)

# [2026-05-13 P1 fix-1 v3] ForkingProgramExecutor child-exit 分类(waitpid status
# 单 source):覆盖 normal / SIGSEGV / SIGKILL-self / _exit(2) 4 个状态分流分支。
add_executable(forking_executor_status_test
    forking_executor_status_test.cpp
)

# [2026-05-13] ExecutionEngine result-kind mapping regression:partial stays OK,
# crash becomes CHILD_ABORTED, no-result becomes EXEC_ERROR.
add_executable(execution_engine_result_kind_mapping_test
    execution_engine_result_kind_mapping_test.cpp
)

# [D12 ns-runner] NsRunnerSupervisor 5 subtests:Spawn+echo+Stop / Respawn x5 /
# loop_child exit propagate / Stop idempotent / double-Spawn guarded。host
# non-root 跑(unshare(NEWPID) 通常 EPERM → silent fallback,IPC 仍 work)。
add_executable(ns_runner_test
    ns_runner_test.cpp
)

# PR-D4 — USB family handler test (25 syz_usb_*$ pseudos: connect /
# control_io / ep_read / ep_write / disconnect / usbip_server_init).
# Cap-gate cases always run; /dev/raw-gadget-dependent cases skip
# when dummy_udc / raw-gadget driver unavailable.
add_executable(pseudo_usb_handler_test
    pseudo_usb_handler_test.cpp
)

# PR-D4 — USB oracle (mechanism b hand-derive per plan §7.1). Pins
# routing goldens (25 pseudos → 6 handler families) + state-transition
# invariants (control_io requires running gadget; ep_write payload
# bounded to kMaxEpData).
add_executable(pseudo_usb_oracle_test
    pseudo_usb_oracle_test.cpp
)

# Epic 2 step-4 — oracle #25: supported pseudo call reaches the worker
# pseudo dispatcher (not syscall(0,...)). End-to-end: generate →
# serialize_for_exec → decode_exec_wire → KernelWireDriver →
# ResolveSyzCallByNr returns kPseudo.
add_executable(pseudo_dispatch_oracle_test
    pseudo_dispatch_oracle_test.cpp
)

# create_resource recursive ctor walk; deterministic cases.
# Probabilistic link-rate oracle is in tools/run_all_oracles.sh.
add_executable(create_resource_test
    create_resource_test.cpp
)

# resource_centric corpus-walk; deterministic cases.
# Artifact-first contract is the headline invariant; 0 payload-decode
# fallbacks in the v2-shaped test corpus.
add_executable(resource_centric_test
    resource_centric_test.cpp
)

# mutate_resource_arg createResource fallback + engine extras splice.
add_executable(mutate_resource_extras_test
    mutate_resource_extras_test.cpp
)

# Mutator-side concrete IGen impl (GenImpl) — bridge between
# program/syz/linux SpecialType bodies and mutator helpers.
add_executable(special_gen_impl_test
    special_gen_impl_test.cpp
)

# 14 SpecialType bodies — manifest coverage + no-abort gate.
add_executable(special_type_manifest_test
    special_type_manifest_test.cpp
)

# PR-3-B3 — SpecialType dispatch hook in generate_arg / bypass via
# generate_arg_no_special.
add_executable(generate_arg_special_dispatch_test
    generate_arg_special_dispatch_test.cpp
)

# Epic 4 PR-4-A — csource module substrate tests.
add_executable(csource_options_check_test     csource_options_check_test.cpp)
add_executable(csource_host_goos_test         csource_host_goos_test.cpp)
add_executable(csource_data_mmap_golden_test  csource_data_mmap_golden_test.cpp)
add_executable(crash_repro_csource_stage_test crash_repro_csource_stage_test.cpp)

# Epic 4 PR-4-B-1 — gate / filter / sandbox tests.
add_executable(csource_sandbox_signature_test csource_sandbox_signature_test.cpp)
add_executable(csource_filter_calls_test      csource_filter_calls_test.cpp)
add_executable(csource_baseline_gate_test     csource_baseline_gate_test.cpp)

# Epic 4 PR-4-B-2 — emit_args + emit_csum tests.
add_executable(csource_const_format_test      csource_const_format_test.cpp)
add_executable(csource_csum_inet_test         csource_csum_inet_test.cpp)

# Epic 4 PR-4-B-3 — emit_call + emit_prog_calls test.
add_executable(csource_emit_call_test         csource_emit_call_test.cpp)

# Epic 4 PR-4-B-4 — typed call comment generator.
add_executable(csource_typed_call_comment_test csource_typed_call_comment_test.cpp)

# Epic 4 PR-4-B-5 — common header / define list pieces.
add_executable(csource_define_list_test       csource_define_list_test.cpp)

# Epic 4 PR-4-B-6 — Write() end-to-end smoke + index alignment + annotator.
add_executable(csource_write_round_trip_test       csource_write_round_trip_test.cpp)
add_executable(csource_emit_index_alignment_test   csource_emit_index_alignment_test.cpp)
add_executable(csource_annotator_insertion_test    csource_annotator_insertion_test.cpp)

# Epic 4 PR-4-B-rev2 BLOCKER regression — DataOffset rebase + WireAddr
# (top-level + copyin) + vars defaults.
add_executable(csource_data_offset_rebase_test     csource_data_offset_rebase_test.cpp)

# A7 regression — worker scratch must cover full linux/amd64 exec VMA window.
add_executable(syz_exec_scratch_size_test          syz_exec_scratch_size_test.cpp)

# Epic 4 PR-4-C — Build() argv layout pin (no compiler spawn).
add_executable(csource_build_argv_test             csource_build_argv_test.cpp)

# Epic 4 PR-4-D — repro_manager B1 artifact propagation regression.
add_executable(repro_manager_minimize_artifact_propagation_test
    repro_manager_minimize_artifact_propagation_test.cpp)

# Epic 4 PR-4-D §6.2 — upstream testdata golden samples.
add_executable(csource_golden_samples_test         csource_golden_samples_test.cpp)
target_compile_definitions(csource_golden_samples_test PRIVATE
    REFUZZ_UPSTREAM_CSOURCE_TESTDATA="${CMAKE_SOURCE_DIR}/../pkg/csource/testdata")

# PR-3-C — ChoiceTable lazy build + OnSeedAdmitted COW publish.
add_executable(choice_table_rebuild_test
    choice_table_rebuild_test.cpp
)

# Epic 3 probabilistic generation oracles (#26/#27). Buildable for
# tools/run_all_oracles.sh, intentionally not a default CTest.
add_executable(epic3_generation_oracle_test
    epic3_generation_oracle_test.cpp
)

# P2-M1 — squash-to-ANY round-trip oracle (size invariant + double-squash
# idempotence). Verifies the prog/any.go::squashPtr port.
add_executable(squash_any_roundtrip_test
    squash_any_roundtrip_test.cpp
)

# seed-value signal B — ComputeUnstableRatio oracle (cross-execution coverage
# variance). Header-only (control/stage/stable_cover.hpp), pure stdlib → no link.
add_executable(seed_value_unstable_test
    seed_value_unstable_test.cpp
)
target_include_directories(seed_value_unstable_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/control/include
)

# seed-value signal C — ComputeStateAltitude + IMutatorEngine::AnalyzeStateAltitude
# oracle (generates real progs, cross-checks against a forward-traversal ref).
add_executable(seed_value_altitude_test
    seed_value_altitude_test.cpp
)
target_link_libraries(seed_value_altitude_test
    PRIVATE
        refuzz_mutator
        refuzz_program
        refuzz_core
        pthread
)

# [seed-future-value] SeedHorizonModel scoring core unit test.
add_executable(seed_horizon_model_test
    seed_horizon_model_test.cpp
)
target_link_libraries(seed_horizon_model_test
    PRIVATE
        refuzz_corpus
        refuzz_mutator
        refuzz_program
        refuzz_core
        pthread
)

# [seed-future-value] AnalyzeResourceFrontier extraction + full chain to Future.
add_executable(resource_frontier_test
    resource_frontier_test.cpp
)
target_link_libraries(resource_frontier_test
    PRIVATE
        refuzz_corpus
        refuzz_mutator
        refuzz_program
        refuzz_core
        pthread
)

# [seed-future-value] SeedHorizon component: live mask + on-admit future scoring.
add_executable(seed_horizon_test
    seed_horizon_test.cpp
)
target_link_libraries(seed_horizon_test
    PRIVATE
        refuzz_corpus
        refuzz_mutator
        refuzz_program
        refuzz_core
        pthread
)

add_executable(seed_band2_test
    seed_band2_test.cpp
)
target_link_libraries(seed_band2_test
    PRIVATE
        refuzz_corpus
        refuzz_mutator
        refuzz_program
        refuzz_core
        pthread
)
add_test(NAME seed_band2_test COMMAND seed_band2_test)

# [belief-graph] Phase-A: StaticBeliefGraph loads graph_M.tsv + scores a seed by unlock potential.
add_executable(static_belief_graph_test
    static_belief_graph_test.cpp
)
target_link_libraries(static_belief_graph_test
    PRIVATE
        refuzz_corpus
        refuzz_mutator
        refuzz_program
        refuzz_core
        pthread
)
add_test(NAME static_belief_graph_test COMMAND static_belief_graph_test)

# seed-value signal A — RarityScore helper + SeedRarityScore engine seam oracle.
add_executable(seed_value_rarity_test
    seed_value_rarity_test.cpp
)
target_link_libraries(seed_value_rarity_test
    PRIVATE
        refuzz_corpus
        refuzz_program
        refuzz_core
        refuzz_logging
        pthread
)

# seed-value signal A — cold-arm rarity prior (Exp3-IX Ĝ₀ head-start) oracle.
add_executable(seed_value_rarity_prior_test
    seed_value_rarity_prior_test.cpp
)
target_link_libraries(seed_value_rarity_prior_test
    PRIVATE
        refuzz_corpus
        refuzz_program
        refuzz_core
        refuzz_logging
        pthread
)

# P3 / G6.4 — conditional-union correctness oracle (selected arm satisfies its
# condition). Verifies the prog/expr.go::patchConditionalFields port.
add_executable(conditional_union_test
    conditional_union_test.cpp
)

# post-V1-retirement B-6 — RawBytesArtifact (target-agnostic raw-bytes
# adapter) smoke test。
add_executable(raw_bytes_artifact_test
    raw_bytes_artifact_test.cpp
)

# §3.10 step-2 — syz_v2 DeepClone (Prog/Call/Arg + ResultArg remap).
add_executable(syz_v2_clone_test
    syz_v2_clone_test.cpp
)

# §3.10 step-3 — IMutatorEngine::MutateTyped contract + native syz_v2
# typed mutation path (codec-counter-free hot loop).
add_executable(syz_v2_mutate_typed_test
    syz_v2_mutate_typed_test.cpp
)

# §3.10 step-9 oracle #17 — MutateTyped hot path codec-free check.
add_executable(mutate_typed_codec_free_test
    mutate_typed_codec_free_test.cpp
)

# §3.11 oracle #23 — ResultArg.uses forward-edge invariant (C0).
add_executable(result_arg_uses_invariant_test
    result_arg_uses_invariant_test.cpp
)

# §3.11-C1 P2 — typed structural transform helpers used by minimizer.
add_executable(syz_v2_transform_test
    syz_v2_transform_test.cpp
)

# §3.11 follow-up — sanitize_call / sanitize_fix per-syscall coverage.
add_executable(syz_v2_sanitize_test
    syz_v2_sanitize_test.cpp
)

# §3.11-C1 P3 — Call.Props text/wire/minimizer/worker integration.
if (TARGET refuzz_worker_core)
    add_executable(call_props_integration_test
        call_props_integration_test.cpp
    )
endif()

# §3.11-C1 P4 — typed artifact per-argument minimizer slices.
add_executable(minimize_typed_args_test
    minimize_typed_args_test.cpp
)

# §3.11 follow-up P2 step 1 — MinimizeCtx::try_commit / try_remove_call
# in-place + snapshot rollback semantics.
add_executable(minimize_ctx_try_commit_test
    minimize_ctx_try_commit_test.cpp
)

# §3.11 follow-up P2 step 3 — IntType / FlagsType / ProcType
# minimize virtual override behavioral test.
add_executable(scalar_type_minimize_test
    scalar_type_minimize_test.cpp
)

# §3.11 follow-up P2 step 4 — ArrayType::minimize virtual override
# behavioral test (fast path + peel-from-end + dispatch_lookup contract).
add_executable(array_type_minimize_test
    array_type_minimize_test.cpp
)

# §3.11 follow-up P2 step 5 — PtrType::minimize virtual override
# behavioral test (null replacement + rollback).
add_executable(ptr_type_minimize_test
    ptr_type_minimize_test.cpp
)

# §3.11 follow-up P2 step 6 — ResourceType::minimize virtual override
# behavioral test (C0 forward-edge cleanup + producer/consumer
# fixture).
add_executable(resource_type_minimize_test
    resource_type_minimize_test.cpp
)

# §3.11 follow-up P2 step 7 — BufferType::minimize virtual override
# behavioral test (per-kind shrink: blob halving / filename trim /
# string-glob-text-compressed skip).
add_executable(buffer_type_minimize_test
    buffer_type_minimize_test.cpp
)

# §3.11 follow-up P2 step 8 — UnionType::minimize virtual override
# behavioral test (default-arm replace + conditional handling).
add_executable(union_type_minimize_test
    union_type_minimize_test.cpp
)

# §3.11 oracle #21 — repro/minimize candidate loop is text-codec-free
# after CrashContext::origin_artifact wiring (A).
add_executable(repro_artifact_decode_count_test
    repro_artifact_decode_count_test.cpp
)

# Diagnostic one-shot: dump a wire-format prog file (for crash-storm forensics).
add_executable(wire_dump
    wire_dump.cpp
)
target_link_libraries(wire_dump PRIVATE refuzz_program refuzz_core)

# §3.11 oracle #22 — 6-class dedup hash stability + v2 IR transition (B).
add_executable(dedup_v2_transition_stability_test
    dedup_v2_transition_stability_test.cpp
)

# §3.11-C1 supplementary smoke (NOT oracle #24).
add_executable(minimize_typed_smoke_test
    minimize_typed_smoke_test.cpp
)

add_executable(minimize_driver_oracle_test
    minimize_driver_oracle_test.cpp
)

# §3.11-C1 P5 — oracle #24: 20-sample syzkaller golden parity.
add_executable(minimize_syzkaller_parity_test
    minimize_syzkaller_parity_test.cpp
)

# Throwaway probe to measure byte-level parity for §3.11 closure
# discussion. Not registered as CTest.
add_executable(byte_parity_probe
    byte_parity_probe.cpp
)



# §3.10 step-9 oracle #18 — Smash repeat decode count.
add_executable(smash_repeat_decode_count_test
    smash_repeat_decode_count_test.cpp
)

# [Step 6 stage 清场] smash_enrich_execution_test 已删(smash stage 退役;smash 现为 smash_op job)。

# §3.10 step-9 oracle #19 — Corpus v2 artifact round-trip + counters.
add_executable(corpus_v2_artifact_roundtrip_test
    corpus_v2_artifact_roundtrip_test.cpp
)

# §3.10 step-9 oracle #20 — serialize_for_exec placement.
add_executable(serialize_for_exec_placement_test
    serialize_for_exec_placement_test.cpp
)

# §3.11-A — Bug #1 fix verification: ParseAndClassifyOp origin gate.
add_executable(crash_origin_gate_test
    crash_origin_gate_test.cpp
)

# post-V1-retirement — artifact-first universal contract acceptance oracle.
# 验证 §5.3：(1) submit→completion 后 Seed.artifact != nullptr；
# (2) BuildContextOp 直接 propagate origin_artifact 不调任何 canonical-text decode。

# §3.11-B — ConsoleRingBuffer (heartbeat → console snapshot bridge).
add_executable(console_ring_buffer_test
    console_ring_buffer_test.cpp
)

# §3.11-C — Dedup hash 细粒度（fault_reason + stack_top）—— Bug #3 fix.
add_executable(crash_dedup_finer_grain_test
    crash_dedup_finer_grain_test.cpp
)

# §3.11-D — EvidenceFragment / Incident 中性数据类型 smoke test.
add_executable(evidence_fragment_smoke_test
    evidence_fragment_smoke_test.cpp
)

# §3.11-E — IIncidentAnalyzer registry + IIncidentCorrelator smoke test.
add_executable(incident_analyzer_registry_test
    incident_analyzer_registry_test.cpp
)

# §3.11-F — LocalFsEvidenceBlobStore unit test.
add_executable(evidence_blob_store_test
    evidence_blob_store_test.cpp
)


add_executable(policy_monitor_metric_test
    policy_monitor_metric_test.cpp
)

add_executable(executor_metric_parity_test
    executor_metric_parity_test.cpp
)

add_executable(executor_hot_path_test
    executor_hot_path_test.cpp
)

# [v2 Epic 7 PR-11 B1] submit boundary fail-closed regression — encoder
# MaterializeExecWire failure must NOT result in empty payload going to
# worker. Verify: 1) no channel.Submit; 2) host-synthesized AbnormalCompletion
# pushed to event_queue with kExecError + ctx.worker_id=0.
add_executable(dispatcher_materialize_fail_closed_test
    dispatcher_materialize_fail_closed_test.cpp
)
target_link_libraries(dispatcher_materialize_fail_closed_test
    PRIVATE
        refuzz_channeldispatcher
        refuzz_channel
        refuzz_program
        refuzz_core
        pthread
)
add_test(NAME dispatcher_materialize_fail_closed_test
         COMMAND dispatcher_materialize_fail_closed_test)

add_executable(channel_metrics_5b_test
    channel_metrics_5b_test.cpp
)

add_executable(channel_completion_wakeup_test
    channel_completion_wakeup_test.cpp
)

# PR3 step 5 — locks in ChannelDispatchRequest.target_worker_id strict-affinity
# contract: default kAnyWorkerId round-robin, explicit slot routes only there,
# out-of-range rejected with kInvalid before queue insertion.
add_executable(channel_target_worker_affinity_test
    channel_target_worker_affinity_test.cpp
)

# PR3 step 5 — locks in trace_reader's E2H ExecutingMessage parse path.
# Builds a fabricated exec_trace_*.bin in /tmp containing crafted Executing
# records, asserts ReplayOneFile fires on_executing with the right
# (req_id, proc_id, try_idx) round-trip.
add_executable(replayer_executing_extract_test
    replayer_executing_extract_test.cpp
    ${CMAKE_SOURCE_DIR}/tools/refuzz_exec_replayer/trace_reader.cpp
)
target_include_directories(replayer_executing_extract_test PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${REFUZZ_SYZKALLER_ROOT}
    ${REFUZZ_SYZKALLER_ROOT}/executor/_include)

# Fixed request-stream v1 reader. The fixture is generated by the Syzkaller
# Go encoder test and consumed here to pin the cross-language byte layout.
# [fixed request stream, Step 4] reader lives in control/ (see control/CMakeLists.txt
# for why: it's a fuzz-loop producer input, not an independent module).
add_executable(request_stream_reader_test
    request_stream_reader_test.cpp
    ${CMAKE_SOURCE_DIR}/control/src/request_stream_reader.cpp
)
target_include_directories(request_stream_reader_test PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/control/include
)
target_compile_definitions(request_stream_reader_test PRIVATE
    REFUZZ_REQUEST_STREAM_FIXTURE="${CMAKE_SOURCE_DIR}/tests/data/request_stream/v2_valid.bin"
)

add_executable(ivshmem_v3_layout_commit_test
    ivshmem_v3_layout_commit_test.cpp
)

if (TARGET refuzz_worker_core)
    add_executable(ivshmem_worker_adapter_completion_test
        ivshmem_worker_adapter_completion_test.cpp
        ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/ivshmem_attach.cpp
        ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/adapter/ivshmem_adapter.cpp
    )
endif()

add_executable(channel_input_queue_metric_test
    channel_input_queue_metric_test.cpp
)

add_executable(control_plane_recovery_escalation_test
    control_plane_recovery_escalation_test.cpp
)

add_executable(runtime_instance_kill_retention_test
    runtime_instance_kill_retention_test.cpp
)

add_executable(runtime_instance_deploy_mode_test
    runtime_instance_deploy_mode_test.cpp
)

add_executable(channel_ssh_dead_vmdead_escalation_test
    channel_ssh_dead_vmdead_escalation_test.cpp
)

add_executable(run_state_renderer_test
    run_state_renderer_test.cpp
)

add_executable(policy_engine_registry_test
    policy_engine_registry_test.cpp
)


# [v2 PR2 — Corpus Generation Adaptation] §015 §5 / §6.1 GenerateProducerStage

target_include_directories(mutator_manager_layering_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}
)

target_link_libraries(mutator_manager_layering_test
    PRIVATE
        refuzz_mutator
        pthread
)



# [Step 6 stage 清场] follow_up_dispatcher / stage_catalog / double_chain link rules 已删。



target_link_libraries(config_parser_test
    PRIVATE
        refuzz_config_parser
        pthread
)

# [Step 6 stage 清场] orchestrator_build_wiring_test link rule 已删。

target_link_libraries(scheduler_manager_layering_test
    PRIVATE
        refuzz_corpus
        refuzz_core
        pthread
)


target_link_libraries(corpus_manager_admission_test
    PRIVATE
        refuzz_corpus
        refuzz_core
        pthread
)

# [v2 SubT-B]
target_link_libraries(syzkaller_retry_policy_test
    PRIVATE
        refuzz_feedback
        refuzz_program
        refuzz_core
        pthread
)

# [k-of-n 去抖]
target_link_libraries(signal_voting_stability_oracle_test
    PRIVATE
        refuzz_feedback
        refuzz_program
        refuzz_core
        pthread
)

# [v2 admit-worker async]
target_link_libraries(in_memory_corpus_concurrent_test
    PRIVATE
        refuzz_corpus
        refuzz_core
        pthread
)
target_link_libraries(async_admit_worker_test
    PRIVATE
        refuzz_control
        refuzz_corpus
        refuzz_mutator
        refuzz_core
        pthread
)

target_link_libraries(fuzzer_loop_harness_fatal_continue_test
    PRIVATE
        refuzz_control
        refuzz_corpus
        refuzz_mutator
        refuzz_core
        pthread
)

target_link_libraries(corpus_metadata_persistence_test
    PRIVATE
        refuzz_corpus
        refuzz_core
        pthread
)

target_link_libraries(corpus_disk_io_strict_drop_test
    PRIVATE
        refuzz_corpus
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(xiuos_wire_corpus_loader_test
    PRIVATE
        refuzz_corpus
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(corpus_v2_persistence_test
    PRIVATE
        refuzz_corpus
        refuzz_mutator
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(program_artifact_test
    PRIVATE
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(syscall_meta_pseudo_fields_test
    PRIVATE
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(syscall_enable_whitelist_test
    PRIVATE
        refuzz_mutator
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(support_checker_test
    PRIVATE
        refuzz_support
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(env_features_test
    PRIVATE
        refuzz_proto_wire
        pthread
)


find_package(ZLIB REQUIRED)
target_link_libraries(pseudo_mount_handler_test
    PRIVATE
        refuzz_worker_core
        refuzz_program
        refuzz_core
        pthread
        ZLIB::ZLIB
)

target_link_libraries(pseudo_state_fork_safety_test
    PRIVATE
        refuzz_worker_core
        pthread
)

target_link_libraries(pseudo_mount_image_oracle_test
    PRIVATE
        refuzz_worker_core
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(pseudo_kvm_handler_test
    PRIVATE
        refuzz_worker_core
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(pseudo_kvm_oracle_test
    PRIVATE
        refuzz_worker_core
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(pseudo_kvm_layout_test
    PRIVATE
        refuzz_worker_core
)

target_link_libraries(topology_recycle_after_test
    PRIVATE
        refuzz_worker_core
        pthread
)

target_link_libraries(child_waiter_test
    PRIVATE
        refuzz_worker_core
        pthread
)

target_link_libraries(fork_server_reaper_test
    PRIVATE
        refuzz_worker_core
        pthread
)

target_link_libraries(topology_double_fork_test
    PRIVATE
        refuzz_worker_core
        pthread
)

target_link_libraries(topology_exec_double_fork_test
    PRIVATE
        refuzz_worker_core
        refuzz_program
        pthread
)

target_link_libraries(fork_window_staging_memory_test
    PRIVATE
        refuzz_worker_core
        refuzz_program
        pthread
)

target_link_libraries(loop_worker_boot_config_test
    PRIVATE
        refuzz_worker_core
        pthread
)

target_link_libraries(net_namespace_reset_test
    PRIVATE
        pthread
)

target_link_libraries(net_namespace_runtime_integration_test
    PRIVATE
        refuzz_worker_core
        pthread
)

target_link_libraries(device_network_init_test PRIVATE pthread)

target_link_libraries(forking_executor_status_test
    PRIVATE
        refuzz_worker_core
        pthread
)

target_link_libraries(execution_engine_result_kind_mapping_test
    PRIVATE
        refuzz_worker_core
        pthread
)

target_link_libraries(ns_runner_test
    PRIVATE
        refuzz_worker_core
        pthread
)

target_link_libraries(pseudo_usb_handler_test
    PRIVATE
        refuzz_worker_core
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(pseudo_usb_oracle_test
    PRIVATE
        refuzz_worker_core
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(pseudo_dispatch_oracle_test
    PRIVATE
        refuzz_worker_core
        refuzz_mutator
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(create_resource_test
    PRIVATE
        refuzz_mutator
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(resource_centric_test
    PRIVATE
        refuzz_mutator
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(mutate_resource_extras_test
    PRIVATE
        refuzz_mutator
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(special_gen_impl_test
    PRIVATE
        refuzz_mutator
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(special_type_manifest_test
    PRIVATE
        refuzz_mutator
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(generate_arg_special_dispatch_test
    PRIVATE
        refuzz_mutator
        refuzz_program
        refuzz_core
        pthread
)

# Epic 4 PR-4-A/B csource module test linkage. csource sources live
# in refuzz_crash; tests pull in refuzz_program for Target +
# refuzz_core for shared infra (no mutator/control deps — structural
# grep test enforces).
foreach(csource_test
        csource_options_check_test
        csource_host_goos_test
        csource_data_mmap_golden_test
        crash_repro_csource_stage_test
        csource_sandbox_signature_test
        csource_filter_calls_test
        csource_baseline_gate_test
        csource_const_format_test
        csource_csum_inet_test
        csource_emit_call_test
        csource_typed_call_comment_test
        csource_define_list_test
        csource_write_round_trip_test
        csource_emit_index_alignment_test
        csource_annotator_insertion_test
        csource_data_offset_rebase_test
        csource_build_argv_test
        csource_golden_samples_test
        repro_manager_minimize_artifact_propagation_test)
    target_link_libraries(${csource_test}
        PRIVATE
            refuzz_crash
            refuzz_program
            refuzz_core
            pthread
    )
endforeach()

target_link_libraries(syz_exec_scratch_size_test
    PRIVATE
        refuzz_worker_core
        refuzz_program
        pthread
)

target_link_libraries(choice_table_rebuild_test
    PRIVATE
        refuzz_mutator
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(epic3_generation_oracle_test
    PRIVATE
        refuzz_mutator
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(squash_any_roundtrip_test
    PRIVATE
        refuzz_mutator
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(conditional_union_test
    PRIVATE
        refuzz_mutator
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(raw_bytes_artifact_test
    PRIVATE
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(syz_v2_clone_test
    PRIVATE
        refuzz_mutator
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(syz_v2_mutate_typed_test
    PRIVATE
        refuzz_mutator
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(mutate_typed_codec_free_test
    PRIVATE
        refuzz_mutator
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(result_arg_uses_invariant_test
    PRIVATE
        refuzz_mutator
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(syz_v2_transform_test
    PRIVATE
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(syz_v2_sanitize_test
    PRIVATE
        refuzz_program
        refuzz_core
        pthread
)

if (TARGET refuzz_worker_core)
    target_link_libraries(call_props_integration_test
        PRIVATE
            refuzz_crash
            refuzz_worker_core
            refuzz_program
            refuzz_core
            pthread
    )
endif()

target_link_libraries(minimize_typed_args_test
    PRIVATE
        refuzz_crash
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(minimize_ctx_try_commit_test
    PRIVATE
        refuzz_crash
        refuzz_mutator
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(scalar_type_minimize_test
    PRIVATE
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(array_type_minimize_test
    PRIVATE
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(ptr_type_minimize_test
    PRIVATE
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(resource_type_minimize_test
    PRIVATE
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(buffer_type_minimize_test
    PRIVATE
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(union_type_minimize_test
    PRIVATE
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(repro_artifact_decode_count_test
    PRIVATE
        refuzz_crash
        refuzz_mutator
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(dedup_v2_transition_stability_test
    PRIVATE
        refuzz_crash
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(minimize_typed_smoke_test
    PRIVATE
        refuzz_crash
        refuzz_mutator
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(minimize_driver_oracle_test
    PRIVATE
        refuzz_control
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(minimize_syzkaller_parity_test
    PRIVATE
        refuzz_crash
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(byte_parity_probe
    PRIVATE
        refuzz_crash
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(smash_repeat_decode_count_test
    PRIVATE
        refuzz_corpus
        refuzz_mutator
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(corpus_v2_artifact_roundtrip_test
    PRIVATE
        refuzz_corpus
        refuzz_mutator
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(serialize_for_exec_placement_test
    PRIVATE
        refuzz_mutator
        refuzz_program
        refuzz_core
        pthread
)


target_link_libraries(policy_monitor_metric_test
    PRIVATE
        refuzz_telemetry
        refuzz_core
        pthread
)

target_link_libraries(core_metadata_test
    PRIVATE
        refuzz_core
        pthread
)

# [v2 batch 3 PR-W2]

# [v2 batch 3 PR-W3]
target_link_libraries(seed_metadata_serde_registry_test
    PRIVATE
        refuzz_program
        refuzz_core
        pthread
)

# [v2 batch 3 PR-X]
target_include_directories(syz_exec_result_decode_per_call_cov_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/executor/channel/worker/include
)
target_link_libraries(syz_exec_result_decode_per_call_cov_test
    PRIVATE
        refuzz_feedback
        refuzz_core
        pthread
)

# V2 production-exec paired oracle / COV-A: flatrpc ExecFlag → wire
# TASK_FLAG_* translator. Header-only logic in tools/refuzz_exec_replayer/
# replayer.hpp, hence no library link beyond pthread.
add_executable(replayer_flag_translation_test
    replayer_flag_translation_test.cpp
)
target_include_directories(replayer_flag_translation_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/tools/refuzz_exec_replayer
)
target_link_libraries(replayer_flag_translation_test
    PRIVATE
        refuzz_proto_wire
        refuzz_core
        pthread
)

# [v2 batch 3 G6] corpus_verify stage + 相关接口单测 link。
target_link_libraries(corpus_store_update_metadata_test
    PRIVATE
        refuzz_corpus
        refuzz_program
        refuzz_core
        pthread
)
target_link_libraries(priority_scheduler_invalidate_test
    PRIVATE
        refuzz_corpus
        refuzz_core
        pthread
)
target_link_libraries(boot_inactive_seed_skips_scheduler_test
    PRIVATE
        refuzz_corpus
        refuzz_program
        refuzz_core
        pthread
)

# [v2 batch 3 G5 follow-up-2] RateWindowTracker test link。
target_link_libraries(rate_window_tracker_test
    PRIVATE
        refuzz_telemetry
        refuzz_core
        pthread
)

# [v2 batch 3 G5] saturation filter + pipeline test link。
target_link_libraries(kernel_coverage_saturation_filter_test
    PRIVATE
        refuzz_feedback
        refuzz_core
        pthread
)
target_link_libraries(noop_saturation_filter_test
    PRIVATE
        refuzz_feedback
        refuzz_core
        pthread
)
# pipeline test 需要完整 KcovCoverageSignal 依赖图(feedback + program + worker
# header for SyzExecResult sizeof)。worker include 已经通过 refuzz_feedback 的
# PUBLIC include path 暴露(详 feedback/CMakeLists.txt:48)。
target_link_libraries(kcov_coverage_signal_saturation_pipeline_test
    PRIVATE
        refuzz_feedback
        refuzz_program
        refuzz_core
        pthread
)

# [v2 batch 3 PR-Y] SyzkallerPriorityCalculator
target_link_libraries(syzkaller_priority_calculator_test
    PRIVATE
        refuzz_feedback
        refuzz_core
        pthread
)

# [v2 batch 3 PR-Y] HashFeedbackStore prio merge / persistence
target_link_libraries(hash_feedback_store_prio_merge_test
    PRIVATE
        refuzz_feedback
        refuzz_core
        pthread
)

target_link_libraries(seed_lineage_yield_store_test
    PRIVATE
        refuzz_feedback
        refuzz_core
        pthread
)

target_link_libraries(variant_handler_map_test
    PRIVATE
        refuzz_feedback
        refuzz_core
        pthread
)
add_test(NAME variant_handler_map_test COMMAND variant_handler_map_test)

# [v2 batch 3 PR-Y] KcovCoverageSignal::Sample priority_calculator 集成单测
target_link_libraries(kcov_coverage_signal_priority_test
    PRIVATE
        refuzz_feedback
        refuzz_core
        pthread
)

target_link_libraries(coverage_filter_signal_test
    PRIVATE
        refuzz_feedback
        refuzz_core
        pthread
)

target_link_libraries(core_bus_test
    PRIVATE
        refuzz_core
        pthread
)

target_link_libraries(core_engine_handle_test
    PRIVATE
        refuzz_core
        pthread
)

target_link_libraries(service_registry_test
    PRIVATE
        refuzz_core
        pthread
)

target_link_libraries(metric_registry_test
    PRIVATE
        refuzz_core
        pthread
)

target_link_libraries(task_queue_tier_test
    PRIVATE
        refuzz_queue
        refuzz_program
        refuzz_proto_wire
        refuzz_core
        pthread
)
target_link_libraries(job_arbitration_test
    PRIVATE
        refuzz_control
        pthread
)

target_link_libraries(job_coroutine_smoke_test
    PRIVATE
        refuzz_control
        pthread
)

target_link_libraries(fixed_input_producer_job_test
    PRIVATE
        refuzz_control
        pthread
)

target_link_libraries(host_logger_test
    PRIVATE
        refuzz_logging
        pthread
)


target_link_libraries(executor_metric_parity_test
    PRIVATE
        refuzz_core
        pthread
)

target_link_libraries(executor_hot_path_test
    PRIVATE
        refuzz_channeldispatcher
        refuzz_channel
        refuzz_core
        pthread
)

target_link_libraries(channel_metrics_5b_test
    PRIVATE
        refuzz_channel
        refuzz_core
        pthread
)

target_link_libraries(channel_completion_wakeup_test
    PRIVATE
        refuzz_channel
        refuzz_core
        pthread
)

target_link_libraries(channel_target_worker_affinity_test
    PRIVATE
        refuzz_channel
        refuzz_core
        pthread
)

target_link_libraries(replayer_executing_extract_test
    PRIVATE
        pthread
)

target_link_libraries(ivshmem_v3_layout_commit_test
    PRIVATE
        refuzz_channel
        refuzz_core
        pthread
)

if (TARGET refuzz_worker_core)
    target_link_libraries(ivshmem_worker_adapter_completion_test
        PRIVATE
            refuzz_worker_core
            pthread
    )
endif()

target_link_libraries(channel_input_queue_metric_test
    PRIVATE
        refuzz_channel
        refuzz_core
        pthread
)

target_link_libraries(control_plane_recovery_escalation_test
    PRIVATE
        refuzz_channel
        refuzz_core
        pthread
)

target_link_libraries(runtime_instance_kill_retention_test
    PRIVATE
        refuzz_channel
        refuzz_core
        pthread
)

target_link_libraries(runtime_instance_deploy_mode_test
    PRIVATE
        refuzz_channel
        refuzz_core
        pthread
)

target_link_libraries(channel_ssh_dead_vmdead_escalation_test
    PRIVATE
        refuzz_channel
        refuzz_core
        pthread
)

target_link_libraries(run_state_renderer_test
    PRIVATE
        refuzz_telemetry
        refuzz_channel
        refuzz_core
        pthread
)

target_link_libraries(policy_engine_registry_test
    PRIVATE
        refuzz_telemetry
        refuzz_core
        pthread
)



target_link_libraries(telemetry_projector_test
    PRIVATE
        refuzz_telemetry
        refuzz_channeldispatcher
        refuzz_channel
        refuzz_core
        pthread
)

# [v2 PR-K-A] coverage series substrate ctest links
target_link_libraries(coverage_series_buffer_test
    PRIVATE
        refuzz_telemetry
        refuzz_core
        pthread
)

target_link_libraries(coverage_series_concurrent_test
    PRIVATE
        refuzz_telemetry
        refuzz_core
        pthread
)

# [v2 PR-K-B] descriptor-driven render ctest links
target_link_libraries(coverage_series_render_test
    PRIVATE
        refuzz_telemetry
        refuzz_core
        pthread
)

# [v2 PR-K-E1] disk-export opt-in ctest links
target_link_libraries(coverage_export_optin_test
    PRIVATE
        refuzz_telemetry
        refuzz_core
        pthread
)

target_link_libraries(periodic_metric_sink_test
    PRIVATE
        refuzz_telemetry
        refuzz_core
        pthread
)

# [v2 PR-K-D] register-two end-to-end ctest links — needs projector + bus
target_link_libraries(coverage_series_register_two_test
    PRIVATE
        refuzz_telemetry
        refuzz_core
        pthread
)

# [v2 Epic 5 PR-5-A] cmp-wire round-trip ctest links — needs feedback codec +
# the worker-side coverage_collector inline helpers (header-only). Add the
# worker include dir so the inline AppendKcovCmpFeedbackRaw resolves.
target_include_directories(feedback_cmp_wire_round_trip_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/executor/channel/worker/include
)
target_link_libraries(feedback_cmp_wire_round_trip_test
    PRIVATE
        refuzz_feedback
        refuzz_core
        pthread
)

# [v2 Epic 5 PR-5-B] kcov_cmp ctest links — wire/signal/telemetry coverage.
target_include_directories(kcov_cmp_wire_flag_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/executor/channel/worker/include
        ${CMAKE_SOURCE_DIR}/proto/wire/include
        ${CMAKE_SOURCE_DIR}/proto/domain/include
)
target_link_libraries(kcov_cmp_wire_flag_test
    PRIVATE
        refuzz_core
        pthread
)

target_include_directories(kcov_cmp_signal_decode_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/executor/channel/worker/include
)
target_link_libraries(kcov_cmp_signal_decode_test
    PRIVATE
        refuzz_feedback
        refuzz_core
        pthread
)

target_include_directories(kcov_cmp_signal_dedupe_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/executor/channel/worker/include
)
target_link_libraries(kcov_cmp_signal_dedupe_test
    PRIVATE
        refuzz_feedback
        refuzz_core
        pthread
)

target_link_libraries(kcov_cmp_two_series_active_test
    PRIVATE
        refuzz_telemetry
        refuzz_core
        pthread
)

# [v2 Epic 5 PR-5-B fix #1] worker-local filter ctest links — header-only,
# needs the worker include dir for FilterCmpRecordsByOutputBuffer.
target_include_directories(kcov_cmp_worker_filter_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/executor/channel/worker/include
        ${CMAKE_SOURCE_DIR}/proto/wire/include
)
target_link_libraries(kcov_cmp_worker_filter_test
    PRIVATE
        pthread
)

# [v2 Epic 5 PR-5-C] hints ctest links — refuzz_mutator carries the
# hints subtree (comp_map / hints_apply / hints_limiter / special_ints_set
# / image_zlib); refuzz_program supplies typed Prog/Arg/Type for the
# per-arg helper tests.
target_link_libraries(hints_inplace_intersect_test
    PRIVATE
        refuzz_mutator
        refuzz_program
        pthread
)
target_link_libraries(hints_limiter_test
    PRIVATE
        refuzz_mutator
        refuzz_program
        pthread
)
target_link_libraries(hints_shrink_expand_test
    PRIVATE
        refuzz_mutator
        refuzz_program
        pthread
)
target_link_libraries(hints_check_const_arg_test
    PRIVATE
        refuzz_mutator
        refuzz_program
        pthread
)
target_link_libraries(hints_check_data_arg_test
    PRIVATE
        refuzz_mutator
        refuzz_program
        pthread
)
target_link_libraries(hints_compressed_image_test
    PRIVATE
        refuzz_mutator
        refuzz_program
        pthread
)
target_link_libraries(hints_call_test
    PRIVATE
        refuzz_mutator
        refuzz_program
        pthread
)
target_link_libraries(hints_data_test
    PRIVATE
        refuzz_mutator
        refuzz_program
        pthread
)
target_link_libraries(hints_random_smoke_test
    PRIVATE
        refuzz_mutator
        refuzz_program
        pthread
)
# [v2 Epic 5 PR-5-C fix #1] artifact-first hints test — needs full
# engine surface (mutator + program + core for Seed/ProgramArtifact).
target_link_libraries(hints_artifact_first_test
    PRIVATE
        refuzz_mutator
        refuzz_program
        refuzz_core
        pthread
)

target_link_libraries(session_layout_test
    PRIVATE
        refuzz_control
        pthread
)

enable_testing()
add_test(NAME core_metadata_test COMMAND core_metadata_test)
add_test(NAME seed_metadata_serde_registry_test COMMAND seed_metadata_serde_registry_test)
add_test(NAME syz_exec_result_decode_per_call_cov_test COMMAND syz_exec_result_decode_per_call_cov_test)
add_test(NAME replayer_flag_translation_test COMMAND replayer_flag_translation_test)
# [v2 batch 3 G6]
add_test(NAME corpus_store_update_metadata_test COMMAND corpus_store_update_metadata_test)
add_test(NAME priority_scheduler_invalidate_test COMMAND priority_scheduler_invalidate_test)
add_test(NAME boot_inactive_seed_skips_scheduler_test COMMAND boot_inactive_seed_skips_scheduler_test)
# [v2 batch 3 G5]
add_test(NAME kernel_coverage_saturation_filter_test COMMAND kernel_coverage_saturation_filter_test)
add_test(NAME noop_saturation_filter_test COMMAND noop_saturation_filter_test)
add_test(NAME kcov_coverage_signal_saturation_pipeline_test COMMAND kcov_coverage_signal_saturation_pipeline_test)
# [v2 batch 3 G5 follow-up-2]
add_test(NAME rate_window_tracker_test COMMAND rate_window_tracker_test)
# [v2 batch 3 PR-Y]
add_test(NAME syzkaller_priority_calculator_test COMMAND syzkaller_priority_calculator_test)
add_test(NAME hash_feedback_store_prio_merge_test COMMAND hash_feedback_store_prio_merge_test)
add_test(NAME seed_lineage_yield_store_test COMMAND seed_lineage_yield_store_test)
add_test(NAME kcov_coverage_signal_priority_test COMMAND kcov_coverage_signal_priority_test)
add_test(NAME coverage_filter_signal_test COMMAND coverage_filter_signal_test)
add_test(NAME core_bus_test COMMAND core_bus_test)
add_test(NAME core_engine_handle_test COMMAND core_engine_handle_test)
add_test(NAME service_registry_test COMMAND service_registry_test)
add_test(NAME metric_registry_test COMMAND metric_registry_test)
add_test(NAME task_queue_tier_test COMMAND task_queue_tier_test)
add_test(NAME job_arbitration_test COMMAND job_arbitration_test)
add_test(NAME job_coroutine_smoke_test COMMAND job_coroutine_smoke_test)
add_test(NAME fixed_input_producer_job_test COMMAND fixed_input_producer_job_test)
add_test(NAME host_logger_test COMMAND host_logger_test)
add_test(NAME telemetry_projector_test COMMAND telemetry_projector_test)
# [v2 PR-K-A] coverage series substrate ctest
add_test(NAME coverage_series_buffer_test COMMAND coverage_series_buffer_test)
add_test(NAME coverage_series_concurrent_test COMMAND coverage_series_concurrent_test)
# [v2 PR-K-B] descriptor-driven render ctest
add_test(NAME coverage_series_render_test COMMAND coverage_series_render_test)
# [v2 PR-K-D] register-two end-to-end ctest
add_test(NAME coverage_series_register_two_test COMMAND coverage_series_register_two_test)
# [v2 PR-K-E1] disk-export opt-in gate ctest
add_test(NAME coverage_export_optin_test COMMAND coverage_export_optin_test)
add_test(NAME periodic_metric_sink_test COMMAND periodic_metric_sink_test)
# [v2 Epic 5 PR-5-A] cmp-wire round-trip ctest
add_test(NAME feedback_cmp_wire_round_trip_test COMMAND feedback_cmp_wire_round_trip_test)
# [v2 Epic 5 PR-5-B] kcov_cmp wire/signal/telemetry ctest cluster
add_test(NAME kcov_cmp_wire_flag_test         COMMAND kcov_cmp_wire_flag_test)
add_test(NAME kcov_cmp_signal_decode_test     COMMAND kcov_cmp_signal_decode_test)
add_test(NAME kcov_cmp_signal_dedupe_test     COMMAND kcov_cmp_signal_dedupe_test)
add_test(NAME kcov_cmp_two_series_active_test COMMAND kcov_cmp_two_series_active_test)
# [v2 Epic 5 PR-5-B fix #1] worker-local filter regression
add_test(NAME kcov_cmp_worker_filter_test     COMMAND kcov_cmp_worker_filter_test)
# [v2 Epic 5 PR-5-C] hints ctest registration
add_test(NAME hints_inplace_intersect_test COMMAND hints_inplace_intersect_test)
add_test(NAME hints_limiter_test           COMMAND hints_limiter_test)
add_test(NAME hints_shrink_expand_test     COMMAND hints_shrink_expand_test)
add_test(NAME hints_check_const_arg_test   COMMAND hints_check_const_arg_test)
add_test(NAME hints_check_data_arg_test    COMMAND hints_check_data_arg_test)
add_test(NAME hints_compressed_image_test  COMMAND hints_compressed_image_test)
add_test(NAME hints_call_test              COMMAND hints_call_test)
add_test(NAME hints_data_test              COMMAND hints_data_test)
add_test(NAME hints_random_smoke_test      COMMAND hints_random_smoke_test)
add_test(NAME hints_artifact_first_test    COMMAND hints_artifact_first_test)
add_test(NAME session_layout_test COMMAND session_layout_test)
add_test(NAME mutator_manager_layering_test COMMAND mutator_manager_layering_test)
add_test(NAME config_parser_test COMMAND config_parser_test)
add_test(NAME scheduler_manager_layering_test COMMAND scheduler_manager_layering_test)
add_test(NAME corpus_manager_admission_test COMMAND corpus_manager_admission_test)
add_test(NAME syzkaller_retry_policy_test COMMAND syzkaller_retry_policy_test)
add_test(NAME signal_voting_stability_oracle_test COMMAND signal_voting_stability_oracle_test)
add_test(NAME in_memory_corpus_concurrent_test COMMAND in_memory_corpus_concurrent_test)
add_test(NAME async_admit_worker_test COMMAND async_admit_worker_test)
add_test(NAME fuzzer_loop_harness_fatal_continue_test COMMAND fuzzer_loop_harness_fatal_continue_test)
add_test(NAME corpus_metadata_persistence_test COMMAND corpus_metadata_persistence_test)
add_test(NAME corpus_disk_io_strict_drop_test COMMAND corpus_disk_io_strict_drop_test)
add_test(NAME xiuos_wire_corpus_loader_test COMMAND xiuos_wire_corpus_loader_test)
add_test(NAME corpus_v2_persistence_test COMMAND corpus_v2_persistence_test)
add_test(NAME program_artifact_test COMMAND program_artifact_test)
add_test(NAME syscall_meta_pseudo_fields_test COMMAND syscall_meta_pseudo_fields_test)
add_test(NAME syscall_enable_whitelist_test COMMAND syscall_enable_whitelist_test)
add_test(NAME support_checker_test COMMAND support_checker_test)
add_test(NAME transitive_enabled_calls_test COMMAND transitive_enabled_calls_test)
add_test(NAME env_features_test COMMAND env_features_test)
add_test(NAME env_probe_test COMMAND env_probe_test)
add_test(NAME probe_program_test COMMAND probe_program_test)
add_test(NAME probe_runner_test COMMAND probe_runner_test)
add_test(NAME machine_check_test COMMAND machine_check_test)
add_test(NAME pseudo_mount_handler_test COMMAND pseudo_mount_handler_test)
add_test(NAME pseudo_state_fork_safety_test COMMAND pseudo_state_fork_safety_test)
add_test(NAME pseudo_mount_image_oracle_test COMMAND pseudo_mount_image_oracle_test)
add_test(NAME pseudo_kvm_handler_test COMMAND pseudo_kvm_handler_test)
add_test(NAME pseudo_kvm_oracle_test COMMAND pseudo_kvm_oracle_test)
add_test(NAME pseudo_kvm_layout_test COMMAND pseudo_kvm_layout_test)
add_test(NAME topology_recycle_after_test COMMAND topology_recycle_after_test)
add_test(NAME child_waiter_test COMMAND child_waiter_test)
add_test(NAME fork_server_reaper_test COMMAND fork_server_reaper_test)
add_test(NAME topology_double_fork_test COMMAND topology_double_fork_test)
add_test(NAME topology_exec_double_fork_test COMMAND topology_exec_double_fork_test)
add_test(NAME fork_window_staging_memory_test COMMAND fork_window_staging_memory_test)
add_test(NAME loop_worker_boot_config_test COMMAND loop_worker_boot_config_test)
add_test(NAME net_namespace_reset_test COMMAND net_namespace_reset_test)
add_test(NAME net_namespace_runtime_integration_test
         COMMAND net_namespace_runtime_integration_test)
add_test(NAME device_network_init_test COMMAND device_network_init_test)
add_test(NAME forking_executor_status_test COMMAND forking_executor_status_test)
add_test(NAME execution_engine_result_kind_mapping_test COMMAND execution_engine_result_kind_mapping_test)
add_test(NAME ns_runner_test COMMAND ns_runner_test)
add_test(NAME pseudo_usb_handler_test COMMAND pseudo_usb_handler_test)
add_test(NAME pseudo_usb_oracle_test COMMAND pseudo_usb_oracle_test)
add_test(NAME pseudo_dispatch_oracle_test COMMAND pseudo_dispatch_oracle_test)
add_test(NAME create_resource_test COMMAND create_resource_test)
add_test(NAME squash_any_roundtrip_test COMMAND squash_any_roundtrip_test)
add_test(NAME seed_value_unstable_test COMMAND seed_value_unstable_test)
add_test(NAME seed_value_altitude_test COMMAND seed_value_altitude_test)
add_test(NAME seed_horizon_model_test COMMAND seed_horizon_model_test)
add_test(NAME resource_frontier_test COMMAND resource_frontier_test)
add_test(NAME seed_horizon_test COMMAND seed_horizon_test)
add_test(NAME seed_value_rarity_test COMMAND seed_value_rarity_test)
add_test(NAME seed_value_rarity_prior_test COMMAND seed_value_rarity_prior_test)
add_test(NAME conditional_union_test COMMAND conditional_union_test)
add_test(NAME resource_centric_test COMMAND resource_centric_test)
add_test(NAME mutate_resource_extras_test COMMAND mutate_resource_extras_test)
add_test(NAME special_gen_impl_test COMMAND special_gen_impl_test)
add_test(NAME special_type_manifest_test COMMAND special_type_manifest_test)
add_test(NAME generate_arg_special_dispatch_test COMMAND generate_arg_special_dispatch_test)

# Epic 4 PR-4-A/B csource module tests.
add_test(NAME csource_options_check_test          COMMAND csource_options_check_test)
add_test(NAME csource_host_goos_test              COMMAND csource_host_goos_test)
add_test(NAME csource_data_mmap_golden_test       COMMAND csource_data_mmap_golden_test)
add_test(NAME crash_repro_csource_stage_test      COMMAND crash_repro_csource_stage_test)
add_test(NAME csource_sandbox_signature_test      COMMAND csource_sandbox_signature_test)
add_test(NAME csource_filter_calls_test           COMMAND csource_filter_calls_test)
add_test(NAME csource_baseline_gate_test          COMMAND csource_baseline_gate_test)
add_test(NAME csource_const_format_test           COMMAND csource_const_format_test)
add_test(NAME csource_csum_inet_test              COMMAND csource_csum_inet_test)
add_test(NAME csource_emit_call_test              COMMAND csource_emit_call_test)
add_test(NAME csource_typed_call_comment_test     COMMAND csource_typed_call_comment_test)
add_test(NAME csource_define_list_test            COMMAND csource_define_list_test)
add_test(NAME csource_write_round_trip_test       COMMAND csource_write_round_trip_test)
add_test(NAME csource_emit_index_alignment_test   COMMAND csource_emit_index_alignment_test)
add_test(NAME csource_annotator_insertion_test    COMMAND csource_annotator_insertion_test)
add_test(NAME csource_data_offset_rebase_test     COMMAND csource_data_offset_rebase_test)
add_test(NAME syz_exec_scratch_size_test          COMMAND syz_exec_scratch_size_test)
add_test(NAME csource_build_argv_test             COMMAND csource_build_argv_test)
add_test(NAME csource_golden_samples_test         COMMAND csource_golden_samples_test)
add_test(NAME repro_manager_minimize_artifact_propagation_test
         COMMAND repro_manager_minimize_artifact_propagation_test)

# Epic 4 PR-4-A — structural module-boundary gate.
add_test(
    NAME    csource_module_boundaries_check
    COMMAND ${CMAKE_SOURCE_DIR}/tools/check_csource_module_boundaries.sh
)
add_test(NAME choice_table_rebuild_test COMMAND choice_table_rebuild_test)
add_test(NAME raw_bytes_artifact_test COMMAND raw_bytes_artifact_test)
add_test(NAME syz_v2_clone_test COMMAND syz_v2_clone_test)
add_test(NAME syz_v2_mutate_typed_test COMMAND syz_v2_mutate_typed_test)
add_test(NAME mutate_typed_codec_free_test COMMAND mutate_typed_codec_free_test)
# Temporarily keep this heavy oracle buildable but out of the default CTest run.
# It currently spends minutes rebuilding/generating fixture programs; run manually
# while iterating on ResultArg::uses_ or resource-link rewrites.
# add_test(NAME result_arg_uses_invariant_test COMMAND result_arg_uses_invariant_test)
add_test(NAME syz_v2_transform_test COMMAND syz_v2_transform_test)
add_test(NAME syz_v2_sanitize_test COMMAND syz_v2_sanitize_test)

# §3.11 follow-up P12 — structural test: TypeKind switches must not
# appear in crash/repro or mutator engines (Tier B regression guard).
# Allowlist tracks pre-existing violations awaiting P2 migration.
add_test(NAME structural_no_typed_kind_switch
    COMMAND ${CMAKE_SOURCE_DIR}/tools/check_no_typed_kind_switch.sh
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

# [v2 PR-K-0] kcov-coverage-curve §4.4 — telemetry::CoverageTracker /
# core::ICoverageSink must not have active references in feedback/
# control/ telemetry/ tests/. Backfilled into ctest in PR-K-B (was
# omitted from PR-K-0).
add_test(NAME structural_no_coverage_tracker
    COMMAND ${CMAKE_SOURCE_DIR}/tools/check_no_coverage_tracker.sh
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

# [v2 PR-K-B] kcov-coverage-curve §1.2 Corollary D #1 — render+sink
# must not read coverage by metric name. Enforces Rule B.
add_test(NAME structural_coverage_render_no_metric_name
    COMMAND ${CMAKE_SOURCE_DIR}/tools/check_coverage_render_no_metric_name.sh
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

# [v2 PR-K-D] kcov-coverage-curve §1.2 Corollary D #2 / §7.2 —
# series symbols are confined to telemetry/ + tests/. Forbids
# CoverageSeriesId / coverage_series / RegisterCoverageSeries /
# CoverageSamplePoint in feedback/ control/ mutator/ executor/.
add_test(NAME structural_coverage_series_module_boundaries
    COMMAND ${CMAKE_SOURCE_DIR}/tools/check_coverage_series_module_boundaries.sh
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
# [v2 Epic 5 PR-5-C] hints algorithm symbols are mutator/-private.
# Forbids CompMap / MutateProgWithHints / GenerateArgHints /
# CheckXxxArgHints / ShrinkExpand / HintsLimiter / Compress(Image) /
# IsSpecialInt in feedback/ control/ executor/ program/.
add_test(NAME structural_hints_module_boundaries
    COMMAND ${CMAKE_SOURCE_DIR}/tools/check_hints_module_boundaries.sh
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
if (TARGET refuzz_worker_core)
    add_test(NAME call_props_integration_test COMMAND call_props_integration_test)
endif()
add_test(NAME minimize_typed_args_test COMMAND minimize_typed_args_test)
add_test(NAME minimize_ctx_try_commit_test COMMAND minimize_ctx_try_commit_test)
add_test(NAME scalar_type_minimize_test COMMAND scalar_type_minimize_test)
add_test(NAME array_type_minimize_test COMMAND array_type_minimize_test)
add_test(NAME ptr_type_minimize_test COMMAND ptr_type_minimize_test)
add_test(NAME resource_type_minimize_test COMMAND resource_type_minimize_test)
add_test(NAME buffer_type_minimize_test COMMAND buffer_type_minimize_test)
add_test(NAME union_type_minimize_test COMMAND union_type_minimize_test)
add_test(NAME repro_artifact_decode_count_test COMMAND repro_artifact_decode_count_test)
add_test(NAME dedup_v2_transition_stability_test COMMAND dedup_v2_transition_stability_test)
add_test(NAME minimize_typed_smoke_test COMMAND minimize_typed_smoke_test)
add_test(NAME minimize_driver_oracle_test COMMAND minimize_driver_oracle_test)
add_test(NAME minimize_syzkaller_parity_test
    COMMAND minimize_syzkaller_parity_test
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
add_test(NAME smash_repeat_decode_count_test COMMAND smash_repeat_decode_count_test)
add_test(NAME corpus_v2_artifact_roundtrip_test COMMAND corpus_v2_artifact_roundtrip_test)
add_test(NAME serialize_for_exec_placement_test COMMAND serialize_for_exec_placement_test)
add_test(NAME policy_monitor_metric_test COMMAND policy_monitor_metric_test)
add_test(NAME executor_metric_parity_test COMMAND executor_metric_parity_test)
add_test(NAME executor_hot_path_test COMMAND executor_hot_path_test)
add_test(NAME channel_metrics_5b_test COMMAND channel_metrics_5b_test)
add_test(NAME channel_completion_wakeup_test COMMAND channel_completion_wakeup_test)
add_test(NAME channel_target_worker_affinity_test COMMAND channel_target_worker_affinity_test)
add_test(NAME replayer_executing_extract_test COMMAND replayer_executing_extract_test)
add_test(NAME request_stream_reader_test COMMAND request_stream_reader_test)
add_test(NAME ivshmem_v3_layout_commit_test COMMAND ivshmem_v3_layout_commit_test)
if (TARGET refuzz_worker_core)
    add_test(NAME ivshmem_worker_adapter_completion_test
             COMMAND ivshmem_worker_adapter_completion_test)
endif()
add_test(NAME channel_input_queue_metric_test COMMAND channel_input_queue_metric_test)
add_test(NAME control_plane_recovery_escalation_test COMMAND control_plane_recovery_escalation_test)
add_test(NAME runtime_instance_kill_retention_test COMMAND runtime_instance_kill_retention_test)
add_test(NAME runtime_instance_deploy_mode_test COMMAND runtime_instance_deploy_mode_test)
add_test(NAME channel_ssh_dead_vmdead_escalation_test COMMAND channel_ssh_dead_vmdead_escalation_test)
add_test(NAME run_state_renderer_test COMMAND run_state_renderer_test)
add_test(NAME policy_engine_registry_test COMMAND policy_engine_registry_test)




# [Step 6 stage 清场] inflight_registry_test + stage_shared_state_test 已删(inflight registry /
#   StageSharedState 退役;job 模型下 JobScheduler.TryClaim 取代 inflight 映射)。

# ─── Phase 3 Step 3.2 triage stage 单测（D-003）──────────────────────



# [Step 6 stage/job 清场] 旧 FuzzerLoop baseline harness 已删；后续验证走 jobs-only smoke。

# ─── Phase 3 Step 3.3 triage → minimize follow-up 链路集成测试 ──────
# 装 triage chain + stub feedback，验证 mc 截留 admit → triage 投 N 次
# re-exec → consumer 累积交集 → push minimize follow-up 端到端。秒级，进 ctest。



# ─── Phase 4 Step 4.0 minimize follow-up priority 契约 ───────────────
# 验证 minimize 完成后多 follow-up 路径的 priority 排序契约：同 reason bucket 内
# 高 priority 先 pop / 不同 reason 桶互相独立 / smash+hints+fault_inject 同时入队。
# chain 顺序断言放 Step 4.4 e2e test。
# [Step 6 stage 清场] minimize_followup_priority_test 已删(FollowUpDispatcher 退役)。

# ─── Phase 4 Step 4.1 smash stage 单测 ───────────────────────────────



# ─── Phase 4 Step 4.2 hints stage 单测（D-005，mock 实现）───────────
# [Step 6 stage 清场] hints_stage_test 已删(hints stage 退役;hints 现为 hints_job)。

# ─── Epic 5 PR-5-D HintsConsumerStage correlation ctest ───────────────────
# [Step 6 stage 清场] hints_consumer_correlation_test 已删(hints consumer stage 退役)。

# ─── Phase 4 Step 4.3 fault injection stage 单测（D-006，mock 实现）────
# [Step 6 stage 清场] fault_injection_stage_test 已删(fault stage 退役;fault 现为 fault_job)。

# ─── Epic 6 PR-6-A — fault injection substrate ctest ───────────────────
# Plan: docs/plans/syzkaller-capability-closure-epic-6.md §6.1 #1/#2/#3.
# 3 NEW ctest executables (item #4 = call_props_integration_test 案例延展,
# item #8 = fault_injection_stage_test body 在 PR-6-C 替换):
#   1. kernel_wire_driver_fault_inject_test — driver hook + 6 cases
#   2. syz_exec_result_decode_round_trip_test — DecodeSyzExecResults helper
#   3. fault_artifact_propagation_test — §3.10 BuildCombinedFromFault propagate

if (TARGET refuzz_worker_core)
    add_executable(worker_perf_stage_test
        worker_perf_stage_test.cpp
    )
    target_link_libraries(worker_perf_stage_test
        PRIVATE
            refuzz_worker_core
            pthread
    )
    add_test(NAME worker_perf_stage_test
             COMMAND worker_perf_stage_test)

    add_executable(kernel_wire_driver_fault_inject_test
        kernel_wire_driver_fault_inject_test.cpp
    )
    target_link_libraries(kernel_wire_driver_fault_inject_test
        PRIVATE
            refuzz_worker_core
            refuzz_program
            refuzz_core
            pthread
    )
    add_test(NAME kernel_wire_driver_fault_inject_test
             COMMAND kernel_wire_driver_fault_inject_test)

    # [v2 Epic 7 PR-4] KernelThreadPool smoke test — exercises pool lifecycle
    # (StartTask/ScheduleCall/WaitCallDone/EndTaskAllUsed/TakeThreadDrained)
    # without dependence on /sys/kernel/debug/kcov (provider stub returns
    # nullptr → worker thread skips Begin/Reset/Collect gracefully).
    add_executable(kernel_thread_pool_smoke_test
        kernel_thread_pool_smoke_test.cpp
    )
    target_link_libraries(kernel_thread_pool_smoke_test
        PRIVATE
            refuzz_worker_core
            refuzz_program
            refuzz_core
            pthread
    )
    add_test(NAME kernel_thread_pool_smoke_test
             COMMAND kernel_thread_pool_smoke_test)

    # [v2 Epic 7 PR-5] KernelWireDriver threaded smoke test — driver Execute
    # threaded branch end-to-end (codec → ExecuteThreaded → pool schedule
    # → drain_sink) without real KCOV. Includes fail-closed setup cases
    # (thread_count=1, null provider), pseudo acceptance, and serial
    # fallthrough.
    add_executable(kernel_wire_driver_threaded_smoke_test
        kernel_wire_driver_threaded_smoke_test.cpp
    )
    target_link_libraries(kernel_wire_driver_threaded_smoke_test
        PRIVATE
            refuzz_worker_core
            refuzz_program
            refuzz_core
            pthread
    )
    add_test(NAME kernel_wire_driver_threaded_smoke_test
             COMMAND kernel_wire_driver_threaded_smoke_test)

    # S3 gate — threaded deferred-copyout timing: a producer→copyout→consumer
    # chain must resolve the consumer's WireResult to the copyout'd value in
    # both serial and threaded paths. Fills the resource-dependency gap the
    # threaded smoke test leaves open.
    add_executable(wire_stream_threaded_copyout_parity_test
        wire_stream_threaded_copyout_parity_test.cpp
    )
    target_link_libraries(wire_stream_threaded_copyout_parity_test
        PRIVATE
            refuzz_worker_core
            refuzz_program
            refuzz_core
            pthread
    )
    add_test(NAME wire_stream_threaded_copyout_parity_test
             COMMAND wire_stream_threaded_copyout_parity_test)

    # [v2 Epic 7 PR-6] KcovSink threaded packet emission tests — verifies
    # IKcovDrainSink path (StartThreadedSession + AppendThreadDrained +
    # PackFeedback) without needing real /sys/kernel/debug/kcov. Covers PC
    # and CMP modes, FilterCmpRecordsByOutputBuffer in concat path, empty
    # session, and cross-task mode switching.
    add_executable(kcov_sink_threaded_emission_test
        kcov_sink_threaded_emission_test.cpp
    )
    target_link_libraries(kcov_sink_threaded_emission_test
        PRIVATE
            refuzz_worker_core
            refuzz_program
            refuzz_core
            pthread
    )
    add_test(NAME kcov_sink_threaded_emission_test
             COMMAND kcov_sink_threaded_emission_test)

    # PR-A regression — wire-address reversal (special pointers + nested ptr).
    # docs/plans/worker-special-pointer-fix/02_pr_a_draft.md §6
    add_executable(wire_address_reversal_test
        wire_address_reversal_test.cpp
    )
    target_link_libraries(wire_address_reversal_test
        PRIVATE
            refuzz_worker_core
            refuzz_program
            refuzz_core
            pthread
    )
    # vendor 进 repo 的 test artifact 路径(prog0.bin from incident #3,
    # 用绝对路径保证 ctest 任意 cwd 跑都能找到)
    target_compile_definitions(wire_address_reversal_test
        PRIVATE
            WIRE_ADDR_TEST_PROG_PRIMARY="${CMAKE_SOURCE_DIR}/tests/data/worker_special_pointer_incident3.bin"
    )
    add_test(NAME wire_address_reversal_test
             COMMAND wire_address_reversal_test)

    # [v2 Epic 7 PR-10] encoder fail-closed regression — write_arg silent-no-op
    # paths must return ExecError, never produce partial wire bytes.
    add_executable(encoder_fail_closed_test
        encoder_fail_closed_test.cpp
    )
    target_link_libraries(encoder_fail_closed_test
        PRIVATE
            refuzz_program
            refuzz_core
            pthread
    )
    add_test(NAME encoder_fail_closed_test
             COMMAND encoder_fail_closed_test)
endif()

# Streaming wire decoder parity gate (S2): assert WireStreamReader yields the
# same instruction sequence + fields as the materializing decode_exec_wire over
# a rich hand-built corpus. Pure decoder comparison — only needs refuzz_program.
add_executable(wire_stream_decode_parity_test
    wire_stream_decode_parity_test.cpp
)
target_link_libraries(wire_stream_decode_parity_test
    PRIVATE
        refuzz_program
        refuzz_core
        pthread
)
add_test(NAME wire_stream_decode_parity_test
         COMMAND wire_stream_decode_parity_test)

# PR-D regression — validate strict_invariant gate (Plan B feature flag) +
# MemAlloc bankruptcy counter。
# docs/plans/worker-special-pointer-fix/04_pr_d_draft.md §6
add_executable(validation_special_pointer_test
    validation_special_pointer_test.cpp
)
target_link_libraries(validation_special_pointer_test
    PRIVATE
        refuzz_mutator
        refuzz_program
        refuzz_core
        pthread
)
add_test(NAME validation_special_pointer_test
         COMMAND validation_special_pointer_test)

add_executable(syz_exec_result_decode_round_trip_test
    syz_exec_result_decode_round_trip_test.cpp
)
target_link_libraries(syz_exec_result_decode_round_trip_test
    PRIVATE
        refuzz_feedback
        pthread
)
add_test(NAME syz_exec_result_decode_round_trip_test
         COMMAND syz_exec_result_decode_round_trip_test)

add_executable(fault_artifact_propagation_test
    fault_artifact_propagation_test.cpp
)
target_link_libraries(fault_artifact_propagation_test
    PRIVATE
        refuzz_feedback
        refuzz_program
        refuzz_core
        pthread
)
add_test(NAME fault_artifact_propagation_test
         COMMAND fault_artifact_propagation_test)

# ─── Epic 6 PR-6-B — fault injection algorithm helper + metrics ctest ──
# Plan: docs/plans/syzkaller-capability-closure-epic-6.md §6.1 #5/#6.
# 2 NEW ctest executables.

add_executable(fault_inject_variant_test
    fault_inject_variant_test.cpp
)
target_link_libraries(fault_inject_variant_test
    PRIVATE
        refuzz_mutator
        refuzz_program
        refuzz_core
        pthread
)
add_test(NAME fault_inject_variant_test COMMAND fault_inject_variant_test)

# ─── Epic 6 PR-6-C — fault injection consumer correlation ctest ────────
# Plan: docs/plans/syzkaller-capability-closure-epic-6.md §6.1 #9.
# 5 cases: hit/continue, cap-reached, foreign event, consumer-not-chained
# negative (P1-2 review fix), flag-clear terminate.

# [Step 6 stage 清场] fault_injection_consumer_correlation_test 已删(fault consumer stage 退役)。

# ─── Epic 6 PR-6-C — fault-injection module-boundary lint gate ─────────
add_test(NAME check_fault_injection_module_boundaries
         COMMAND ${CMAKE_SOURCE_DIR}/tools/check_fault_injection_module_boundaries.sh)

# ─── Epic 6 PR-6-D — corpus admit gate refuses FailNth>0 seeds ─────────
# Plan: docs/plans/syzkaller-capability-closure-epic-6.md §6.1 #10.
# Mirror upstream pkg/manager/seeds.go:289-293 "input has fail_nth > 0".

add_executable(corpus_loader_fault_inject_reject_test
    corpus_loader_fault_inject_reject_test.cpp
)
target_link_libraries(corpus_loader_fault_inject_reject_test
    PRIVATE
        refuzz_corpus
        refuzz_program
        refuzz_core
        pthread
)
add_test(NAME corpus_loader_fault_inject_reject_test
         COMMAND corpus_loader_fault_inject_reject_test)

# ─── Phase 3 Step 3.6 kernel_triage profile 端到端集成测试 ───────────
# ─── kernel_triage / kernel_full 端到端集成测试（V2 IR engine） ─────────────






# ─── Syzkaller Phase A metadata/auditability contract tests ───────
add_executable(pseudo_generated_contract_test
    pseudo_generated_contract_test.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_dispatcher.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_core.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_file.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_fs.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_device.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_net.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_wifi.cpp
    # [PR-D4] usb subdir replaces deleted pseudo_usb.cpp ENOSYS stub.
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_helpers.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_state.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_enumeration.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_dispatcher.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/fuse/fuse_dispatcher.cpp
    # [PR-D1] mount domain handler — required since pseudo_dispatcher.cpp now
    # references DispatchMountPseudo for the kMount domain branch.
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/mount/mount_helpers.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/mount/mount_state.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/mount/mount_dispatcher.cpp
    # [PR-D2] kvm subdir replaces deleted pseudo_kvm.cpp ENOSYS stub.
    ${REFUZZ_PSEUDO_KVM_SYZOS_SOURCE}
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/kvm/kvm_helpers.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/kvm/kvm_state.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/kvm/kvm_dispatcher.cpp
)

# [PR-METRIC] All tests below that compile pseudo_dispatcher.cpp directly
# now also need pseudo_dispatch_metric.cpp because the dispatcher hooks
# metrics::RecordDispatch on every exit path.
add_executable(pseudo_runtime_cleanup_test
    pseudo_runtime_cleanup_test.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_runtime.cpp
    # pseudo_runtime.cpp now references KcovCollector::ResetForCall via the
    # KcovCursorReset override (mid-call cover_reset(0) hook mirroring upstream
    # common_linux.h:3064/:3171). Bundle the collector TU so tests link.
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/coverage/kcov_collector.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_dispatcher.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_core.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_file.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_fs.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_device.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_net.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_wifi.cpp
    # [PR-D4] usb subdir replaces deleted pseudo_usb.cpp ENOSYS stub.
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_helpers.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_state.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_enumeration.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_dispatcher.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/fuse/fuse_dispatcher.cpp
    # [PR-D1] mount domain handler — required since pseudo_dispatcher.cpp now
    # references DispatchMountPseudo for the kMount domain branch.
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/mount/mount_helpers.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/mount/mount_state.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/mount/mount_dispatcher.cpp
    # [PR-D2] kvm subdir replaces deleted pseudo_kvm.cpp ENOSYS stub.
    ${REFUZZ_PSEUDO_KVM_SYZOS_SOURCE}
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/kvm/kvm_helpers.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/kvm/kvm_state.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/kvm/kvm_dispatcher.cpp
)

# [PR-A1] io_uring handler unit test — host-runnable (Submit/Complete
# operate on user-space ring buffers; Setup is kernel-dependent and
# exercised by pseudo_dispatch_oracle_test routing only).
add_executable(pseudo_io_uring_handler_test
    pseudo_io_uring_handler_test.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_core.cpp
)

# [PR-A3] BTF id-by-name handler unit test — drives ScanBtfForName with
# synthetic BTF blob. ReadBtfVmlinux IO path is host-dependent (no CI gate).
add_executable(pseudo_btf_handler_test
    pseudo_btf_handler_test.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_core.cpp
)

# [PR-A2] process / memory / kfuzztest / nvme handler unit tests.
# memcpy_off / pkey_set / pidfd_open / nvme exercised end-to-end via
# DispatchCorePseudo / DispatchNetPseudo. clone / clone3 / execute_func
# args-validation only (actual fork/exec dangerous in CI).
add_executable(pseudo_pra2_handler_test
    pseudo_pra2_handler_test.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_core.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_net.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_wifi.cpp
)

# [PR-D3] FUSE handler unit tests. SelectFuseResponse opcode-demux
# fixtures (mechanism b hand-derive per plan §7.1) + socketpair
# end-to-end (read+route+write integration without /dev/fuse).
add_executable(pseudo_fuse_handler_test
    pseudo_fuse_handler_test.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/fuse/fuse_dispatcher.cpp
)

# [PR-C0/B1/B2/B4] Lane 2 net handlers — host-runnable behavioral.
add_executable(pseudo_lane2_handler_test
    pseudo_lane2_handler_test.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_runtime.cpp
    # See note on pseudo_runtime_cleanup_test for KcovCollector link dep.
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/coverage/kcov_collector.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_dispatcher.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_core.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_file.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_fs.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_device.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_net.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_wifi.cpp
    # [PR-D4] usb subdir replaces deleted pseudo_usb.cpp ENOSYS stub.
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_helpers.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_state.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_enumeration.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_dispatcher.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/fuse/fuse_dispatcher.cpp
    # [PR-D1] mount domain handler — required since pseudo_dispatcher.cpp now
    # references DispatchMountPseudo for the kMount domain branch.
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/mount/mount_helpers.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/mount/mount_state.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/mount/mount_dispatcher.cpp
    # [PR-D2] kvm subdir replaces deleted pseudo_kvm.cpp ENOSYS stub.
    ${REFUZZ_PSEUDO_KVM_SYZOS_SOURCE}
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/kvm/kvm_helpers.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/kvm/kvm_state.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/kvm/kvm_dispatcher.cpp
)

# [PR-B3] 802.11 inject / join_ibss — args validation + module-absent
# graceful path. Real hwsim/nl80211 dialog requires operator-loaded modules.
add_executable(pseudo_wifi_handler_test
    pseudo_wifi_handler_test.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_runtime.cpp
    # See note on pseudo_runtime_cleanup_test for KcovCollector link dep.
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/coverage/kcov_collector.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_dispatcher.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_core.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_file.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_fs.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_device.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_net.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_wifi.cpp
    # [PR-D4] usb subdir replaces deleted pseudo_usb.cpp ENOSYS stub.
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_helpers.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_state.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_enumeration.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_dispatcher.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/fuse/fuse_dispatcher.cpp
    # [PR-D1] mount domain handler — required since pseudo_dispatcher.cpp now
    # references DispatchMountPseudo for the kMount domain branch.
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/mount/mount_helpers.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/mount/mount_state.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/mount/mount_dispatcher.cpp
    # [PR-D2] kvm subdir replaces deleted pseudo_kvm.cpp ENOSYS stub.
    ${REFUZZ_PSEUDO_KVM_SYZOS_SOURCE}
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/kvm/kvm_helpers.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/kvm/kvm_state.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/kvm/kvm_dispatcher.cpp
)

add_executable(pseudo_subset_net_test
    pseudo_subset_net_test.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_dispatcher.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_core.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_file.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_fs.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_device.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_net.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_wifi.cpp
    # [PR-D4] usb subdir replaces deleted pseudo_usb.cpp ENOSYS stub.
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_helpers.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_state.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_enumeration.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_dispatcher.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/fuse/fuse_dispatcher.cpp
    # [PR-D1] mount domain handler — required since pseudo_dispatcher.cpp now
    # references DispatchMountPseudo for the kMount domain branch.
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/mount/mount_helpers.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/mount/mount_state.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/mount/mount_dispatcher.cpp
    # [PR-D2] kvm subdir replaces deleted pseudo_kvm.cpp ENOSYS stub.
    ${REFUZZ_PSEUDO_KVM_SYZOS_SOURCE}
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/kvm/kvm_helpers.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/kvm/kvm_state.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/kvm/kvm_dispatcher.cpp
)

add_executable(pseudo_subset_fs_test
    pseudo_subset_fs_test.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_dispatcher.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_core.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_file.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_fs.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_device.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_net.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_wifi.cpp
    # [PR-D4] usb subdir replaces deleted pseudo_usb.cpp ENOSYS stub.
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_helpers.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_state.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_enumeration.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_dispatcher.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/fuse/fuse_dispatcher.cpp
    # [PR-D1] mount domain handler — required since pseudo_dispatcher.cpp now
    # references DispatchMountPseudo for the kMount domain branch.
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/mount/mount_helpers.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/mount/mount_state.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/mount/mount_dispatcher.cpp
    # [PR-D2] kvm subdir replaces deleted pseudo_kvm.cpp ENOSYS stub.
    ${REFUZZ_PSEUDO_KVM_SYZOS_SOURCE}
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/kvm/kvm_helpers.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/kvm/kvm_state.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/kvm/kvm_dispatcher.cpp
)

add_executable(pseudo_dispatch_algorithm_test
    pseudo_dispatch_algorithm_test.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_dispatcher.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_core.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_file.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_fs.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_device.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_net.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_wifi.cpp
    # [PR-D4] usb subdir replaces deleted pseudo_usb.cpp ENOSYS stub.
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_helpers.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_state.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_enumeration.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_dispatcher.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/fuse/fuse_dispatcher.cpp
    # [PR-D1] mount domain handler — required since pseudo_dispatcher.cpp now
    # references DispatchMountPseudo for the kMount domain branch.
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/mount/mount_helpers.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/mount/mount_state.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/mount/mount_dispatcher.cpp
    # [PR-D2] kvm subdir replaces deleted pseudo_kvm.cpp ENOSYS stub.
    ${REFUZZ_PSEUDO_KVM_SYZOS_SOURCE}
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/kvm/kvm_helpers.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/kvm/kvm_state.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/kvm/kvm_dispatcher.cpp
)

add_executable(pseudo_subset_nonpriv_test
    pseudo_subset_nonpriv_test.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_dispatcher.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_core.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_file.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_fs.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_device.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_net.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_wifi.cpp
    # [PR-D4] usb subdir replaces deleted pseudo_usb.cpp ENOSYS stub.
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_helpers.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_state.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_enumeration.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_dispatcher.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/fuse/fuse_dispatcher.cpp
    # [PR-D1] mount domain handler — required since pseudo_dispatcher.cpp now
    # references DispatchMountPseudo for the kMount domain branch.
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/mount/mount_helpers.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/mount/mount_state.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/mount/mount_dispatcher.cpp
    # [PR-D2] kvm subdir replaces deleted pseudo_kvm.cpp ENOSYS stub.
    ${REFUZZ_PSEUDO_KVM_SYZOS_SOURCE}
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/kvm/kvm_helpers.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/kvm/kvm_state.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/kvm/kvm_dispatcher.cpp
)

add_executable(pseudo_subset_dev_test
    pseudo_subset_dev_test.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_dispatcher.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_core.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_file.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_fs.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_device.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_net.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_wifi.cpp
    # [PR-D4] usb subdir replaces deleted pseudo_usb.cpp ENOSYS stub.
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_helpers.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_state.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_enumeration.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_dispatcher.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/fuse/fuse_dispatcher.cpp
    # [PR-D1] mount domain handler — required since pseudo_dispatcher.cpp now
    # references DispatchMountPseudo for the kMount domain branch.
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/mount/mount_helpers.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/mount/mount_state.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/mount/mount_dispatcher.cpp
    # [PR-D2] kvm subdir replaces deleted pseudo_kvm.cpp ENOSYS stub.
    ${REFUZZ_PSEUDO_KVM_SYZOS_SOURCE}
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/kvm/kvm_helpers.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/kvm/kvm_state.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/kvm/kvm_dispatcher.cpp
)

add_executable(pseudo_subset_usbfusekvm_test
    pseudo_subset_usbfusekvm_test.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_dispatcher.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_core.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_file.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_fs.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_device.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_net.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/pseudo_wifi.cpp
    # [PR-D4] usb subdir replaces deleted pseudo_usb.cpp ENOSYS stub.
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_helpers.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_state.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_enumeration.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/usb/usb_dispatcher.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/fuse/fuse_dispatcher.cpp
    # [PR-D1] mount domain handler — required since pseudo_dispatcher.cpp now
    # references DispatchMountPseudo for the kMount domain branch.
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/mount/mount_helpers.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/mount/mount_state.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/mount/mount_dispatcher.cpp
    # [PR-D2] kvm subdir replaces deleted pseudo_kvm.cpp ENOSYS stub.
    ${REFUZZ_PSEUDO_KVM_SYZOS_SOURCE}
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/kvm/kvm_helpers.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/kvm/kvm_state.cpp
    ${CMAKE_SOURCE_DIR}/executor/channel/worker/src/backend/pseudo/kvm/kvm_dispatcher.cpp
)

target_include_directories(pseudo_generated_contract_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/executor/channel/worker/include
)

target_include_directories(pseudo_runtime_cleanup_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/executor/channel/worker/include
)

target_include_directories(pseudo_io_uring_handler_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/executor/channel/worker/include
)

target_include_directories(pseudo_btf_handler_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/executor/channel/worker/include
)

target_include_directories(pseudo_pra2_handler_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/executor/channel/worker/include
)

target_include_directories(pseudo_fuse_handler_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/executor/channel/worker/include
)

target_include_directories(pseudo_lane2_handler_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/executor/channel/worker/include
)

target_include_directories(pseudo_wifi_handler_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/executor/channel/worker/include
)

target_include_directories(pseudo_subset_net_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/executor/channel/worker/include
)

target_include_directories(pseudo_subset_fs_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/executor/channel/worker/include
)

target_include_directories(pseudo_dispatch_algorithm_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/executor/channel/worker/include
)

target_include_directories(pseudo_subset_nonpriv_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/executor/channel/worker/include
)

target_include_directories(pseudo_subset_dev_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/executor/channel/worker/include
)

target_include_directories(pseudo_subset_usbfusekvm_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/executor/channel/worker/include
)

foreach(refuzz_wifi_pseudo_test
        pseudo_generated_contract_test
        pseudo_runtime_cleanup_test
        pseudo_pra2_handler_test
        pseudo_lane2_handler_test
        pseudo_wifi_handler_test
        pseudo_subset_net_test
        pseudo_subset_fs_test
        pseudo_dispatch_algorithm_test
        pseudo_subset_nonpriv_test
        pseudo_subset_dev_test
        pseudo_subset_usbfusekvm_test)
    target_sources(${refuzz_wifi_pseudo_test}
        PRIVATE
            ${REFUZZ_PSEUDO_WIFI_DEVICE_INIT_SOURCES})
endforeach()

target_link_libraries(pseudo_generated_contract_test
    PRIVATE
        refuzz_program
        pthread
        ZLIB::ZLIB
)

target_link_libraries(pseudo_runtime_cleanup_test
    PRIVATE
        refuzz_program
        pthread
        ZLIB::ZLIB
)

target_link_libraries(pseudo_io_uring_handler_test
    PRIVATE
        refuzz_program
        pthread
)

target_link_libraries(pseudo_btf_handler_test
    PRIVATE
        refuzz_program
        pthread
)

target_link_libraries(pseudo_pra2_handler_test
    PRIVATE
        refuzz_program
        pthread
)

target_link_libraries(pseudo_fuse_handler_test
    PRIVATE
        refuzz_program
        pthread
)

target_link_libraries(pseudo_lane2_handler_test
    PRIVATE
        refuzz_program
        pthread
        ZLIB::ZLIB
)

target_link_libraries(pseudo_wifi_handler_test
    PRIVATE
        refuzz_program
        pthread
        ZLIB::ZLIB
)

target_link_libraries(pseudo_subset_net_test
    PRIVATE
        refuzz_program
        pthread
        ZLIB::ZLIB
)

target_link_libraries(pseudo_subset_fs_test
    PRIVATE
        refuzz_program
        pthread
        ZLIB::ZLIB
)

target_link_libraries(pseudo_dispatch_algorithm_test
    PRIVATE
        refuzz_program
        pthread
        ZLIB::ZLIB
)

target_link_libraries(pseudo_subset_nonpriv_test
    PRIVATE
        refuzz_program
        pthread
        ZLIB::ZLIB
)

target_link_libraries(pseudo_subset_dev_test
    PRIVATE
        refuzz_program
        pthread
        ZLIB::ZLIB
)

target_link_libraries(pseudo_subset_usbfusekvm_test
    PRIVATE
        refuzz_program
        pthread
        ZLIB::ZLIB
)

add_test(NAME pseudo_generated_contract_test COMMAND pseudo_generated_contract_test)
add_test(NAME pseudo_runtime_cleanup_test COMMAND pseudo_runtime_cleanup_test)
add_test(NAME pseudo_io_uring_handler_test COMMAND pseudo_io_uring_handler_test)
add_test(NAME pseudo_btf_handler_test COMMAND pseudo_btf_handler_test)
add_test(NAME pseudo_pra2_handler_test COMMAND pseudo_pra2_handler_test)
add_test(NAME pseudo_fuse_handler_test COMMAND pseudo_fuse_handler_test)
add_test(NAME pseudo_lane2_handler_test COMMAND pseudo_lane2_handler_test)
add_test(NAME pseudo_wifi_handler_test COMMAND pseudo_wifi_handler_test)
add_test(NAME pseudo_subset_net_test COMMAND pseudo_subset_net_test)
add_test(NAME pseudo_subset_fs_test COMMAND pseudo_subset_fs_test)
add_test(NAME pseudo_dispatch_algorithm_test COMMAND pseudo_dispatch_algorithm_test)
add_test(NAME pseudo_subset_nonpriv_test COMMAND pseudo_subset_nonpriv_test)
add_test(NAME pseudo_subset_dev_test COMMAND pseudo_subset_dev_test)
add_test(NAME pseudo_subset_usbfusekvm_test COMMAND pseudo_subset_usbfusekvm_test)

# ─── Syzkaller Phase E E4 crash report parsing/bucketing inputs ───
add_executable(kernel_report_parser_test
    kernel_report_parser_test.cpp
)

target_link_libraries(kernel_report_parser_test
    PRIVATE
        refuzz_crash
        refuzz_channel
        pthread
)

add_test(NAME kernel_report_parser_test COMMAND kernel_report_parser_test)

add_executable(kernel_repro_engine_title_test
    kernel_repro_engine_title_test.cpp
)

target_link_libraries(kernel_repro_engine_title_test
    PRIVATE
        refuzz_crash
        refuzz_channel
        pthread
)

add_test(NAME kernel_repro_engine_title_test COMMAND kernel_repro_engine_title_test)

add_executable(linux_report_parser_corpus_test
    linux_report_parser_corpus_test.cpp
)

target_link_libraries(linux_report_parser_corpus_test
    PRIVATE
        refuzz_crash
        refuzz_channel
        pthread
)

add_test(
    NAME linux_report_parser_corpus_test
    COMMAND linux_report_parser_corpus_test
            ${REFUZZ_SYZKALLER_ROOT}/pkg/report/testdata/linux/report
)

# ─── Syzkaller Phase F F7 crash classification ──────────────────
add_executable(fault_classification_test
    fault_classification_test.cpp
)

target_link_libraries(fault_classification_test
    PRIVATE
        refuzz_feedback
        refuzz_channel
        pthread
)

add_test(NAME fault_classification_test COMMAND fault_classification_test)

# §3.11-A — Origin gate Bug #1 fix verification.
target_link_libraries(crash_origin_gate_test
    PRIVATE
        refuzz_crash
        refuzz_channel
        refuzz_core
        pthread
)
add_test(NAME crash_origin_gate_test COMMAND crash_origin_gate_test)

# post-V1-retirement — artifact-first universal contract acceptance oracle.

# §3.11-B — ConsoleRingBuffer unit test.
target_link_libraries(console_ring_buffer_test
    PRIVATE
        refuzz_channel
        refuzz_core
        pthread
)
add_test(NAME console_ring_buffer_test COMMAND console_ring_buffer_test)

# §3.11-C — Dedup description finer-grain test.
target_link_libraries(crash_dedup_finer_grain_test
    PRIVATE
        refuzz_crash
        refuzz_channel
        refuzz_core
        pthread
)
add_test(NAME crash_dedup_finer_grain_test COMMAND crash_dedup_finer_grain_test)

# §3.11-D — EvidenceFragment / Incident smoke test.
target_link_libraries(evidence_fragment_smoke_test
    PRIVATE
        refuzz_crash
        refuzz_program
        refuzz_core
        pthread
)
add_test(NAME evidence_fragment_smoke_test COMMAND evidence_fragment_smoke_test)

# §3.11-E — IIncidentAnalyzer registry test.
target_link_libraries(incident_analyzer_registry_test
    PRIVATE
        refuzz_crash
        refuzz_program
        refuzz_core
        pthread
)
add_test(NAME incident_analyzer_registry_test COMMAND incident_analyzer_registry_test)

# §3.11-F — EvidenceBlobStore test.
target_link_libraries(evidence_blob_store_test
    PRIVATE
        refuzz_crash
        refuzz_core
        pthread
)
add_test(NAME evidence_blob_store_test COMMAND evidence_blob_store_test)

target_link_libraries(linux_amd64_call_table_test
    PRIVATE
        refuzz_program
)
add_test(NAME linux_amd64_call_table_test COMMAND linux_amd64_call_table_test)

# Phase 2 §B v1 — XiUOS UART wire codec golden + round-trip tests.
add_executable(xiuos_uart_codec_test
    xiuos_uart_codec_test.cpp
)
target_link_libraries(xiuos_uart_codec_test
    PRIVATE
        refuzz_channel
        refuzz_core
        pthread
)
add_test(NAME xiuos_uart_codec_test COMMAND xiuos_uart_codec_test)

# Phase 2 §B v1 — XiUOS UART backbone unit tests (no QEMU).
# Cover the two findings from the v1 review: pending-frame queue (HIGH) and
# cross-thread Close shutdown() wake (MEDIUM).
add_executable(xiuos_uart_backbone_test
    xiuos_uart_backbone_test.cpp
)
target_link_libraries(xiuos_uart_backbone_test
    PRIVATE
        refuzz_channel
        refuzz_core
        pthread
)
add_test(NAME xiuos_uart_backbone_test COMMAND xiuos_uart_backbone_test)

# Phase 2 §B v1 — XiUOS UART assembler + catalog wiring tests (no QEMU).
# Verifies XiuosUartProfile / QemuUartXiuosAssembler.Assemble +
# .AssembleAndBuild + ChannelCatalog.Build paths construct components and
# return non-null IChannel without exercising Boot (Boot E2E lives in a
# follow-up test once Channel::Boot is verified against the XiUOS stack).
add_executable(xiuos_uart_assembler_test
    xiuos_uart_assembler_test.cpp
)
target_link_libraries(xiuos_uart_assembler_test
    PRIVATE
        refuzz_channel
        refuzz_core
        pthread
)
add_test(NAME xiuos_uart_assembler_test COMMAND xiuos_uart_assembler_test)

# Phase 2 §B v1 review fixes — HIGH WaitAllWorkersReady(0) fallback +
# MEDIUM BeginSession state machine. Uses a 127.0.0.1 TCP loopback peer;
# no QEMU required.
add_executable(xiuos_uart_control_plane_test
    xiuos_uart_control_plane_test.cpp
)
target_link_libraries(xiuos_uart_control_plane_test
    PRIVATE
        refuzz_channel
        refuzz_core
        pthread
)
add_test(NAME xiuos_uart_control_plane_test
         COMMAND xiuos_uart_control_plane_test)

# XiUOS UART DataPlane state-machine tests. Uses a TCP loopback peer that
# intentionally never sends RESULT frames; no QEMU required.
add_executable(xiuos_uart_data_plane_test
    xiuos_uart_data_plane_test.cpp
)
target_link_libraries(xiuos_uart_data_plane_test
    PRIVATE
        refuzz_channel
        refuzz_core
        pthread
)
add_test(NAME xiuos_uart_data_plane_test
         COMMAND xiuos_uart_data_plane_test)

# Poll-to-health wedge bridge test. No QEMU required.
add_executable(wedge_relay_sensor_test
    wedge_relay_sensor_test.cpp
)
target_link_libraries(wedge_relay_sensor_test
    PRIVATE
        refuzz_channel
        refuzz_core
        pthread
)
add_test(NAME wedge_relay_sensor_test
         COMMAND wedge_relay_sensor_test)

# Phase 2 §B v1 review fix — MEDIUM IsVMAlive must reap zombies. Uses
# /bin/true as the "qemu_bin" so the child exits immediately.
add_executable(xiuos_uart_substrate_test
    xiuos_uart_substrate_test.cpp
)
target_link_libraries(xiuos_uart_substrate_test
    PRIVATE
        refuzz_channel
        refuzz_core
        pthread
)
add_test(NAME xiuos_uart_substrate_test
         COMMAND xiuos_uart_substrate_test)

# Phase 2 §C #16 — XiUOS coverage Feedback signal unit tests.
# AFL log2 bucketize + 256B global bitmap OR; pinned by 050 §Stage 6.
add_executable(xiuos_coverage_signal_test
    xiuos_coverage_signal_test.cpp
)
target_link_libraries(xiuos_coverage_signal_test
    PRIVATE
        refuzz_feedback
        refuzz_core
        pthread
)
add_test(NAME xiuos_coverage_signal_test
         COMMAND xiuos_coverage_signal_test)

add_executable(xiuos_oracle_signal_test
    xiuos_oracle_signal_test.cpp
)
target_link_libraries(xiuos_oracle_signal_test
    PRIVATE
        refuzz_feedback
        refuzz_core
        pthread
)
add_test(NAME xiuos_oracle_signal_test
         COMMAND xiuos_oracle_signal_test)

# Phase 2 §B #15 — XiUOS Program seed JSON loader / encoder unit tests (no QEMU).
add_executable(xiuos_program_seed_test
    xiuos_program_seed_test.cpp
)
target_link_libraries(xiuos_program_seed_test
    PRIVATE
        refuzz_program
        refuzz_core
        pthread
)
add_test(NAME xiuos_program_seed_test
         COMMAND xiuos_program_seed_test)

# Phase 2 §B #15 acceptance gate — generated seeds → Channel → Completion
# → XiuosCoverageSignal. SKIPs (exit 0) if ELF or corpus tree absent.
add_executable(xiuos_program_seed_e2e_smoke
    xiuos_program_seed_e2e_smoke.cpp
)
target_link_libraries(xiuos_program_seed_e2e_smoke
    PRIVATE
        refuzz_channel
        refuzz_feedback
        refuzz_program
        refuzz_core
        pthread
)
target_compile_definitions(xiuos_program_seed_e2e_smoke
    PRIVATE
        XIUOS_GENERATED_CORPUS_DIR_DEFAULT="${CMAKE_SOURCE_DIR}/run/xiuos/corpus/generated"
)
add_test(NAME xiuos_program_seed_e2e_smoke
         COMMAND xiuos_program_seed_e2e_smoke)

# Phase 2 §C #17 acceptance gate — XiuosCoverageSignal interesting
# → CompositeFeedbackEngine → CorpusInbox → CorpusManager → InMemoryCorpusStore
# + CorpusDiskIO::SaveSeed. Three assertions: pipeline correctness, in-memory
# dedupe, persistence + reload. SKIPs if ELF or corpus tree absent.

# Phase 2 §C #18 — XiUOS crash bucket unit tests (no QEMU; synthetic
# AbnormalCompletion events). Covers MakeBucketKey format, persist + dedup
# semantics, bucket separation by (trap_pc, mcause), ignore rules, and
# LoadFromDisk recovery.
add_executable(xiuos_crash_bucket_test
    xiuos_crash_bucket_test.cpp
)
target_link_libraries(xiuos_crash_bucket_test
    PRIVATE
        refuzz_feedback
        refuzz_program
        refuzz_core
        pthread
)
add_test(NAME xiuos_crash_bucket_test
         COMMAND xiuos_crash_bucket_test)

# Phase 2 §C #20 acceptance gate — full mutation pipeline E2E. Loads
# generated corpus seeds, mutates K times each via XiuosMutatorEngine,
# drives Channel + admission + crash bucket. Asserts: pipeline stays
# alive under mutated inputs, signal admits at least one, all four
# mutator ops fired across the batch. SKIPs if ELF/corpus absent.

# Phase 2 §C #21 acceptance gate — scheduler-driven closed fuzz loop.
# Bootstraps corpus, then loops with PrioritySchedulerEngine + RoundRobin:
# scheduler.NextSeedId → store.GetSeed → mutator.Mutate → Channel.Submit →
# DrainEvents → admission/bucket → manager.Tick (admits new seeds → next
# scheduler tick sees them). Asserts corpus grows during the loop and
# scheduler hands out more distinct ids than the bootstrap count, which
# proves newly admitted seeds become selectable.
add_executable(xiuos_scheduler_loop_e2e_smoke
    xiuos_scheduler_loop_e2e_smoke.cpp
)
target_link_libraries(xiuos_scheduler_loop_e2e_smoke
    PRIVATE
        refuzz_control
        pthread
)
target_compile_definitions(xiuos_scheduler_loop_e2e_smoke
    PRIVATE
        XIUOS_GENERATED_CORPUS_DIR_DEFAULT="${CMAKE_SOURCE_DIR}/run/xiuos/corpus/generated"
)
add_test(NAME xiuos_scheduler_loop_e2e_smoke
         COMMAND xiuos_scheduler_loop_e2e_smoke)

# Phase 2 §C #22 — configurable stress run for the XiUOS scheduler-driven
# fuzz loop. Defaults to 500 iterations; tunable via XIUOS_STRESS_*
# env vars (ITERATIONS / BOOTSTRAP_COUNT / PROGRESS_EVERY / VIOLATION_PCT
# / INVALID_ARG_PCT / MAX_CALLS / MUT_SEED). Liveness-only assertions —
# coverage plateaus quickly on XiUOS's small API surface so we don't
# require unbounded growth.
add_executable(xiuos_stress_loop_smoke
    xiuos_stress_loop_smoke.cpp
)
target_link_libraries(xiuos_stress_loop_smoke
    PRIVATE
        refuzz_control
        pthread
)
target_compile_definitions(xiuos_stress_loop_smoke
    PRIVATE
        XIUOS_GENERATED_CORPUS_DIR_DEFAULT="${CMAKE_SOURCE_DIR}/run/xiuos/corpus/generated"
)
add_test(NAME xiuos_stress_loop_smoke
         COMMAND xiuos_stress_loop_smoke)
# CI smoke uses the tighter pre-2026-05-23 wedge drain so CTest wallclock
# stays bounded. Production / operator runs inherit the 8s/12s Config
# defaults — they're the empirically-correct floor for slow blocking
# programs (see XiuosFuzzSessionConfig comment).
set_tests_properties(xiuos_stress_loop_smoke PROPERTIES
    ENVIRONMENT "XIUOS_WEDGE_INITIAL_DRAIN_MS=5000;XIUOS_WEDGE_VERIFY_DRAIN_MS=8000")

add_executable(xiuos_archive_replay_smoke
    xiuos_archive_replay_smoke.cpp
)
target_link_libraries(xiuos_archive_replay_smoke
    PRIVATE
        refuzz_control
        pthread
)
target_compile_definitions(xiuos_archive_replay_smoke
    PRIVATE
        XIUOS_GENERATED_CORPUS_DIR_DEFAULT="${CMAKE_SOURCE_DIR}/run/xiuos/corpus/generated"
)
# Default 500 iter × ~30-50ms/round-trip ≈ 25s; allow plenty of slack
# for operators running with bumped XIUOS_STRESS_ITERATIONS up to ~5000.
set_tests_properties(xiuos_stress_loop_smoke PROPERTIES TIMEOUT 600)

# Timer + Event blocking ops (KEventProcess, KMsgQueueRecv with non-zero
# timeouts) add real per-program latency. Mutation-driven tests that
# chain N mutations × M base seeds inherit that latency over hundreds of
# submits and need a generous CTest timeout. Pre-Timer baseline was
# ~2s; with full priority-family surface ~120s.
set_tests_properties(xiuos_scheduler_loop_e2e_smoke PROPERTIES TIMEOUT 300)

# ──────────────────────────────────────────────────────────────
# [mab-stage-selection Step 0] MabReward + Exp3Bandit 纯算法单测。
# 两个 mab 源无 IO / 无 refuzz 依赖,直接编进测试可执行,不链 refuzz_control。
# ──────────────────────────────────────────────────────────────
add_executable(mab_bandit_reward_test
    mab_bandit_reward_test.cpp
    ${CMAKE_SOURCE_DIR}/core/src/mab/mab_reward.cpp
    ${CMAKE_SOURCE_DIR}/core/src/mab/exp3_bandit.cpp
)
target_include_directories(mab_bandit_reward_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/core/include
)
add_test(NAME mab_bandit_reward_test COMMAND mab_bandit_reward_test)

# [mab-stage-selection Step 1] MabTaskSelector 单测(同样直接编三个 mab 源,纯算法)。
add_executable(mab_task_selector_test
    mab_task_selector_test.cpp
    ${CMAKE_SOURCE_DIR}/core/src/mab/mab_reward.cpp
    ${CMAKE_SOURCE_DIR}/core/src/mab/exp3_bandit.cpp
    ${CMAKE_SOURCE_DIR}/control/src/mab/mab_task_selector.cpp
)
target_include_directories(mab_task_selector_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/core/include
        ${CMAKE_SOURCE_DIR}/control/include
)
add_test(NAME mab_task_selector_test COMMAND mab_task_selector_test)

# crash-execution-history-ring Step 1 — Layer-2 per-worker completed-program ring
# (async-deferred crash-trigger capture). Header-only; STL-only deps.
add_executable(recent_program_ring_test
    recent_program_ring_test.cpp
)
target_include_directories(recent_program_ring_test
    PRIVATE
        ${CMAKE_SOURCE_DIR}/executor/channel/orchestration/include
        ${CMAKE_SOURCE_DIR}/core/include
)
add_test(NAME recent_program_ring_test COMMAND recent_program_ring_test)

# crash-execution-history-ring D5 — DiagnosticStore persists prog0.bin + the
# Layer-2 history (history{0..N}.bin) + meta.json history_count.
add_executable(diagnostic_store_history_persist_test
    diagnostic_store_history_persist_test.cpp
)
target_link_libraries(diagnostic_store_history_persist_test
    PRIVATE
        refuzz_crash
        refuzz_program
        refuzz_core
        pthread
)
add_test(NAME diagnostic_store_history_persist_test COMMAND diagnostic_store_history_persist_test)

# async-crash-reproduction Phase 1.5 — typed V2-IR concat (merge typed programs →
# one Prog + exec-wire payload + typed artifact, so a bisect/concat repro extract
# is minimizable). Needs the mutator engine to synthesize test programs.
add_executable(program_concat_typed_test
    program_concat_typed_test.cpp
)
target_link_libraries(program_concat_typed_test
    PRIVATE
        refuzz_crash
        refuzz_mutator
        refuzz_program
        refuzz_core
        pthread
)
add_test(NAME program_concat_typed_test COMMAND program_concat_typed_test)

# [mab-stage-selection Step 2] MabExp3IxPolicy(seed-MAB)单测,链 refuzz_corpus(policy+engine)。
add_executable(mab_seed_policy_test
    mab_seed_policy_test.cpp
)
target_link_libraries(mab_seed_policy_test
    PRIVATE
        refuzz_corpus
        refuzz_core
        pthread
)
add_test(NAME mab_seed_policy_test COMMAND mab_seed_policy_test)

# [job-loop 重设计 Step 3 Slice A] deflake 抽取纯逻辑单测(SelectStableCall /
# ComputeNewStableCallCandidates / k-of-n voting / SelectStableExecStatus /
# ComputeFullStableCover)。抽取前无直测,此测钉住旧 stage + 新 core-path job 共依赖的行为。
add_executable(triage_deflake_test triage_deflake_test.cpp)
target_link_libraries(triage_deflake_test
    PRIVATE
        refuzz_control
        refuzz_program
        refuzz_core
        pthread
)
add_test(NAME triage_deflake_test COMMAND triage_deflake_test)

add_executable(core_path_deflake_test core_path_deflake_test.cpp)
target_link_libraries(core_path_deflake_test
    PRIVATE
        refuzz_control
        refuzz_program
        refuzz_core
        pthread
)
add_test(NAME core_path_deflake_test COMMAND core_path_deflake_test)

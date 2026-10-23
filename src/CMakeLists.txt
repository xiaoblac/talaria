cmake_minimum_required(VERSION 3.15)
project(reFuzz LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# C++23 <expected>: clang may point at an older libstdc++ without <expected>. If the default
# stdlib cannot compile it, fall back to LLVM libc++ (-stdlib=libc++), matching docs/BUILDING.md.
include(CheckCXXSourceCompiles)
check_cxx_source_compiles("
#include <expected>
int main() {
  std::expected<int, int> e{1};
  return *e;
}
" REFUZZ_HAVE_EXPECTED_DEFAULT)

if(NOT REFUZZ_HAVE_EXPECTED_DEFAULT)
  set(_refuzz_saved_req_flags "${CMAKE_REQUIRED_FLAGS}")
  string(APPEND CMAKE_REQUIRED_FLAGS " -stdlib=libc++")
  check_cxx_source_compiles("
#include <expected>
int main() {
  std::expected<int, int> e{1};
  return *e;
}
" REFUZZ_HAVE_EXPECTED_LIBCXX)
  set(CMAKE_REQUIRED_FLAGS "${_refuzz_saved_req_flags}")
  unset(_refuzz_saved_req_flags)
  if(REFUZZ_HAVE_EXPECTED_LIBCXX)
    add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-stdlib=libc++>)
    add_link_options($<$<COMPILE_LANGUAGE:CXX>:-stdlib=libc++>)
    message(STATUS "reFuzz: <expected> requires libc++; using -stdlib=libc++")
  else()
    message(FATAL_ERROR
      "C++23 <expected> is not available with the default libstdc++ or with -stdlib=libc++. "
      "Install libc++ / libc++abi for your Clang (e.g. libc++-20-dev on Debian/Ubuntu) or use GCC 12+ libstdc++.")
  endif()
else()
  message(STATUS "reFuzz: <expected> OK with default C++ standard library")
endif()

# [perf 2026-05-22 reverted] A+B (-flto=thin + -fno-exceptions/-fno-rtti)
# 实测 3-run stable -2.4% prog/s regression (vs -O2 only). worker_total /
# sync_gap 微正向 (LTO 让 hot path 紧凑), 但 fork/wait 微负, net -2.4%.
# 编译期 ceiling 已被 -O2 吃掉. ThinLTO + no-exc/rtti 都 revert.
# AsIvshmem() helper 保留 (无害 + future RTTI off 可行).


add_library(refuzz_proto_domain INTERFACE)
target_include_directories(refuzz_proto_domain INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/proto/domain/include
)

add_library(refuzz_proto_wire INTERFACE)
target_include_directories(refuzz_proto_wire INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/proto/wire/include
)

add_library(refuzz_core STATIC
    core/src/service_registry.cpp
    core/src/metrics/metric_registry.cpp
    core/src/metrics/metric_lookup.cpp
    core/src/metrics/fuzzer_metrics.cpp
    core/src/metrics/executor_metrics.cpp
    core/src/metrics/channel_metrics.cpp
    core/src/metrics/policy_state_publisher.cpp
    # [mab-stage-selection] 共享 MAB 原语(refuzz::mab):task-MAB(control)+ seed-MAB
    # (corpus scheduler policy)都复用。纯算法、无 IO。
    core/src/mab/exp3_bandit.cpp
    core/src/mab/mab_reward.cpp
)
target_include_directories(refuzz_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/core/include
)
target_link_libraries(refuzz_core PUBLIC refuzz_proto_domain)

option(REFUZZ_BUILD_WORKER "Build guest ivshmem_worker executable" ON)
option(REFUZZ_BUILD_TESTS "Build test targets" ON)

# Vendored stackful-coroutine primitive (libaco). refuzz_control runs each Job
# as a coroutine on one shared stack instead of one OS thread per Job — see
# third_party/libaco/README.refuzz.md and control/src/job/job.cpp.
add_subdirectory(third_party/libaco)

# 依赖 DAG（自上而下）：logging/queue -> program -> mutator/feedback -> corpus ->
# channel -> worker -> channeldispatcher -> crash -> telemetry -> control（含 control/orchestrator 子目录）
add_subdirectory(logging)
add_subdirectory(queue)
add_subdirectory(program)
add_subdirectory(mutator)
add_subdirectory(feedback)
add_subdirectory(corpus)
add_subdirectory(executor/channel)
if (REFUZZ_BUILD_WORKER)
    add_subdirectory(executor/channel/worker)
endif()
add_subdirectory(executor/channeldispatcher)
add_subdirectory(crash)
add_subdirectory(telemetry)
add_subdirectory(control)

# Phase 2 §C #22 follow-up — XiUOS crash bucket triage CLI. Reads an
# on-disk XiuosCrashBucket directory and prints per-bucket trap_pc +
# mcause analysis. Symbol resolution via addr2line subprocess when
# --elf is provided.
add_executable(refuzz_xiuos_triage tools/refuzz_xiuos_triage/main.cpp)
target_link_libraries(refuzz_xiuos_triage PRIVATE refuzz_program)
set_target_properties(refuzz_xiuos_triage PROPERTIES OUTPUT_NAME refuzz-xiuos-triage)

# [Stage 3 去山头] 把 XiUOS JSON descriptor 语料预编码成 orchestrator 认的
# canonical wire-byte 种子 (<out>/<hash16>/payload.bin),桥接 CorpusDiskIO::LoadAll。
add_executable(xiuos_corpus_encode tools/xiuos_corpus_encode/main.cpp)
target_link_libraries(xiuos_corpus_encode PRIVATE refuzz_program)
set_target_properties(xiuos_corpus_encode PROPERTIES OUTPUT_NAME xiuos-corpus-encode)

# Structural dump of the new v2 polymorphic IR — used to verify
# IR表达力 ≥ syzkaller IR by diffing against a Go-side prog.Target dump.
add_executable(refuzz_syz_v2_dump tools/refuzz_syz_v2_dump/main.cpp)
target_link_libraries(refuzz_syz_v2_dump PRIVATE refuzz_program_syz_v2)
set_target_properties(refuzz_syz_v2_dump PROPERTIES OUTPUT_NAME refuzz-syz-v2-dump)

# v2 text codec round-trip oracle: parse .syz then re-emit canonical form.
add_executable(refuzz_syz_v2_text tools/refuzz_syz_v2_text/main.cpp)
target_link_libraries(refuzz_syz_v2_text PRIVATE refuzz_program_syz_v2)
set_target_properties(refuzz_syz_v2_text PROPERTIES OUTPUT_NAME refuzz-syz-v2-text)

# v2 integrity self-check (L2 verification).
add_executable(refuzz_syz_v2_check tools/refuzz_syz_v2_check/main.cpp)
target_link_libraries(refuzz_syz_v2_check PRIVATE refuzz_program_syz_v2)
set_target_properties(refuzz_syz_v2_check PROPERTIES OUTPUT_NAME refuzz-syz-v2-check)

# v2 full field-level enumeration (L1 verification).
add_executable(refuzz_syz_v2_enum tools/refuzz_syz_v2_enum/main.cpp)
target_link_libraries(refuzz_syz_v2_enum PRIVATE refuzz_program_syz_v2)
set_target_properties(refuzz_syz_v2_enum PROPERTIES OUTPUT_NAME refuzz-syz-v2-enum)

# v2 text round-trip batch tool (L3 verification): single process loads
# Target once and round-trips every file in indir.
add_executable(refuzz_syz_v2_text_batch tools/refuzz_syz_v2_text_batch/main.cpp)
target_link_libraries(refuzz_syz_v2_text_batch PRIVATE refuzz_program_syz_v2)
set_target_properties(refuzz_syz_v2_text_batch PROPERTIES OUTPUT_NAME refuzz-syz-v2-text-batch)

# v2 corpus dump tool: walks <corpus_root>/<seed_id>/payload.bin and writes
# a decoded_corpus.log compatible with tools/decode_prog.py output, but with
# fuzzer-sourced TextDecoder so canonical text never schema-drifts. On fail
# prints payload length + hex header + decoder line/col so v1-wire / corrupt
# / non-canonical payloads can be triaged.
add_executable(refuzz_syz_v2_corpus_dump tools/refuzz_syz_v2_corpus_dump/main.cpp)
target_link_libraries(refuzz_syz_v2_corpus_dump PRIVATE refuzz_program_syz_v2)
set_target_properties(refuzz_syz_v2_corpus_dump PROPERTIES OUTPUT_NAME refuzz-syz-v2-corpus-dump)

# Measure the real in-memory footprint of a materialized corpus (held Prog RSS +
# SEGS image bytes/seed) — answers "how much does the corpus actually occupy".
add_executable(refuzz_corpus_memprobe tools/refuzz_corpus_memprobe/main.cpp)
target_link_libraries(refuzz_corpus_memprobe PRIVATE refuzz_program refuzz_program_syz_v2)
set_target_properties(refuzz_corpus_memprobe PROPERTIES OUTPUT_NAME refuzz-corpus-memprobe)

# Static resource graph dump (per-syscall produces/consumes/uses + resource
# kind hierarchy) — the spec-graph anchor for the structural-horizon seed-value
# calibration (docs/plans/structural-horizon-seed-value.md §5.1).
add_executable(refuzz_seed_horizon_dump tools/refuzz_seed_horizon_dump/main.cpp)
# refuzz_mutator: static ChoiceTable (call-transition prior, prio.go analogue).
target_link_libraries(refuzz_seed_horizon_dump PRIVATE refuzz_mutator refuzz_program refuzz_program_syz_v2)
set_target_properties(refuzz_seed_horizon_dump PROPERTIES OUTPUT_NAME refuzz-seed-horizon-dump)

# [variant-handler-binding 2026-06-18] per-variant cmd const VALUES + resources from
# the syzlang grammar (structural join key into the kernel ioctl dispatch tables).
add_executable(refuzz_variant_grammar_dump tools/refuzz_variant_grammar_dump/main.cpp)
target_link_libraries(refuzz_variant_grammar_dump PRIVATE refuzz_mutator refuzz_program refuzz_program_syz_v2)
set_target_properties(refuzz_variant_grammar_dump PROPERTIES OUTPUT_NAME refuzz-variant-grammar-dump)

# refuzz-kernel-block-map — function-granularity block map from vmlinux_cf.txt
# (the block-residual mask's static input: per function, its trace-pc block count
# + start address, so a covered PC's function and its uncovered-sibling residual
# are computable in-engine without dispatch recovery).
add_executable(refuzz_kernel_block_map tools/refuzz_kernel_block_map/main.cpp)
set_target_properties(refuzz_kernel_block_map PROPERTIES OUTPUT_NAME refuzz-kernel-block-map)

# v2 validation batch tool: decode + validate every .syz in a directory.
add_executable(refuzz_syz_v2_validate tools/refuzz_syz_v2_validate/main.cpp)
target_link_libraries(refuzz_syz_v2_validate PRIVATE refuzz_program_syz_v2)
set_target_properties(refuzz_syz_v2_validate PROPERTIES OUTPUT_NAME refuzz-syz-v2-validate)

# v2 exec-wire batch encoder (§3.2 oracle): decode each .syz then write
# the SerializeForExec byte stream. Pair with `tools/syzgen exec-wire-diff`
# for the byte-equal cross-implementation check.
add_executable(refuzz_syz_v2_exec_wire tools/refuzz_syz_v2_exec_wire/main.cpp)
target_link_libraries(refuzz_syz_v2_exec_wire PRIVATE refuzz_program_syz_v2)
set_target_properties(refuzz_syz_v2_exec_wire PROPERTIES OUTPUT_NAME refuzz-syz-v2-exec-wire)

# Fixed-workload characterization for the system-paper evaluation.  This uses
# the production v2 request-stream reader and typed syz program model; it never
# infers syscall semantics from serialized text.
add_executable(refuzz_workload_characterize
    tools/refuzz_workload_characterize/main.cpp
    control/src/request_stream_reader.cpp)
target_include_directories(refuzz_workload_characterize PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/control/include)
target_link_libraries(refuzz_workload_characterize PRIVATE refuzz_program_syz_v2)
set_target_properties(refuzz_workload_characterize
    PROPERTIES OUTPUT_NAME refuzz-workload-characterize)

# v2 exec-wire decoder roundtrip (§3.3 Layer-1 oracle): encode → decode →
# re-encode, assert byte-equal. Proves the decoder is the inverse of the
# encoder — combined with §3.2's byte-equal-vs-syzkaller, this means the
# wire is a bidirectional bijection with prog.Prog.SerializeForExec.
add_executable(refuzz_syz_v2_exec_wire_roundtrip
    tools/refuzz_syz_v2_exec_wire_roundtrip/main.cpp)
target_link_libraries(refuzz_syz_v2_exec_wire_roundtrip PRIVATE refuzz_program_syz_v2)
set_target_properties(refuzz_syz_v2_exec_wire_roundtrip
    PROPERTIES OUTPUT_NAME refuzz-syz-v2-exec-wire-roundtrip)

# v2 wire trace dumper (§3.3 Layer-3 milestone I.3): walks decode_exec_wire
# output and emits the dispatch-shape JSONL, paired with `tools/syzgen
# exec-trace-dump` (Go IR walk) for trace-equivalence acceptance.
add_executable(refuzz_syz_v2_exec_trace
    tools/refuzz_syz_v2_exec_trace/main.cpp)
target_link_libraries(refuzz_syz_v2_exec_trace PRIVATE refuzz_program_syz_v2)
set_target_properties(refuzz_syz_v2_exec_trace
    PROPERTIES OUTPUT_NAME refuzz-syz-v2-exec-trace)

# v2 bulk generator (§3.4 milestone V.9): produces N random programs to a
# directory; consumed by the validate-on-generated and round-trip oracles.
if (TARGET refuzz_mutator)
    add_executable(refuzz_syz_v2_gen tools/refuzz_syz_v2_gen/main.cpp)
    target_link_libraries(refuzz_syz_v2_gen PRIVATE refuzz_mutator refuzz_program)
    set_target_properties(refuzz_syz_v2_gen
        PROPERTIES OUTPUT_NAME refuzz-syz-v2-gen)

    # v2 bulk mutator (§3.5): reads .syz files from -indir, applies the
    # active policy via SyzV2MutatorEngine, writes mutated text to
    # -outdir. Consumed by the §3.5 mutate-on-corpus oracle (validate
    # every output, no dangling resource refs). M0 lands stubs so all
    # outputs equal inputs (engine returns original payload when ops
    # decline); M1+ fill the algorithmic core.
    add_executable(refuzz_syz_v2_mutate tools/refuzz_syz_v2_mutate/main.cpp)
    target_link_libraries(refuzz_syz_v2_mutate PRIVATE refuzz_mutator refuzz_program)
    set_target_properties(refuzz_syz_v2_mutate
        PROPERTIES OUTPUT_NAME refuzz-syz-v2-mutate)

    # v2 choice-ref (§3.6 M0): emit choice-table reference JSON for
    # byte-equal diff against `tools/syzgen choice-ref`.
    add_executable(refuzz_syz_v2_choice_ref tools/refuzz_syz_v2_choice_ref/main.cpp)
    target_link_libraries(refuzz_syz_v2_choice_ref PRIVATE refuzz_mutator refuzz_program)
    set_target_properties(refuzz_syz_v2_choice_ref
        PROPERTIES OUTPUT_NAME refuzz-syz-v2-choice-ref)

endif()

# v2 wire-driver smoke (§3.3 Layer-2 oracle): runs the full wire pipeline
# through KernelWireDriver with a MockDispatcher (never enters the kernel).
# Proves the wire interpreter walks the instruction stream without crashing
# and translates call_id → SyscallMeta::nr correctly.
if (TARGET refuzz_worker_core)
    add_executable(refuzz_syz_v2_wire_driver_smoke
        tools/refuzz_syz_v2_wire_driver_smoke/main.cpp)
    target_link_libraries(refuzz_syz_v2_wire_driver_smoke PRIVATE refuzz_worker_core refuzz_program)
    set_target_properties(refuzz_syz_v2_wire_driver_smoke
        PROPERTIES OUTPUT_NAME refuzz-syz-v2-wire-driver-smoke)

    # Layer-3 milestone II.6: real-syscall harness via SyscallOrPseudoDispatcher.
    # Default-deny — programs must appear in the safe-corpus manifest unless
    # -allow-unsafe is set (only inside an isolated VM/container).
    add_executable(refuzz_syz_v2_wire_driver_real
        tools/refuzz_syz_v2_wire_driver_real/main.cpp)
    target_link_libraries(refuzz_syz_v2_wire_driver_real PRIVATE refuzz_worker_core refuzz_program)
    set_target_properties(refuzz_syz_v2_wire_driver_real
        PROPERTIES OUTPUT_NAME refuzz-syz-v2-wire-driver-real)

    # Layer-3 milestone III.10: stdio-protocol wrapper for the wire driver.
    # Speaks the same contract as tools/syz_executor_stdio_wrapper (III.9);
    # consumed by the paired-VM orchestrator (III.12).
    add_executable(refuzz_wire_driver_stdio
        tools/refuzz_wire_driver_stdio/main.cpp)
    target_link_libraries(refuzz_wire_driver_stdio PRIVATE refuzz_worker_core refuzz_program refuzz_feedback)
    if (TARGET refuzz_executor)
        add_dependencies(refuzz_wire_driver_stdio refuzz_executor)
        target_compile_definitions(refuzz_wire_driver_stdio PRIVATE
            REFUZZ_EXECUTOR_DEFAULT_PATH="$<TARGET_FILE:refuzz_executor>")
    endif()
    set_target_properties(refuzz_wire_driver_stdio
        PROPERTIES OUTPUT_NAME refuzz-wire-driver-stdio)
endif()

# Epic 4 PR-4-D — operator-driven oracle for #c-repro-3 (csource::Write
# coverage) and #c-repro-4 (csource::Build success rate). Walks a
# directory of .syz text fixtures, drives Write+Build, and reports the
# four-bucket histogram pinned by the oracle ledger #30 / #31. Pure
# host: no VM, no executor binding. NOT in default ctest — run by hand
# after a csource / common-header / sysTarget cflags change, or before
# the next PR-4-D refresh.
add_executable(csource_emit_oracle tools/csource_emit_oracle/main.cpp)
target_link_libraries(csource_emit_oracle
    PRIVATE refuzz_crash refuzz_program refuzz_core)
set_target_properties(csource_emit_oracle
    PROPERTIES OUTPUT_NAME csource-emit-oracle)

find_program(GO_EXECUTABLE go REQUIRED)
set(REFUZZ_SYZKALLER_ROOT "/workspace/syzkaller" CACHE PATH "syzkaller checkout used by tools/syzgen")
# Phase 2 layout sweep: split syzgen output between schema-side
# (consts dict) and worker-facing pseudo metadata. Both dirs are
# parallel children of program/include/refuzz/program/syz/.
set(REFUZZ_SYZ_CONSTS_DIR
    "${CMAKE_SOURCE_DIR}/program/include/refuzz/program/syz/generated"
    CACHE PATH "generated syzkaller consts.gen.hpp output directory")
set(REFUZZ_SYZ_PSEUDO_DIR
    "${CMAKE_SOURCE_DIR}/program/include/refuzz/program/syz/pseudo/generated"
    CACHE PATH "generated syzkaller pseudo metadata output directory")

add_custom_target(syz_regen
    COMMAND ${GO_EXECUTABLE} run ./tools/syzgen all
            -os linux -arch amd64
            -syzkaller-root ${REFUZZ_SYZKALLER_ROOT}
            -consts-out ${REFUZZ_SYZ_CONSTS_DIR}
            -pseudo-out ${REFUZZ_SYZ_PSEUDO_DIR}
            -pin-file ${CMAKE_SOURCE_DIR}/.syzkaller-pin
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Regenerating syzkaller metadata with tools/syzgen")

add_custom_target(syz_verify
    COMMAND ${GO_EXECUTABLE} run ./tools/syzgen verify
            -os linux -arch amd64
            -syzkaller-root ${REFUZZ_SYZKALLER_ROOT}
            -consts-out ${REFUZZ_SYZ_CONSTS_DIR}
            -pseudo-out ${REFUZZ_SYZ_PSEUDO_DIR}
            -pin-file ${CMAKE_SOURCE_DIR}/.syzkaller-pin
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Verifying checked-in syzkaller metadata with tools/syzgen")

# Re-emit USB / HID ID database from upstream sys/linux/init_vusb_ids.go.
# Operator-driven (run after syzkaller upstream rebase touches that file);
# CI does NOT auto-run this — generated files are checked into git per
# plan §5.5. Golden test in tools/syz_usbgen_emit catches drift.
add_custom_target(syz_regen_usb
    COMMAND ${GO_EXECUTABLE} run ./tools/syz_usbgen_emit
            -in  ${REFUZZ_SYZKALLER_ROOT}/sys/linux/init_vusb_ids.go
            -hpp ${CMAKE_SOURCE_DIR}/program/include/refuzz/program/syz/linux/generated/usb_ids.gen.hpp
            -cpp ${CMAKE_SOURCE_DIR}/program/src/syz/linux/generated/usb_ids.gen.cpp
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Regenerating USB/HID ID database with tools/syz_usbgen_emit")

# Epic 4 PR-4-A — re-emit csource common header (executor/common*.h
# bundle). Operator-driven; CI does NOT auto-run this — generated
# file is checked into git; golden test in tools/csource_header_emit
# detects drift.
add_custom_target(syz_regen_csource_common
    COMMAND ${GO_EXECUTABLE} run ./tools/csource_header_emit
            -syzkaller-root ${REFUZZ_SYZKALLER_ROOT}
            -out ${CMAKE_SOURCE_DIR}/crash/repro/csource/src/csource_common_source.gen.cpp
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Regenerating csource common header bundle with tools/csource_header_emit")

add_custom_target(refuzz-syz-audit
    COMMAND ${CMAKE_SOURCE_DIR}/tools/syzgen/run_audit.sh
            ${GO_EXECUTABLE}
            ${CMAKE_SOURCE_DIR}
            ${REFUZZ_SYZKALLER_ROOT}
            ${CMAKE_SOURCE_DIR}/docs/syzkaller-integration/reports
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Writing Phase A syzkaller audit report with tools/syzgen audit")

# V2 production-exec paired oracle PR3-3b — replayer.
# Reads exec_trace_*.bin (proxy output) and submits ChannelDispatchRequest
# entries to an IChannel, recording outcomes to ref_result.bin. PR3-3b ships
# only the in-process echo backend; -backend=qemu_ivshmem_linux is wired
# in PR3-3c. Trace reader parses syzkaller flatrpc HostMessage frames via
# the upstream-generated pkg/flatrpc/flatrpc.h header (and its vendored
# flatbuffers runtime under executor/_include/).
# [chunk-based mount image] replayer inflates syz_mount_image imgs host-side at
# corpus load (see corpus_replay.cpp SegmentizeMountImages). find_package here
# because ZLIB::ZLIB is otherwise only created in the worker's CMake scope.
find_package(ZLIB REQUIRED)
add_executable(refuzz_exec_replayer
    tools/refuzz_exec_replayer/main.cpp
    tools/refuzz_exec_replayer/trace_reader.cpp
    tools/refuzz_exec_replayer/ref_result_writer.cpp
    tools/refuzz_exec_replayer/replayer.cpp
    tools/refuzz_exec_replayer/corpus_replay.cpp
    tools/refuzz_exec_replayer/echo_channel.cpp)
target_include_directories(refuzz_exec_replayer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/tools/refuzz_exec_replayer
    ${REFUZZ_SYZKALLER_ROOT}
    ${REFUZZ_SYZKALLER_ROOT}/executor/_include)
target_link_libraries(refuzz_exec_replayer PRIVATE
    refuzz_channel
    refuzz_core
    # refuzz_config_parser provides ParseConfigFromJson + OrchestratorConfig.
    # Replayer reuses it (PR3-3c) to avoid hand-rolling a channel JSON parser
    # that would drift from production schema. Cost: config must be phase5-
    # shaped (full top-level blocks). Heavy transitive deps (mutator / corpus /
    # feedback / telemetry / channeldispatcher / crash) come along but are
    # already built and only inflate the binary.
    refuzz_config_parser
    # Corpus-replay path consumes syz-prog text → wire bytes via TextDecoder
    # + serialize_for_exec. The existing refuzz-syz-v2-exec-wire tool already
    # links this lib so the build cost is amortized.
    refuzz_program_syz_v2
    # [speed-compare 严格 C] -collect-cover-mode kcov-pc 在 completion 同步路径
    # 复用 fuzz-loop 的 cover 解析(CoverageFeedbackCodec / DecodeSyzExecResults-
    # WithCoverage / NormalizeCoverageEntries),对齐 syzkaller convertCallInfo
    # 成本。PUBLIC include 还带来 worker/backend/syz_exec_runner.hpp(SyzExecResult)。
    refuzz_feedback
    # [chunk-based mount image] corpus-load decompresses each syz_mount_image
    # img ONCE host-side (zlib) and re-encodes it as non-zero segments (SEGS),
    # so the guest skips the per-exec decompress entirely. Needs libz here.
    ZLIB::ZLIB)
set_target_properties(refuzz_exec_replayer PROPERTIES OUTPUT_NAME refuzz-exec-replayer)

# refuzz_snapshot_driver — decoupled witness tool for the snapshot CHANNEL BACKEND.
# Production snapshot fuzzing is the qemu_ivshmem_snapshot_linux backend driven by
# the orchestrator; this tool assembles the same components (Runtime + ControlPlane
# + SnapshotDataPlane) directly and drives Submit/Poll to run determinism /
# state-isolation witnesses standalone. No separate session lib (the savevm/loadvm
# logic lives in the production SnapshotDataPlane inside refuzz_channel).
add_executable(refuzz_snapshot_driver
    tools/refuzz_snapshot_driver/main.cpp
    # Reuse the replayer's trace reader to extract a real ExecRequest payload
    # (= prog.SerializeForExec bytes = worker input) from a captured trace dir.
    tools/refuzz_exec_replayer/trace_reader.cpp)
target_include_directories(refuzz_snapshot_driver PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/tools/refuzz_exec_replayer
    ${REFUZZ_SYZKALLER_ROOT}
    ${REFUZZ_SYZKALLER_ROOT}/executor/_include)
target_link_libraries(refuzz_snapshot_driver PRIVATE
    refuzz_channel refuzz_core refuzz_feedback refuzz_program_syz_v2)
set_target_properties(refuzz_snapshot_driver PROPERTIES OUTPUT_NAME refuzz-snapshot-driver)

# Read-only trace diagnostic: decodes captured ExecRequest.Data back into
# per-call wire args so oracle mismatch rows can be joined to original params.
add_executable(refuzz_exec_trace_wire_dump
    tools/refuzz_exec_trace_wire_dump/main.cpp
    tools/refuzz_exec_replayer/trace_reader.cpp)
target_include_directories(refuzz_exec_trace_wire_dump PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/tools/refuzz_exec_replayer
    ${REFUZZ_SYZKALLER_ROOT}
    ${REFUZZ_SYZKALLER_ROOT}/executor/_include)
target_link_libraries(refuzz_exec_trace_wire_dump PRIVATE
    refuzz_program_syz_v2)
set_target_properties(refuzz_exec_trace_wire_dump
    PROPERTIES OUTPUT_NAME refuzz-exec-trace-wire-dump)

# V2 production-exec paired oracle PR4 — comparator / report.
# Go binary built via `go build` into ${CMAKE_BINARY_DIR} so all three V2
# tools (syz_flatrpc_proxy, refuzz_exec_replayer, refuzz_exec_oracle) land
# side-by-side under build-llvm20/. Mirrors plan §0 line 43 build cmd.
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/refuzz_exec_oracle.stamp
    COMMAND ${GO_EXECUTABLE} build -o ${CMAKE_BINARY_DIR}/refuzz_exec_oracle ./tools/refuzz_exec_oracle
    COMMAND ${CMAKE_COMMAND} -E touch ${CMAKE_BINARY_DIR}/refuzz_exec_oracle.stamp
    DEPENDS ${CMAKE_SOURCE_DIR}/tools/refuzz_exec_oracle/main.go
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Building refuzz_exec_oracle (V2 paired oracle comparator)")
add_custom_target(refuzz_exec_oracle DEPENDS ${CMAKE_BINARY_DIR}/refuzz_exec_oracle.stamp)

if (REFUZZ_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

cmake_minimum_required(VERSION 3.15)
project(refuzz_program CXX)

# v2 polymorphic IR — refuzz::program::syz namespace.
# Generated/*.gen.cpp is produced by `tools/syzgen target-cpp`.
file(GLOB REFUZZ_PROGRAM_V2_GENERATED
    "${CMAKE_CURRENT_SOURCE_DIR}/src/syz/generated/*.gen.cpp"
)

# [build-perf 2026-05-21] Generated files are init-time data table builders
# (上万次 push_back constructor 调用), runtime cost negligible. Compiling them
# with -O2/-O3 costs 5-8 GB RAM each (OOM on 16 GB machines with -j16).
# Force -O0 for these specific files; the rest of the project (hot code paths
# in driver/, coverage/, etc.) keep the Release -O2 setting from CMake build
# type. -O0 appended after global -O2; clang uses last -O wins.
set_source_files_properties(
    ${REFUZZ_PROGRAM_V2_GENERATED}
    "${CMAKE_CURRENT_SOURCE_DIR}/src/syz/linux/generated/usb_ids.gen.cpp"
    PROPERTIES COMPILE_OPTIONS "-O0"
)
set(REFUZZ_PROGRAM_V2_SOURCES
    src/syz/type.cpp
    src/syz/arg.cpp
    src/syz/target.cpp
    src/syz/alloc.cpp
    src/syz/analysis.cpp
    src/syz/size.cpp
    src/syz/encoding.cpp
    src/syz/validation.cpp
    src/syz/csum.cpp
    src/syz/exec_wire.cpp
    src/syz/exec_wire_decode.cpp
    src/syz/artifact_materializer.cpp
    src/syz/mount_image_segment.cpp
    src/syz/clone.cpp
    src/syz/transform.cpp
    src/syz/sanitize.cpp
    src/syz/minimize.cpp
    src/syz/type_methods.cpp
    src/syz/any.cpp
    src/syz/expr.cpp
    src/syz/state_altitude.cpp
    src/syz/linux/special_types.cpp
    src/syz/linux/special_types_time.cpp
    src/syz/linux/special_types_alg.cpp
    src/syz/linux/special_types_alg_tables.cpp
    src/syz/linux/special_types_netfilter.cpp
    src/syz/linux/special_types_usb.cpp
    # USB / HID ID database — regenerated from upstream
    # sys/linux/init_vusb_ids.go via `make syz_regen_usb`. Checked
    # into git; CI does not auto-emit.
    src/syz/linux/generated/usb_ids.gen.cpp
    ${REFUZZ_PROGRAM_V2_GENERATED}
)

# §3.10 — neutral ProgramArtifact + Seed::AssertV2Authoritative stub
# + codec counter storage.
# post-V1-retirement B-6: raw_bytes_artifact.cpp 提供 target-agnostic
# raw-bytes ProgramArtifact 的实现（multi-target enabler）。
set(REFUZZ_PROGRAM_NEUTRAL_SOURCES
    src/artifact.cpp
    src/artifact_materializer_dispatch.cpp
    src/raw_bytes_artifact.cpp
    src/seed_assert.cpp
    # [v2 batch 3 PR-W3] durable Seed.metadata JSON serde registry。
    src/seed_metadata_serde.cpp
    src/syz/pseudo_schema_def.cpp

    # XiUOS program-level types + PROGRAM payload encoder + RESULT payload
    # decoder + JSON seed loader. Belongs in refuzz_program because it is
    # in-memory program representation consumed downstream by refuzz_channel
    # and refuzz_feedback (XiuosCoverageSignal).
    src/xiuos/xiuos_program.cpp
    src/xiuos/xiuos_program_seed.cpp
    src/xiuos/xiuos_result.cpp
)

add_library(refuzz_program
    ${REFUZZ_PROGRAM_V2_SOURCES}
    ${REFUZZ_PROGRAM_NEUTRAL_SOURCES}
)

target_include_directories(refuzz_program
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        # [v2 batch 3 PR-W3] seed_metadata_serde.hpp 公开 API 暴露 nlohmann::json,
        # 需要 util/json.hpp 单头位于 repo root;消费者(corpus / tests / 其它 lib)
        # 通过 PUBLIC propagate 拿到此 include path,无需各自 add CMAKE_SOURCE_DIR。
        ${CMAKE_SOURCE_DIR}
)

# [chunk-based mount image] mount_image_segment.cpp (in REFUZZ_PROGRAM_V2_SOURCES)
# inflates syz_mount_image imgs host-side to pre-segment them (SEGS) so the guest
# skips the per-exec decompress. PUBLIC so binaries linking these libs get libz.
find_package(ZLIB REQUIRED)

# [dense mount image] zstd: host-side zlib→zstd transcode of DENSE mount images
# (mount_image_segment.cpp) — zstd fits the wire like zlib but the guest decompresses
# ~5-15× faster. No -dev package on this host, so fall back to the runtime soname
# (present on host AND in the guest rootfs). PUBLIC so linking binaries pick it up.
find_library(REFUZZ_ZSTD_LIB NAMES zstd libzstd.so.1
             PATHS /usr/lib/x86_64-linux-gnu /lib/x86_64-linux-gnu)
if(NOT REFUZZ_ZSTD_LIB)
    set(REFUZZ_ZSTD_LIB /lib/x86_64-linux-gnu/libzstd.so.1)
endif()

target_link_libraries(refuzz_program
    PUBLIC
        refuzz_core
        refuzz_logging
        refuzz_proto_wire
        ZLIB::ZLIB
        ${REFUZZ_ZSTD_LIB}
)

# v2-only target for fast iteration (no v1 deps, lighter test cycle).
add_library(refuzz_program_syz_v2
    ${REFUZZ_PROGRAM_V2_SOURCES}
    ${REFUZZ_PROGRAM_NEUTRAL_SOURCES}
)
target_include_directories(refuzz_program_syz_v2
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        # [v2 batch 3 PR-W3] mirror refuzz_program: 公开 util/ 给 nlohmann::json。
        ${CMAKE_SOURCE_DIR}
)
target_link_libraries(refuzz_program_syz_v2
    PUBLIC
        refuzz_core
        refuzz_logging
        refuzz_proto_wire
        ZLIB::ZLIB
        ${REFUZZ_ZSTD_LIB}
)

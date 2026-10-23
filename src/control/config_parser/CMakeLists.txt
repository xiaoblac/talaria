cmake_minimum_required(VERSION 3.15)
project(refuzz_config_parser CXX)

# P6.0: 从 refuzz_control 拆出的 JSON 解析层。打破
# refuzz_control -> refuzz_profile -> refuzz_startup -> (欲链) refuzz_control 循环:
# refuzz_control 和 refuzz_startup 都依赖本库,本库不依赖任何 control 子模块。
add_library(refuzz_config_parser STATIC
    src/orchestrator_config.cpp
    src/session_layout.cpp
)

# 头仍位于 ../orchestrator/include(与旧布局兼容),也要让
# 下游通过本库间接拿到 include 路径。
target_include_directories(refuzz_config_parser PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../orchestrator/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(refuzz_config_parser PUBLIC
    refuzz_channel           # ChannelConfig / QemuIvshmemLinuxProfile / channel_backend_id
    refuzz_channeldispatcher # ExecutorConfig
    refuzz_telemetry         # PolicyEngineConfig / ObservabilityConfig
    refuzz_crash             # ReproConfig
    refuzz_core              # Result/ComponentError (未来)
    refuzz_program
    refuzz_mutator
    refuzz_feedback
    refuzz_corpus
    refuzz_queue
    refuzz_proto_domain
    refuzz_proto_wire
)

target_link_libraries(refuzz_config_parser PRIVATE
    refuzz_logging           # HostLineBuilder
)

# ParseConfig 里用到了 FuzzerLoopConfig(通过 orchestrator_config.hpp)
target_include_directories(refuzz_config_parser PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../include      # fuzzer_loop.hpp
)

# util/json.hpp — parse_config_from_json.hpp 对外包含,需 PUBLIC
target_include_directories(refuzz_config_parser PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../..
)

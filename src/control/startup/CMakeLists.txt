cmake_minimum_required(VERSION 3.15)
project(refuzz_startup CXX)

# P6: 从 INTERFACE 升级为 STATIC。承载 JSON/CLI -> LaunchPlan 的前端实现。
add_library(refuzz_startup STATIC
    src/json_frontend.cpp
    src/cli_frontend.cpp
)

target_include_directories(refuzz_startup PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# 依赖关系:
#   - refuzz_config_parser: 拿 ParseConfigFromJson + OrchestratorConfig 头 + ChannelConfig 等
#   - refuzz_feedback: LaunchPlan/ParseResult 含 FeedbackEngineSpec
#   - refuzz_core: Result/ComponentError
# 不 link refuzz_control——那会再形成循环。
target_link_libraries(refuzz_startup PUBLIC
    refuzz_config_parser
    refuzz_feedback
    refuzz_core
)

target_link_libraries(refuzz_startup PRIVATE
    refuzz_logging
)

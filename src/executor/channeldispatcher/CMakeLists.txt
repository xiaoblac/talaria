cmake_minimum_required(VERSION 3.15)
project(refuzz_channeldispatcher CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -Werror)

add_library(refuzz_channeldispatcher
    src/executor/channeldispatcher.cpp
)

target_include_directories(refuzz_channeldispatcher
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/include/refuzz/executor
        ${CMAKE_CURRENT_SOURCE_DIR}/../../core/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../../proto/domain/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../../proto/wire/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../../queue/include
        # refuzz_channel 的 public include dirs 通过 target_link_libraries 传递；
        # v3.5 Phase A 目录重排后，不再硬编码 channel 子目录路径。
)

target_link_libraries(refuzz_channeldispatcher
    PUBLIC
        refuzz_core
        refuzz_channel
        refuzz_logging
        refuzz_proto_domain
        refuzz_proto_wire
        refuzz_queue
)

cmake_minimum_required(VERSION 3.15)
project(refuzz_queue CXX)

add_library(refuzz_queue
    src/crash_queue.cpp
    src/event_queue.cpp
    src/lifecycle_queue.cpp
    src/result_queue.cpp
    src/task_queue.cpp
)

target_include_directories(refuzz_queue
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../proto/domain/include
        # refuzz_channel 的 public include dirs 通过 target_link_libraries 传递；
        # v3.5 Phase A 目录重排后，不再硬编码 channel 子目录路径。
)

target_link_libraries(refuzz_queue
    PUBLIC
        refuzz_channel
        refuzz_proto_domain
        refuzz_program   # §3.10 step 5 — HostFuzzTask carries ProgramArtifact
)

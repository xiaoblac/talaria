cmake_minimum_required(VERSION 3.15)
project(refuzz_orchestrator CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
add_compile_options(-Wall -Wextra -Werror)

add_library(refuzz_orchestrator INTERFACE)

target_include_directories(refuzz_orchestrator
    INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(refuzz_orchestrator
    INTERFACE
        refuzz_control
)

# refuzz 正式入口
add_executable(refuzz
    ${CMAKE_CURRENT_SOURCE_DIR}/../../tools/refuzz_main.cpp
)

target_link_libraries(refuzz
    PRIVATE
        refuzz_orchestrator
        refuzz_assembler
        refuzz_startup
        pthread
)

# P3 起:REGISTER_PROFILE 宏已下线,改用 profile::RegisterBuiltinProfiles(registry)
# 在 Orchestrator::Build() 里显式注册——不再需要 --whole-archive 保留静态构造。
# refuzz_control -> refuzz_profile 的 PUBLIC 链接(见 control/CMakeLists.txt)
# 已经把 MakeKernelProfile/RegisterBuiltinProfiles 符号传递到这里。

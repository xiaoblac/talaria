cmake_minimum_required(VERSION 3.15)
project(refuzz_assembler CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
add_compile_options(-Wall -Wextra -Werror)

add_library(refuzz_assembler STATIC
    src/assembler.cpp
)

target_include_directories(refuzz_assembler PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Assembler 吃 ResolvedPlan + CatalogSet,构造三个 Manager + Store + Toolkit
# + Channel。需要看到 resolver/startup/orchestrator 头 + 所有 9 个领域的头。
# refuzz_orchestrator 是 INTERFACE,拿头不产生 link 循环(SessionLayout::vm_dir
# 已 inline 化,不再拖出 refuzz_control)。
target_link_libraries(refuzz_assembler PUBLIC
    refuzz_resolver
    refuzz_startup
    refuzz_profile
    refuzz_support
    refuzz_orchestrator
    refuzz_mutator
    refuzz_corpus
    refuzz_feedback
    refuzz_crash
    refuzz_channel
    refuzz_core
)

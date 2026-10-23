cmake_minimum_required(VERSION 3.15)
project(refuzz_support CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
add_compile_options(-Wall -Wextra -Werror)

# [syscall-support-detection] Host-side syscall support detection — the
# orchestration step (syzkaller pkg/vminfo analog). Decides which syscalls the
# current environment can run, and resolves whitelist ∩ supported.
add_library(refuzz_support STATIC
    src/support_checker.cpp
    src/support_check.cpp
)

target_include_directories(refuzz_support PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Needs the program/syz Target schema + compute_enabled_calls (whitelist).
target_link_libraries(refuzz_support PUBLIC
    refuzz_program
)

# [machine-check C4] Execution-based support detection (trial-exec probe builder
# + runner). A sub-component of support detection — the "brain" decides which
# probe programs to run and interprets the errnos — so it nests here under
# support, not as a sibling. See docs/plans/machine-check.md.
add_subdirectory(machine_check)

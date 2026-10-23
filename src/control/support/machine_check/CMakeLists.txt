cmake_minimum_required(VERSION 3.15)
project(refuzz_machine_check CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
add_compile_options(-Wall -Wextra -Werror)

# [machine-check C4] Host-side execution-based syscall support detection
# (syzkaller pkg/vminfo analog): trial-execute probe programs in the VM and
# disable syscalls on ENOSYS. See docs/plans/machine-check.md.
#
#   probe_program — C4.2a: build one default-arg call per syscall (the typed
#                   probe Prog) + lower to exec-wire bytes.
#   probe_runner  — C4.2b: wrap a probe program in the STANDARD data-plane
#                   carrier (HostFuzzTask, artifact-first) + decode per-call
#                   errno from a completion's output buffer.
#   machine_check — C4.6: the phase driver — EnvFeatures→SupportEnv, push probe
#                   tasks → drain completions (standard data plane) → resolve the
#                   final enabled set. The control/ loop calls it post-boot.
add_library(refuzz_machine_check STATIC
    src/probe_program.cpp
    src/probe_runner.cpp
    src/machine_check.cpp
)

target_include_directories(refuzz_machine_check
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        # probe_runner.cpp pulls feedback's decode header, which includes
        # worker/backend/syz_exec_runner.hpp (SyzExecResult, kCallFlag*).
        ${CMAKE_SOURCE_DIR}/executor/channel/worker/include
)

target_link_libraries(refuzz_machine_check
    PUBLIC
        # program/syz: Prog/Call construction, Type::default_arg, assign_sizes,
        # serialize_for_exec, MakeArtifactFromTypedProg.
        refuzz_program
        # HostFuzzTask carrier + InMemory{Task,Event}Queue (public headers).
        refuzz_queue
        # SupportEnv / TrialResults / resolve_enabled_calls / pseudo_syscall_deps.
        refuzz_support
        # EnvFeatures wire contract (public in machine_check.hpp).
        refuzz_proto_wire
    PRIVATE
        # DecodeSyzExecResults (per-call errno head decode).
        refuzz_feedback
        # channel_contract Completion/AbnormalCompletion (event decode).
        refuzz_core
)

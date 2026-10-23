cmake_minimum_required(VERSION 3.15)
project(refuzz_mutator CXX)

add_library(refuzz_mutator
    src/mutator_manager.cpp
    src/mutator_catalog.cpp
    # [§3.4] v2 generator (mirror prog/rand.go + analysis.go state).
    src/linux/syz_v2/random.cpp
    src/linux/syz_v2/gen_state.cpp
    src/linux/syz_v2/generator.cpp
    src/linux/syz_v2/engines/syz_v2_engine.cpp
    # [§3.5 M0] v2 mutation op/policy plumbing (M1/M2/M3 fill bodies).
    src/linux/syz_v2/ops/syz_v2_mutate_ops.cpp
    src/linux/syz_v2/ops/syz_v2_op_wrappers.cpp
    src/linux/syz_v2/policies/syz_v2_mutation_policies.cpp
    # [§3.5 M1] mutateArg dispatch + per-type mutators.
    src/linux/syz_v2/ops/mutate_arg.cpp
    # [§3.5 M2] sequence-level mutation ops.
    src/linux/syz_v2/ops/splice.cpp
    src/linux/syz_v2/ops/insert_call.cpp
    src/linux/syz_v2/ops/remove_call.cpp
    # [§3.5 M3] squash_any op.
    src/linux/syz_v2/ops/squash_any.cpp
    # [§3.6 M0] ChoiceTable (prog/prio.go port).
    src/linux/syz_v2/choice_table.cpp
    # Concrete Target::IGen impl for SpecialType bodies.
    src/linux/syz_v2/special_gen.cpp
    # [Epic 5 PR-5-C] hints algorithm port (prog/hints.go).
    src/linux/syz_v2/hints/comp_map.cpp
    src/linux/syz_v2/hints/hints_apply.cpp
    src/linux/syz_v2/hints/hints_limiter.cpp
    src/linux/syz_v2/hints/special_ints_set.cpp
    src/linux/syz_v2/hints/image_zlib.cpp
    # [Epic 6 PR-6-B] fault-inject algorithm helper (mirror
    # pkg/fuzzer/job.go:506-509 — clone + per-call FailNth set).
    src/linux/syz_v2/fault_inject/fault_inject_variant.cpp
    # [collide 变换层] AssignRandomAsync (mirror prog/collide.go:24-60) —
    # 给 gen/mut 产出的新程序打 async 触发 race。
    src/linux/syz_v2/collide/assign_async.cpp

    # Phase 2 §C #20 — XiUOS structured kernel mutator v1
    # (insert/delete/replace/mutate_arg + lifecycle-aware FSM mirroring
    # tools/xiuos_refuzz/descriptors/common_kernel_sem_mutex.json).
    src/xiuos/xiuos_mutator_engine.cpp
)

target_include_directories(refuzz_mutator
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(refuzz_mutator
    PUBLIC
        refuzz_program
        refuzz_core
        refuzz_feedback
    PRIVATE
        # [Epic 5 PR-5-C] zlib for hints/image_zlib.cpp (mirrors upstream
        # pkg/image/image.go Compress/MustDecompress used by checkCompressedArg).
        z
)

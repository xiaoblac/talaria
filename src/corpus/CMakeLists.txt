cmake_minimum_required(VERSION 3.15)
project(refuzz_corpus CXX)

add_library(refuzz_corpus
    src/corpus/in_memory_corpus.cpp
    src/corpus/corpus_manager.cpp
    src/corpus/content_hash_dedup_filter.cpp
    src/corpus/corpus_disk_io.cpp
    src/corpus/corpus_verify.cpp
    src/corpus/corpus_store_catalog.cpp
    src/scheduler/policy/priority_policy.cpp
    src/scheduler/policy/round_robin_policy.cpp
    src/scheduler/policy/uniform_policy.cpp
    src/scheduler/policy/size_weighted_policy.cpp
    src/scheduler/policy/rarity_weighted_policy.cpp
    src/scheduler/policy/mab_exp3ix_policy.cpp  # [mab Step 2] seed-selection MAB (Exp3-IX)
    src/scheduler/engine/priority_scheduler_engine.cpp
    src/scheduler/manager/scheduler_manager.cpp
    src/scheduler/scheduler_catalog.cpp
    # [seed-future-value] de-flattened resource-precondition horizon scoring core
    # (Target-agnostic core + the one Target-aware BuildFromTarget adapter).
    src/scheduler/horizon/seed_horizon_model.cpp
    src/scheduler/horizon/seed_horizon_build.cpp
    # the live component: model + novelty mask + on-admit future(seed) scoring.
    src/scheduler/horizon/seed_horizon.cpp
    # [future_band2] band-② code-mass kill-shot signal (shadow-only candidate).
    src/scheduler/horizon/seed_band2.cpp
    # [belief-graph] in-engine read-out of the static 8-mechanism belief prior (graph_M.tsv).
    src/scheduler/horizon/static_belief_graph.cpp
)

target_include_directories(refuzz_corpus
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_SOURCE_DIR}
)

target_link_libraries(refuzz_corpus
    PUBLIC
        refuzz_program
        refuzz_feedback
        refuzz_core
        refuzz_logging
)

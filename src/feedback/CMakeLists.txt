cmake_minimum_required(VERSION 3.15)
project(refuzz_feedback CXX)

add_library(refuzz_feedback
    src/coverage_semantics.cpp
    src/feedback_codec.cpp
    src/feedback_manager.cpp
    src/hash_feedback_store.cpp
    # [seed-future-value §5.1] per-base-seed lineage downstream-yield oracle
    # accumulator (value-realized seed-yield, depth-bucketed). Pure accumulation;
    # FuzzerLoop owns the lineage walk that feeds it.
    src/lineage/seed_lineage_yield_store.cpp
    # [variant-handler-binding 2026-06-18] live per_call variant->handler map
    # (binding entry side of the structural-horizon region). Pure accumulation;
    # FuzzerLoop feeds it from ProcessEventFeedback.
    src/binding/variant_handler_map.cpp

    src/signal/exec_result_signal.cpp
    src/signal/fault_signal.cpp
    src/signal/kcov_coverage_signal.cpp
    src/signal/kcov_cmp_signal.cpp
    src/signal/feedback_signal_catalog.cpp
    # Phase 2 §C #16 — XiUOS UART backend coverage signal (AFL log2 bucketize
    # + 256B global bitmap OR; see 050_corpus_generation_method.md §Stage 6).
    src/signal/xiuos_coverage_signal.cpp
    # [State coverage] second coverage dimension — joint-hash the worker's peak
    # live-object-count features (RESULT v2 state region) to escape PC saturation.
    src/signal/xiuos_state_coverage_signal.cpp
    # [State coverage §8.1] call-graph edge coverage over the program API sequence
    # (new prev->cur bigram) — ordering dimension, host-side, no worker change.
    src/signal/xiuos_call_transition_signal.cpp
    # per-program invariant oracle (heap/state corruption + leak) as a feedback
    # signal — turns the worker's per-call/per-program verdicts (Completion
    # vendor_status / vendor_flags) into the normal crash_payload finding path.
    src/signal/xiuos_oracle_signal.cpp

    # [v2 Epic 6 PR-6-A D-8 — host-side per-call flag decoder]
    src/decode/syz_exec_result_decode.cpp

    src/aggregator/coverage_guided_aggregator.cpp
    src/aggregator/blackbox_aggregator.cpp
    src/aggregator/weighted_or_aggregator.cpp
    src/aggregator/feedback_aggregator_catalog.cpp

    # [v2 SubT-A] Framework primitive: signal stability oracle.
    src/stability/signal_set_intersection_oracle.cpp
    # k-of-n 投票式 stability oracle(对齐 syzkaller deflake 2/6 容错)。
    src/stability/signal_voting_stability_oracle.cpp

    # [v2 SubT-B] Framework primitive: candidate retry policy.
    src/retry/syzkaller_retry_policy.cpp

    # [v2 batch 3 PR-Y] Framework primitive: priority calculator.
    src/priority/syzkaller_priority_calculator.cpp

    # [v2 batch 3 G5] Framework primitive: signal-time saturation filter.
    src/saturation/kernel_coverage_saturation_filter.cpp

    # [verdict 重构] dispatcher 子系统已删除 — admit/notify/metrics actuation 归
    # control loop;准入决策 + Seed 构造归 corpus(CorpusManager::OfferVerdict)。

    src/engine/composite_feedback_engine.cpp
    src/engine/feedback_engine_catalog.cpp

    # Phase 2 §C #18 — XiUOS-only crash record + bucket layer (consumes
    # AbnormalCompletion from the XiUOS UART data plane).
    src/bucket/xiuos_crash_bucket.cpp
)

target_include_directories(refuzz_feedback
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        # [v2 Epic 6 PR-6-A — DecodeSyzExecResults uses worker SyzExecResult
        #  POD layout from worker/backend/syz_exec_runner.hpp; PUBLIC so
        #  consumers (PR-6-C FaultInjectionConsumerStage) get it transitively.]
        ${CMAKE_CURRENT_SOURCE_DIR}/../executor/channel/worker/include
)

target_link_libraries(refuzz_feedback
    PUBLIC
        refuzz_program
        refuzz_channel
        refuzz_proto_domain
        refuzz_proto_wire
        refuzz_core
        # [v2 batch 3 PR-Y B1] HashFeedbackStore::LoadFromFile v1 legacy migration
        # 路径调 HostLineBuilder 提示用户 schema 迁移。refuzz_logging 是 leaf dep
        # (无任何下游 reFuzz lib),加进 feedback PUBLIC 不引发 circular。
        refuzz_logging
)

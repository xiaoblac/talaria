cmake_minimum_required(VERSION 3.15)
project(refuzz_telemetry CXX)

add_library(refuzz_telemetry
    src/policy/policy_engine.cpp
    src/policy/policy_monitor.cpp
    # [v1 — DELETED in PR-K-0, see docs/plans/kcov-coverage-curve.md §4.1]
    # ROLLBACK: uncomment the next line.
    # src/coverage/coverage_tracker.cpp
    # [v2 PR-K-A — coverage_series substrate, see plan §5.1]
    src/observation/coverage_series.cpp
    src/observation/coverage_metrics_sink.cpp
    src/observation/fuzzer_stats_sink.cpp
    src/observation/periodic_sample_gate.cpp
    src/observation/run_state_store.cpp
    # [v2 G5 follow-up-2] RateWindowTracker — LibAFL afl_exec_sec equiv
    src/observation/rate_window_tracker.cpp
    src/observation/observability_projector.cpp
    src/observation/run_state_renderer.cpp
    src/observation/terminal_dashboard.cpp
    src/observation/run_summary.cpp
    src/observation/run_summary_computer.cpp
    src/observation/run_summary_json_sink.cpp
)

target_include_directories(refuzz_telemetry
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(refuzz_telemetry
    PUBLIC
        refuzz_core
        refuzz_crash
        refuzz_channeldispatcher
        refuzz_channel
        refuzz_queue
)

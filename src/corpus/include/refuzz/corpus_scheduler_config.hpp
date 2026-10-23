#pragma once

#include <cstddef>
#include <string>

namespace refuzz::fuzzer {

/// Defaults and tunables shared by corpus ingestion (CorpusManager) and seed
/// scheduling (SchedulerManager). Policy strings must match registered names.
struct CorpusSchedulerConfig {
    struct Corpus {
        size_t capacity = 10000;
        /// Max inbox seeds drained per CorpusManager::Tick.
        int max_drain = 32;
        /// Admission policy name, e.g. "all_filters", "no_filter".
        std::string admission_policy = "all_filters";
        /// Optional on-disk corpus root; empty means no loop-level persistence.
        std::string persist_dir;
    } corpus;

    struct Scheduler {
        /// Scheduling policy name, e.g. "round_robin", "priority".
        std::string policy = "round_robin";
    } scheduler;
};

} // namespace refuzz::fuzzer

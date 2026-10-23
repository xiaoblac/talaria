#include "refuzz/core/concepts.hpp"
#include "refuzz/corpus/corpus_store.hpp"
#include "refuzz/scheduler/engine/priority_scheduler_engine.hpp"
#include "refuzz/program/seed.hpp"

static_assert(refuzz::core::CorpusLike<refuzz::fuzzer::InMemoryCorpusStore, refuzz::fuzzer::Seed>);
static_assert(refuzz::core::SchedulerLike<refuzz::fuzzer::PrioritySchedulerEngine>);

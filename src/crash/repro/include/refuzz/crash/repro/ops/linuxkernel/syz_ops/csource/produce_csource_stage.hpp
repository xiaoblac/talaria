// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Epic 4 PR-4-D — StageProduceCSource entry point.
//
// Free function deliberately, not a member of ReproManager:
// StageProduceCSource consumes only `ReproResult` and `ReproConfig` —
// it does not need engine_ / exec_ops_ / observed_titles_ / etc., so
// keeping it out of the manager class keeps the manager's surface
// focused on stages that drive the executor.
//
// The function emits the .c source via csource::Write on
// `result.selected_artifact->As<program::syz::Prog>()`, optionally
// invokes csource::Build per `cfg.try_compile_c_reproducer`, and
// updates `result.c_reproducer_source` /
// `result.c_reproducer_build_err` /
// `result.last_completed_stage` /
// `result.completion_reason` per the failure matrix in Epic 4 plan §3
// "ReproManager wiring (binding)".

#pragma once

#include <functional>
#include <string>

namespace refuzz::crash {
struct ReproConfig;
struct ReproResult;
} // namespace refuzz::crash

namespace refuzz::crash::repro::syz_ops::csource {

// Test-only hook: called between csource::Write and csource::Build,
// allowing a unit test to mutate the freshly-emitted source so that
// `csource::Build` is guaranteed to fail (e.g., prepend `#error`).
// Production callers leave this empty; the live path is bypassed.
using TestOnlySourceTransform = std::function<std::string(std::string)>;

// Stage entry point. Returns true on success (also when nothing was
// produced because cfg.produce_c_reproducer is false — the BuildPlan
// gate keeps that path unreachable). Returns false on hard failure
// with `result.completion` / `result.completion_reason` set per the
// matrix:
//   selected_artifact null / wrong type
//                                → kCReproNoMinimizedArtifact
//   csource::Write kUnsupportedByEpic4
//                                → kCReproUnsupportedByEpic4
//   csource::Write other errors  → kCReproWriteFailed
//   csource::Build failure (with try_compile_c_reproducer)
//                                → kCReproBuildFailed
//                                  (.source preserved when
//                                   keep_c_source_on_build_failure)
bool ProduceCSourceStage(::refuzz::crash::ReproResult& result,
                         const ::refuzz::crash::ReproConfig& cfg,
                         const TestOnlySourceTransform& test_only_xform = {});

} // namespace refuzz::crash::repro::syz_ops::csource

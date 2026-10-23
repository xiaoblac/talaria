// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Epic 4 PR-4-D — StageProduceCSource body.
//
// Reads `result.selected_artifact->As<program::syz::Prog>()` and
// drives csource::Write + (optional) csource::Build. Failure
// matrix is documented on the header; this file is the only
// production caller of csource::Build outside the csource module
// itself.

#include "refuzz/crash/repro/ops/linuxkernel/syz_ops/csource/produce_csource_stage.hpp"

#include "refuzz/crash/repro/core/repro_config.hpp"
#include "refuzz/crash/repro/core/repro_types.hpp"
#include "refuzz/crash/repro/csource/annotator.hpp"
#include "refuzz/crash/repro/csource/build.hpp"
#include "refuzz/crash/repro/csource/csource.hpp"
#include "refuzz/crash/repro/csource/options.hpp"
#include "refuzz/crash/repro/csource/target_info.hpp"
#include "refuzz/program/artifact.hpp"
#include "refuzz/program/syz/prog.hpp"

#include <filesystem>
#include <string>
#include <system_error>
#include <utility>

namespace refuzz::crash::repro::syz_ops::csource {

namespace cs  = ::refuzz::crash::repro::csource;
namespace syz = ::refuzz::program::syz;

namespace {

cs::Options BaselineOptions() {
    // Mirror Epic 4 plan §5.3 "default" baseline opts: sandbox=none,
    // single proc, segv handler on, typed call comments on. These are
    // the values the operator-driven repro path uses in production.
    cs::Options opts;
    opts.Sandbox      = "none";
    opts.Threaded     = false;
    opts.Repeat       = false;
    opts.Procs        = 1;
    opts.UseTmpDir    = false;
    opts.HandleSegv   = true;
    opts.CallComments = true;
    return opts;
}

void CleanupBuildArtifacts(const std::string& bin_path) {
    if (bin_path.empty()) return;
    std::error_code ec;
    std::filesystem::remove(bin_path, ec);
    std::filesystem::path bin(bin_path);
    if (bin.parent_path().filename().string().rfind(
            "refuzz-csource-", 0) == 0) {
        std::filesystem::remove_all(bin.parent_path(), ec);
    }
}

void SetWriteFailure(::refuzz::crash::ReproResult& result,
                     cs::CSourceError code) {
    using ::refuzz::crash::ReproCompletionReason;
    using ::refuzz::crash::ReproCompletionStatus;
    result.completion = ReproCompletionStatus::kFailed;
    result.completion_reason =
        (code == cs::CSourceError::kUnsupportedByEpic4)
            ? ReproCompletionReason::kCReproUnsupportedByEpic4
            : ReproCompletionReason::kCReproWriteFailed;
    result.c_reproducer_source.clear();
}

} // namespace

bool ProduceCSourceStage(::refuzz::crash::ReproResult& result,
                         const ::refuzz::crash::ReproConfig& cfg,
                         const TestOnlySourceTransform& test_only_xform) {
    using ::refuzz::crash::ReproCompletionReason;
    using ::refuzz::crash::ReproCompletionStatus;
    using ::refuzz::crash::ReproStage;

    if (result.selected_artifact == nullptr ||
        !result.selected_artifact->valid()) {
        result.completion = ReproCompletionStatus::kFailed;
        result.completion_reason =
            ReproCompletionReason::kCReproNoMinimizedArtifact;
        return false;
    }

    auto prog_view = result.selected_artifact->As<syz::Prog>();
    if (prog_view == nullptr) {
        result.completion = ReproCompletionStatus::kFailed;
        result.completion_reason =
            ReproCompletionReason::kCReproNoMinimizedArtifact;
        return false;
    }

    auto opts = BaselineOptions();
    auto wr = cs::Write(*prog_view, opts,
                        cs::linux_amd64_annotator(),
                        cs::linux_amd64_target_info());
    if (!wr.has_value()) {
        SetWriteFailure(result, wr.error().code);
        return false;
    }

    std::string source = std::move(*wr);
    if (test_only_xform) {
        source = test_only_xform(std::move(source));
    }
    result.c_reproducer_source = source;

    if (cfg.try_compile_c_reproducer) {
        cs::BuildOptions bopts;
        bopts.timeout_seconds = 60;
        auto br = cs::Build(source, bopts, cs::linux_amd64_target_info());
        if (!br.has_value()) {
            result.c_reproducer_build_err = br.error();
            if (!cfg.keep_c_source_on_build_failure) {
                result.c_reproducer_source.clear();
            }
            result.completion        = ReproCompletionStatus::kFailed;
            result.completion_reason =
                ReproCompletionReason::kCReproBuildFailed;
            return false;
        }
        // Keep `c_reproducer_source` populated; binary itself is a
        // build-time witness, not part of the artifact-first contract.
        CleanupBuildArtifacts(br->binary_path);
    }

    result.last_completed_stage = ReproStage::kProduceCSource;
    return true;
}

} // namespace refuzz::crash::repro::syz_ops::csource

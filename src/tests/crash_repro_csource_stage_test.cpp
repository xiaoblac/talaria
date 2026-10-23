// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Epic 4 PR-4-D — full StageProduceCSource fail-closed matrix.
//
// Five cases, all without an operator VM (per plan §6.1):
//   (a) produce_c_reproducer=true but selected_artifact==null
//       → kCReproNoMinimizedArtifact, no .c emitted.
//   (b) baseline prog (getpid, sandbox=none) → success;
//       result.c_reproducer_source non-empty.
//   (c) non-baseline prog (CallProps.fail_nth=5)
//       → kCReproUnsupportedByEpic4, no .c emitted.
//   (d) try_compile_c_reproducer=true and a malformed source via
//       TestOnlySourceTransform that prepends #error
//       → kCReproBuildFailed, .source preserved when
//       keep_c_source_on_build_failure=true.
//   (e) PR-4-A regression: BuildPlan does NOT append kProduceCSource
//       when cfg.produce_c_reproducer=false; flips to true append it
//       at the tail post-Reliability/Symbolize.

#include "refuzz/crash/repro/core/exec_adapter.hpp"
#include "refuzz/crash/repro/core/repro_config.hpp"
#include "refuzz/crash/repro/core/repro_types.hpp"
#include "refuzz/crash/repro/manager/repro_manager.hpp"
#include "refuzz/crash/repro/ops/linuxkernel/syz_ops/csource/produce_csource_stage.hpp"
#include "refuzz/program/artifact.hpp"
#include "refuzz/program/prog_format.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <typeinfo>
#include <utility>
#include <vector>

namespace {

namespace pr  = ::refuzz::program;
namespace syz = ::refuzz::program::syz;
namespace cs_stage = ::refuzz::crash::repro::syz_ops::csource;
using ::refuzz::crash::ReproCompletionReason;
using ::refuzz::crash::ReproCompletionStatus;
using ::refuzz::crash::ReproConfig;
using ::refuzz::crash::ReproManager;
using ::refuzz::crash::ReproResult;
using ::refuzz::crash::ReproStage;
using ::refuzz::crash::ReproStageOp;

#define CHECK(expr)                                                         \
    do {                                                                    \
        if (!(expr)) {                                                      \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,    \
                         #expr);                                            \
            std::abort();                                                   \
        }                                                                   \
    } while (0)

#define RUN_TEST(fn)                                                        \
    do {                                                                    \
        std::fprintf(stderr, "RUN  %s\n", #fn);                             \
        fn();                                                               \
        std::fprintf(stderr, "OK   %s\n", #fn);                             \
    } while (0)

// ----- helpers -----

pr::ProgramTargetKey LinuxAmd64Key() {
    const auto& t = syz::Target::linux_amd64();
    return {std::string(t.os()), std::string(t.arch()), std::string(t.revision())};
}

std::unique_ptr<syz::Call>
DefaultCall(const syz::Target& t, const std::string& name) {
    const auto* meta = t.find_syscall(name);
    if (meta == nullptr) {
        std::fprintf(stderr, "schema lacks %s\n", name.c_str());
        std::abort();
    }
    auto call = std::make_unique<syz::Call>();
    call->set_meta(meta);
    for (const auto& f : meta->args()) {
        if (f.type() == nullptr) continue;
        call->add_arg(f.type()->default_arg(f.dir(syz::Dir::kIn)));
    }
    return call;
}

std::shared_ptr<const pr::ProgramArtifact>
ArtifactFromProg(std::unique_ptr<syz::Prog> prog) {
    auto typed_mut = std::shared_ptr<syz::Prog>(std::move(prog));
    std::shared_ptr<const syz::Prog> typed = typed_mut;
    auto canonical = std::make_shared<const std::vector<std::uint8_t>>(
        std::vector<std::uint8_t>{'\n'});
    auto art = pr::ProgramArtifact::Build(
        ::refuzz::fuzzer::ProgFormat::kSyzProg,
        LinuxAmd64Key(),
        std::static_pointer_cast<const void>(typed),
        typeid(syz::Prog),
        canonical,
        {});
    return std::make_shared<const pr::ProgramArtifact>(std::move(art));
}

std::shared_ptr<const pr::ProgramArtifact> BaselineArtifact() {
    const auto& t = syz::Target::linux_amd64();
    auto p = std::make_unique<syz::Prog>();
    p->set_target(&t);
    p->add_call(DefaultCall(t, "getpid"));
    return ArtifactFromProg(std::move(p));
}

std::shared_ptr<const pr::ProgramArtifact> FailNthArtifact() {
    const auto& t = syz::Target::linux_amd64();
    auto p = std::make_unique<syz::Prog>();
    p->set_target(&t);
    auto c = DefaultCall(t, "getpid");
    syz::CallProps props;
    props.fail_nth = 5;
    c->set_props(props);
    p->add_call(std::move(c));
    return ArtifactFromProg(std::move(p));
}

// ----- minimal IExecAdapter stub for case (e) — BuildPlanForCurrentConfig
//       reads only policy_idx_ + cfg_ on the manager, never touches the
//       adapter. Engine pointer is nullptr; CurrentEngine() returns null
//       which would short-circuit Run(), but we never call Run() here.
class NullExecAdapter : public ::refuzz::crash::IExecAdapter {
public:
    bool EnsureReady() override { return true; }
    ::refuzz::crash::RunResult Execute(const std::vector<std::uint8_t>&,
                                       std::uint64_t) override {
        return {};
    }
    bool RestartBetweenRuns() override { return true; }
    void RequestStop() override {}
};

// ----- cases -----

void test_a_artifact_null_yields_no_minimized_artifact_reason() {
    ReproResult result;
    result.selected_artifact = nullptr;
    ReproConfig cfg;
    cfg.produce_c_reproducer = true;

    bool ok = cs_stage::ProduceCSourceStage(result, cfg);
    CHECK(!ok);
    CHECK(result.completion == ReproCompletionStatus::kFailed);
    CHECK(result.completion_reason ==
          ReproCompletionReason::kCReproNoMinimizedArtifact);
    CHECK(result.c_reproducer_source.empty());
    CHECK(result.last_completed_stage != ReproStage::kProduceCSource);
}

void test_b_baseline_prog_emits_csource_source() {
    ReproResult result;
    result.selected_artifact = BaselineArtifact();
    ReproConfig cfg;
    cfg.produce_c_reproducer       = true;
    cfg.try_compile_c_reproducer   = false;   // emit only

    bool ok = cs_stage::ProduceCSourceStage(result, cfg);
    if (!ok) {
        std::fprintf(stderr,
                     "  unexpected stage failure: completion_reason=%d\n",
                     int(result.completion_reason));
    }
    CHECK(ok);
    CHECK(!result.c_reproducer_source.empty());
    CHECK(result.c_reproducer_source.find("// autogenerated by reFuzz csource")
          != std::string::npos);
    CHECK(result.c_reproducer_source.find("syscall(__NR_getpid")
          != std::string::npos);
    CHECK(result.last_completed_stage == ReproStage::kProduceCSource);
    CHECK(result.c_reproducer_build_err.empty());
}

void test_c_non_baseline_failnth_yields_unsupported_reason() {
    ReproResult result;
    result.selected_artifact = FailNthArtifact();
    ReproConfig cfg;
    cfg.produce_c_reproducer = true;

    bool ok = cs_stage::ProduceCSourceStage(result, cfg);
    CHECK(!ok);
    CHECK(result.completion == ReproCompletionStatus::kFailed);
    CHECK(result.completion_reason ==
          ReproCompletionReason::kCReproUnsupportedByEpic4);
    CHECK(result.c_reproducer_source.empty());
    CHECK(result.last_completed_stage != ReproStage::kProduceCSource);
}

void test_d_build_failure_keeps_source_when_flag_on() {
    ReproResult result;
    result.selected_artifact = BaselineArtifact();
    ReproConfig cfg;
    cfg.produce_c_reproducer            = true;
    cfg.try_compile_c_reproducer        = true;
    cfg.keep_c_source_on_build_failure  = true;

    auto force_failure = [](std::string src) {
        // Prepend a #error directive so gcc fails BEFORE syntactic
        // parsing of the rest of the source, deterministic regardless
        // of the ambient toolchain.
        return std::string("#error refuzz-stage-test-force-build-failure\n") + src;
    };

    bool ok = cs_stage::ProduceCSourceStage(result, cfg, force_failure);
    CHECK(!ok);
    CHECK(result.completion == ReproCompletionStatus::kFailed);
    CHECK(result.completion_reason ==
          ReproCompletionReason::kCReproBuildFailed);
    // .source is preserved when keep_c_source_on_build_failure=true.
    CHECK(!result.c_reproducer_source.empty());
    CHECK(result.c_reproducer_source.find(
              "#error refuzz-stage-test-force-build-failure")
          != std::string::npos);
    CHECK(!result.c_reproducer_build_err.empty());
    CHECK(result.last_completed_stage != ReproStage::kProduceCSource);
}

void test_d_build_failure_drops_source_when_flag_off() {
    ReproResult result;
    result.selected_artifact = BaselineArtifact();
    ReproConfig cfg;
    cfg.produce_c_reproducer            = true;
    cfg.try_compile_c_reproducer        = true;
    cfg.keep_c_source_on_build_failure  = false;

    auto force_failure = [](std::string src) {
        return std::string("#error force\n") + src;
    };

    bool ok = cs_stage::ProduceCSourceStage(result, cfg, force_failure);
    CHECK(!ok);
    CHECK(result.completion_reason ==
          ReproCompletionReason::kCReproBuildFailed);
    // .source dropped per flag.
    CHECK(result.c_reproducer_source.empty());
}

void test_e_buildplan_gated_by_produce_c_reproducer_flag() {
    NullExecAdapter exec;
    ReproManager mgr(/*engine=*/nullptr, exec);

    // Default cfg → produce_c_reproducer = false → no kProduceCSource.
    {
        const auto plan = mgr.BuildPlanForCurrentConfig();
        bool found = false;
        for (const auto& node : plan) {
            if (node.op == ReproStageOp::kProduceCSource) { found = true; break; }
        }
        CHECK(!found);
    }

    // Flip the flag → kProduceCSource appended at the tail (after Reliability).
    {
        ReproConfig cfg;
        cfg.produce_c_reproducer = true;
        mgr.SetReproConfig(cfg);
        const auto plan = mgr.BuildPlanForCurrentConfig();
        CHECK(!plan.empty());
        CHECK(plan.back().op == ReproStageOp::kProduceCSource);
        // Reliability MUST appear strictly before the new tail so a
        // non-reproducible repro short-circuits the loop before ever
        // invoking csource.
        bool reliability_before_csource = false;
        for (std::size_t i = 0; i + 1 < plan.size(); ++i) {
            if (plan[i].op == ReproStageOp::kReliability) {
                reliability_before_csource = true;
                break;
            }
        }
        CHECK(reliability_before_csource);
    }
}

} // namespace

int main() {
    RUN_TEST(test_a_artifact_null_yields_no_minimized_artifact_reason);
    RUN_TEST(test_b_baseline_prog_emits_csource_source);
    RUN_TEST(test_c_non_baseline_failnth_yields_unsupported_reason);
    RUN_TEST(test_d_build_failure_keeps_source_when_flag_on);
    RUN_TEST(test_d_build_failure_drops_source_when_flag_off);
    RUN_TEST(test_e_buildplan_gated_by_produce_c_reproducer_flag);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}

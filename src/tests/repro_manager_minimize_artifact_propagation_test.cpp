// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Epic 4 PR-4-D B1 — verifies that StageMinimize writes back the
// minimized typed authority into ReproResult.selected_artifact so
// downstream stages (StageProduceCSource and any future smash /
// mutational resume) see the post-minimize prog instead of the
// extract output.
//
// Tests are unit tests on the `detail::ApplyMinimizeResult` helper —
// the exact callsite used inside `ReproManager::StageMinimize`. A
// regression that drops the propagation block (e.g., reverting the
// PR-4-D B1 fix) flunks both tests.

#include "refuzz/crash/repro/core/repro_types.hpp"
#include "refuzz/crash/repro/manager/repro_manager.hpp"
#include "refuzz/crash/repro/ops/linuxkernel/syz_ops/minimize/program_minimizer.hpp"
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
using ::refuzz::crash::MinimizeResult;
using ::refuzz::crash::ReproResult;
using ::refuzz::crash::detail::ApplyMinimizeResult;

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

pr::ProgramTargetKey LinuxAmd64Key() {
    const auto& t = syz::Target::linux_amd64();
    return {std::string(t.os()), std::string(t.arch()), std::string(t.revision())};
}

std::shared_ptr<const pr::ProgramArtifact> MakeArtifactFor(const char* call_name) {
    const auto& t = syz::Target::linux_amd64();
    auto p = std::make_unique<syz::Prog>();
    p->set_target(&t);
    const auto* meta = t.find_syscall(call_name);
    auto c = std::make_unique<syz::Call>();
    c->set_meta(meta);
    for (const auto& f : meta->args()) {
        if (f.type() == nullptr) continue;
        c->add_arg(f.type()->default_arg(f.dir(syz::Dir::kIn)));
    }
    p->add_call(std::move(c));

    auto typed_mut = std::shared_ptr<syz::Prog>(std::move(p));
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

void test_minimized_artifact_replaces_extract_artifact() {
    auto artA = MakeArtifactFor("getpid");      // pre-minimize (extract output)
    auto artB = MakeArtifactFor("getuid");      // post-minimize (minimized)
    CHECK(artA != nullptr && artA->valid());
    CHECK(artB != nullptr && artB->valid());

    ReproResult r;
    r.selected_artifact   = artA;
    r.original_call_count = 0;        // not yet set by extract path

    MinimizeResult mr;
    mr.success                = true;
    mr.payload                = {0x10, 0x20, 0x30};
    mr.original_call_count    = 5;
    mr.minimized_call_count   = 1;
    mr.minimize_attempts      = 17;
    mr.minimize_commits       = 4;
    mr.minimize_stage         = "calls";
    mr.artifact               = artB;

    ApplyMinimizeResult(std::move(mr), r);

    // selected_artifact now points at the minimized typed authority.
    CHECK(r.selected_artifact.get() == artB.get());
    CHECK(r.selected_artifact->valid());
    // Counts + payload propagated.
    CHECK(r.minimized_payload.size() == 3);
    CHECK(r.original_call_count == 5);
    CHECK(r.minimized_call_count == 1);
    CHECK(r.minimize_attempts == 17);
    CHECK(r.minimize_commits == 4);
    CHECK(r.minimize_stage == "calls");
}

void test_null_minimize_artifact_leaves_extract_artifact_intact() {
    auto artA = MakeArtifactFor("getpid");
    CHECK(artA != nullptr && artA->valid());

    ReproResult r;
    r.selected_artifact = artA;

    MinimizeResult mr;
    mr.success            = true;        // success path
    mr.artifact           = nullptr;     // engine returned no typed view
    mr.minimized_call_count = 1;

    ApplyMinimizeResult(std::move(mr), r);

    // Per Epic 4 plan §3 fallback rule: extract artifact stays — we
    // don't have a better authority to propagate.
    CHECK(r.selected_artifact.get() == artA.get());
}

void test_failed_minimize_does_not_touch_artifact_or_payload() {
    auto artA = MakeArtifactFor("getpid");
    ReproResult r;
    r.selected_artifact = artA;
    r.minimized_payload = {0xAA};          // earlier extract bytes
    r.original_call_count  = 7;
    r.minimized_call_count = 7;

    MinimizeResult mr;
    mr.success         = false;            // engine failed
    mr.minimize_attempts = 3;
    mr.minimize_commits  = 0;
    mr.minimize_stage    = "calls";
    // mr.artifact intentionally left null

    ApplyMinimizeResult(std::move(mr), r);

    // Counters are surfaced regardless of success.
    CHECK(r.minimize_attempts == 3);
    CHECK(r.minimize_commits == 0);
    CHECK(r.minimize_stage == "calls");
    // But payload, counts, and selected_artifact must be untouched.
    CHECK(r.minimized_payload.size() == 1);
    CHECK(r.minimized_payload[0] == 0xAA);
    CHECK(r.original_call_count == 7);
    CHECK(r.minimized_call_count == 7);
    CHECK(r.selected_artifact.get() == artA.get());
}

} // namespace

int main() {
    RUN_TEST(test_minimized_artifact_replaces_extract_artifact);
    RUN_TEST(test_null_minimize_artifact_leaves_extract_artifact_intact);
    RUN_TEST(test_failed_minimize_does_not_touch_artifact_or_payload);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}

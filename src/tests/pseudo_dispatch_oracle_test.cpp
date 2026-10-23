// Epic 2 oracle #25 — supported pseudo reaches the pseudo handler,
// not syscall(0,...).
//
// Closes plan §5 Epic 2 completion gate (a):
//   "A generated program containing a supported pseudo call reaches
//    the pseudo handler, not syscall read(0, ...)."
//
// What this test proves end-to-end:
//   1. Generator's permissive-policy uniform pick can land a kNative
//      pseudo (`syz_open_pts`, no caps required).
//   2. serialize_for_exec emits the synthesized pseudo NR via
//      c->meta()->id() → typed Target syscalls[id]->nr().
//   3. exec_wire decoder recovers the same call_id.
//   4. KernelWireDriver's `nr = syscalls[cl->call_id]->nr()` lookup
//      yields a value ≥ kPseudoNrBase (post-Epic-2 typed Target).
//   5. ResolveSyzCallByNr (worker-side resolver) classifies that nr
//      as kPseudo, which is precisely the gate ExecuteNrOrPseudo uses
//      before routing to DispatchPseudo. (We don't actually fire the
//      pseudo handler — that would touch the real kernel; the test
//      stops at "would dispatch as pseudo".)
//
// This is the byte-level proof that the source-of-truth fix from
// PR-2-A + PR-2-B + PR-2-C closes the BLOCKED_ARCH in audit row #5.
//
// What this test does NOT cover:
//   - The pseudo handler's actual behavior. Worker pseudo runtime is
//     §3.13 / §3.14 follow-up work.
//   - Capability-gated pseudos (handled by selection_allows; covered
//     in pseudo_selection_policy_test).

#include "refuzz/mutator/linux/syz_v2/generator.hpp"
#include "refuzz/mutator/linux/syz_v2/random.hpp"
#include "refuzz/program/syz/pseudo/target_view.hpp"
#include "refuzz/program/syz/exec_wire.hpp"
#include "refuzz/program/syz/exec_wire_decode.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "worker/dispatcher/dispatcher.hpp"
#include "worker/driver/kernel_wire_driver.hpp"

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <vector>

namespace {

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

namespace syz       = ::refuzz::program::syz;
namespace mut_v2    = ::refuzz::mutator::syz_v2;
namespace rw        = ::refuzz::worker;
namespace worker_syz = ::refuzz::fuzzer::syz;

// RecordingDispatcher — captures every nr the wire driver hands out
// without entering the kernel. Mirrors MockDispatcher in the §3.3
// Layer-2 wire-driver smoke. We assert against `seen_nrs` after
// driver.Execute returns.
class RecordingDispatcher final : public rw::IDispatcher {
public:
    std::vector<uint64_t> seen_nrs;

    rw::PseudoResult Dispatch(uint64_t nr,
                              const intptr_t* /*args*/,
                              uint32_t /*argc*/,
                              rw::PseudoRuntimeContext* /*ctx*/) override {
        seen_nrs.push_back(nr);
        // Synthetic non-zero return so wire driver records "ran".
        return rw::PseudoResult{42, 0, nullptr};
    }
    const char* Name() const override { return "recording"; }
};

// Loop generate_program until the produced Prog contains at least one
// kNative pseudo call. With permissive policy + uniform pick (no
// ChoiceTable), pseudo prevalence ≈ 240/8056 ≈ 3% per pick; ncalls=8
// yields a ≥1-pseudo prog with high probability in a handful of
// iterations. Bound retries to keep the test deterministic-ish.
std::unique_ptr<syz::Prog> generate_with_pseudo(const syz::Target& target) {
    constexpr int kCalls = 8;
    constexpr int kMaxAttempts = 200;
    for (int i = 0; i < kMaxAttempts; ++i) {
        auto prog = mut_v2::generate_program(target,
                                             /*seed=*/0xC0FFEEULL + i,
                                             kCalls,
                                             /*ct=*/nullptr);
        if (!prog || prog->calls().empty()) continue;
        for (const auto& call : prog->calls()) {
            if (!call || call->meta() == nullptr) continue;
            if (call->meta()->is_pseudo()) {
                return prog;
            }
        }
    }
    return nullptr;
}

void test_supported_pseudo_reaches_handler_via_wire_driver() {
    const auto& target = syz::Target::linux_amd64();

    auto prog = generate_with_pseudo(target);
    CHECK(prog != nullptr);

    // Encode → wire bytes (typed Target's pseudo NR rides on
    // c->meta()->id() lookup at line 306 of exec_wire.cpp; the actual
    // numeric NR is recovered downstream by the worker via id→nr).
    auto bytes_or = syz::serialize_for_exec(*prog);
    CHECK(bytes_or.has_value());
    const auto& bytes = *bytes_or;
    CHECK(!bytes.empty());

    // Run through the worker's actual streaming driver.
    auto disp_owner = std::make_unique<RecordingDispatcher>();
    RecordingDispatcher* disp = disp_owner.get();
    rw::KernelWireDriver driver(std::move(disp_owner));

    constexpr int kMaxOutput = 1024 * 1024;
    std::vector<uint8_t> out_buf(kMaxOutput);
    uint32_t out_len = 0;
    const int rc = driver.Execute(bytes.data(),
                                  static_cast<uint32_t>(bytes.size()),
                                  out_buf.data(),
                                  static_cast<uint32_t>(out_buf.size()),
                                  &out_len);
    CHECK(rc == 0);

    // The driver must have dispatched at least one nr in the pseudo
    // range. A real syscall picked by uniform fallback would dispatch
    // with nr < kPseudoNrBase; our generated prog had at least one
    // kNative pseudo, so the wire decoder + driver MUST surface it as
    // nr ≥ kPseudoNrBase. This is the post-Epic-2 invariant: typed
    // Target carries synthesized pseudoNrBase+i for syz_*, and the
    // wire driver reads that nr unchanged.
    int pseudo_dispatches = 0;
    int real_dispatches   = 0;
    for (uint64_t nr : disp->seen_nrs) {
        if (nr >= syz::kPseudoNrBase) ++pseudo_dispatches;
        else ++real_dispatches;
    }
    std::fprintf(stderr, "  recorded dispatches: real=%d pseudo=%d\n",
                 real_dispatches, pseudo_dispatches);
    CHECK(pseudo_dispatches >= 1);

    // Worker-side resolver should classify each pseudo nr as kPseudo
    // (this is the gate ExecuteNrOrPseudo uses at runtime). We don't
    // execute pseudo handlers — that's §3.13/§3.14 follow-up — but
    // we prove the routing decision is correct.
    int routed_pseudo = 0;
    for (uint64_t nr : disp->seen_nrs) {
        if (nr < syz::kPseudoNrBase) continue;
        const auto resolved =
            worker_syz::ResolveSyzCallByNr(worker_syz::kDefaultSyzTarget, nr);
        CHECK(resolved.kind == worker_syz::ResolvedCallKind::kPseudo);
        CHECK(resolved.pseudo != nullptr);
        ++routed_pseudo;
    }
    CHECK(routed_pseudo == pseudo_dispatches);
}

void test_real_syscall_does_not_resolve_as_pseudo() {
    // Sanity: `read` (nr=0) must NOT resolve as a pseudo via the
    // worker resolver. This pins the cross-source contract from the
    // *opposite* direction — pre-Epic-2 the typed Target also had
    // nr=0 for syz_*, which would have made this test ambiguous;
    // post-Epic-2 the contract is "nr<kPseudoNrBase ⇔ real syscall".
    const auto resolved = worker_syz::ResolveSyzCallByNr(
        worker_syz::kDefaultSyzTarget, /*nr=*/0);
    CHECK(resolved.kind != worker_syz::ResolvedCallKind::kPseudo);
}

}  // namespace

int main() {
    RUN_TEST(test_real_syscall_does_not_resolve_as_pseudo);
    RUN_TEST(test_supported_pseudo_reaches_handler_via_wire_driver);
    return 0;
}

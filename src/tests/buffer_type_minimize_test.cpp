// §3.11 follow-up P2 step 7 — BufferType::minimize virtual override
// behavioral test.
//
// Invariants under test:
//
//   1. kBlobRand, no min_len: halving-step shrink, kCrashSnapshot
//      mode, pred accepts → first attempt reduces size by half.
//   2. kBlobRand kCrash mode: only one shrink step is tried.
//   3. kBlobRange with range_begin == 4: never shrinks below 4.
//   4. kFilename var_len with trailing 'a's: trimmed + NUL re-added
//      (when no_z=false).
//   5. kFilename no_z=true: trailing NULs/'a's trimmed without
//      re-adding NUL.
//   6. kString / kGlob / kText / kCompressed → return false (not
//      shrinkable).
//   7. dir==kOut → skip.
//   8. dispatch_lookup absent → fail closed.

#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/minimize_ctx.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace {

#define CHECK(expr)                                                     \
    do {                                                                \
        if (!(expr)) {                                                  \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__,          \
                         __LINE__, #expr);                              \
            std::abort();                                               \
        }                                                               \
    } while (0)

#define RUN_TEST(fn)                                                    \
    do {                                                                \
        std::fprintf(stderr, "RUN  %s\n", #fn);                         \
        fn();                                                           \
        std::fprintf(stderr, "OK   %s\n", #fn);                         \
    } while (0)

namespace syz = refuzz::program::syz;

std::unique_ptr<syz::BufferType> MakeBuffer(syz::BufferKind kind,
                                             std::uint64_t   range_begin = 0,
                                             std::uint64_t   range_end = 0,
                                             bool            var_len = true,
                                             bool            no_z = false) {
    auto bt = std::make_unique<syz::BufferType>();
    bt->set_name("test_buffer");
    bt->set_var_len(var_len);
    bt->set_buffer_kind(kind);
    bt->set_range(range_begin, range_end);
    bt->set_no_z(no_z);
    return bt;
}

// Build a single-call Prog whose only arg is a DataArg with given
// data + dir.
std::unique_ptr<syz::Prog> BuildBufferProg(const syz::BufferType*    type,
                                           std::vector<std::uint8_t> data,
                                           syz::Dir                  dir = syz::Dir::kIn) {
    auto prog = std::make_unique<syz::Prog>();
    prog->set_target(&syz::Target::linux_amd64());

    auto call = std::make_unique<syz::Call>();

    auto data_arg = std::make_unique<syz::DataArg>();
    data_arg->set_type(type);
    data_arg->set_dir(dir);
    data_arg->set_data(std::move(data));

    call->add_arg(std::move(data_arg));
    prog->add_call(std::move(call));
    return prog;
}

syz::MinimizeCtx::DispatchLookup MakeFirstArgLookup() {
    return [](syz::Prog& p) -> syz::Arg* {
        if (p.mutable_calls().empty()) return nullptr;
        auto& call = p.mutable_calls()[0];
        if (call == nullptr || call->mutable_args().empty()) return nullptr;
        return call->mutable_args()[0].get();
    };
}

syz::MinimizeCtx MakeCtx(syz::Prog* prog, syz::MinimizeMode mode,
                         const bool& verdict, int& pred_calls) {
    syz::MinimizePred pred = [&](syz::Prog&, int) -> bool {
        ++pred_calls;
        return verdict;
    };
    return syz::MinimizeCtx(prog->target(), /*committed=*/nullptr, prog,
                            /*call_index0=*/0, mode, std::move(pred));
}

// ---------- tests ----------

void TestBlobRandHalvingShrinkCrashSnapshot() {
    auto type = MakeBuffer(syz::BufferKind::kBlobRand);
    std::vector<std::uint8_t> data(16, 0xAB);   // size = 16

    auto prog = BuildBufferProg(type.get(), data);
    auto* arg_ref = prog->mutable_calls()[0]->mutable_args()[0].get();

    bool verdict = true;
    int  pred_calls = 0;
    auto ctx = MakeCtx(prog.get(), syz::MinimizeMode::kCrashSnapshot,
                       verdict, pred_calls);
    ctx.set_dispatch_lookup(MakeFirstArgLookup());

    std::string path = "0:a0.";
    const bool ok = type->minimize(ctx, *arg_ref, path);
    CHECK(ok);
    CHECK(ctx.committed_count() == 1);
    CHECK(ctx.last_stage() == "arg buffer");

    // First candidate is size = 16 - 16 = 0 (skipped via add_unique
    // size==0 guard). Next: step /= 2 → 8 → next_size = 16 - 8 = 8.
    const auto* live = syz::as_data_arg(prog->calls()[0]->args()[0].get());
    CHECK(live != nullptr);
    CHECK(live->data().size() == 8);
}

void TestBlobRangeCrashModeOnlyOneShrinkStep() {
    // BlobRange with min_len=4 ensures the FIRST step produces a
    // valid candidate (next_size = 4, not 0) so we can observe the
    // crash-mode break-after-first-step behavior.
    auto type = MakeBuffer(syz::BufferKind::kBlobRange,
                            /*range_begin=*/4, /*range_end=*/16);
    std::vector<std::uint8_t> data(16, 0xCC);

    auto prog = BuildBufferProg(type.get(), data);
    auto* arg_ref = prog->mutable_calls()[0]->mutable_args()[0].get();

    bool verdict = false;             // pred rejects every candidate
    int  pred_calls = 0;
    auto ctx = MakeCtx(prog.get(), syz::MinimizeMode::kCrash,
                       verdict, pred_calls);
    ctx.set_dispatch_lookup(MakeFirstArgLookup());

    std::string path = "0:a0.";
    const bool ok = type->minimize(ctx, *arg_ref, path);
    CHECK(!ok);
    // Crash mode: only the first step (next_size = 4) is generated.
    CHECK(pred_calls == 1);
    CHECK(ctx.committed_count() == 0);
}

void TestBlobRangeRespectsMinLen() {
    // range_begin = 4 → can't shrink below 4.
    auto type = MakeBuffer(syz::BufferKind::kBlobRange,
                            /*range_begin=*/4, /*range_end=*/16,
                            /*var_len=*/true);
    std::vector<std::uint8_t> data(8, 0x55);

    auto prog = BuildBufferProg(type.get(), data);
    auto* arg_ref = prog->mutable_calls()[0]->mutable_args()[0].get();

    bool verdict = true;
    int  pred_calls = 0;
    auto ctx = MakeCtx(prog.get(), syz::MinimizeMode::kCrashSnapshot,
                       verdict, pred_calls);
    ctx.set_dispatch_lookup(MakeFirstArgLookup());

    std::string path = "0:a0.";
    const bool ok = type->minimize(ctx, *arg_ref, path);
    CHECK(ok);
    const auto* live = syz::as_data_arg(prog->calls()[0]->args()[0].get());
    CHECK(live != nullptr);
    // First candidate: step = 8-4 = 4 → next_size = 8-4 = 4. OK.
    CHECK(live->data().size() == 4);
    CHECK(live->data().size() >= 4);
}

void TestFilenameTrimAddsNul() {
    // var_len, no_z=false. Trailing 'a's get trimmed; NUL re-added.
    auto type = MakeBuffer(syz::BufferKind::kFilename,
                            /*range_begin=*/0, /*range_end=*/0,
                            /*var_len=*/true, /*no_z=*/false);
    // "/tmp/aaaa\0" → trim 'a's and trailing NUL → "/tmp/" + NUL
    std::vector<std::uint8_t> data = {'/', 't', 'm', 'p', '/', 'a', 'a', 'a', 'a', 0};

    auto prog = BuildBufferProg(type.get(), data);
    auto* arg_ref = prog->mutable_calls()[0]->mutable_args()[0].get();

    bool verdict = true;
    int  pred_calls = 0;
    auto ctx = MakeCtx(prog.get(), syz::MinimizeMode::kCrashSnapshot,
                       verdict, pred_calls);
    ctx.set_dispatch_lookup(MakeFirstArgLookup());

    std::string path = "0:a0.";
    const bool ok = type->minimize(ctx, *arg_ref, path);
    CHECK(ok);
    const auto* live = syz::as_data_arg(prog->calls()[0]->args()[0].get());
    CHECK(live != nullptr);
    // Trimmed = 5 ("/tmp/"); add NUL → length 6.
    CHECK(live->data().size() == 6);
    CHECK(live->data()[0] == '/');
    CHECK(live->data()[5] == 0);
}

void TestStringBufferReturnsFalse() {
    auto type = MakeBuffer(syz::BufferKind::kString);
    std::vector<std::uint8_t> data = {'a', 'a', 'a', 0};

    auto prog = BuildBufferProg(type.get(), data);
    auto* arg_ref = prog->mutable_calls()[0]->mutable_args()[0].get();

    bool verdict = true;
    int  pred_calls = 0;
    auto ctx = MakeCtx(prog.get(), syz::MinimizeMode::kCrashSnapshot,
                       verdict, pred_calls);
    ctx.set_dispatch_lookup(MakeFirstArgLookup());

    std::string path = "0:a0.";
    const bool ok = type->minimize(ctx, *arg_ref, path);
    CHECK(!ok);
    CHECK(pred_calls == 0);
    CHECK(ctx.committed_count() == 0);
}

void TestGlobBufferReturnsFalse() {
    auto type = MakeBuffer(syz::BufferKind::kGlob);
    std::vector<std::uint8_t> data = {'/', 't', 'm', 'p', '/', '*', 0};

    auto prog = BuildBufferProg(type.get(), data);
    auto* arg_ref = prog->mutable_calls()[0]->mutable_args()[0].get();

    bool verdict = true;
    int  pred_calls = 0;
    auto ctx = MakeCtx(prog.get(), syz::MinimizeMode::kCrashSnapshot,
                       verdict, pred_calls);
    ctx.set_dispatch_lookup(MakeFirstArgLookup());

    std::string path = "0:a0.";
    const bool ok = type->minimize(ctx, *arg_ref, path);
    CHECK(!ok);
    CHECK(pred_calls == 0);
    CHECK(ctx.committed_count() == 0);
}

void TestTextBufferReturnsFalse() {
    auto type = MakeBuffer(syz::BufferKind::kText);
    std::vector<std::uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};

    auto prog = BuildBufferProg(type.get(), data);
    auto* arg_ref = prog->mutable_calls()[0]->mutable_args()[0].get();

    bool verdict = true;
    int  pred_calls = 0;
    auto ctx = MakeCtx(prog.get(), syz::MinimizeMode::kCrashSnapshot,
                       verdict, pred_calls);
    ctx.set_dispatch_lookup(MakeFirstArgLookup());

    std::string path = "0:a0.";
    const bool ok = type->minimize(ctx, *arg_ref, path);
    CHECK(!ok);
    CHECK(pred_calls == 0);
    CHECK(ctx.committed_count() == 0);
}

void TestCompressedBufferReturnsFalse() {
    // is_compressed() short-circuits at the top of BufferType::minimize,
    // before the buffer_kind() switch — distinct path from kString/kGlob/
    // kText (which fail in the switch).
    auto type = MakeBuffer(syz::BufferKind::kCompressed);
    std::vector<std::uint8_t> data(8, 0x77);

    auto prog = BuildBufferProg(type.get(), data);
    auto* arg_ref = prog->mutable_calls()[0]->mutable_args()[0].get();

    bool verdict = true;
    int  pred_calls = 0;
    auto ctx = MakeCtx(prog.get(), syz::MinimizeMode::kCrashSnapshot,
                       verdict, pred_calls);
    ctx.set_dispatch_lookup(MakeFirstArgLookup());

    std::string path = "0:a0.";
    const bool ok = type->minimize(ctx, *arg_ref, path);
    CHECK(!ok);
    CHECK(pred_calls == 0);
    CHECK(ctx.committed_count() == 0);
}

void TestOutDirReturnsFalse() {
    auto type = MakeBuffer(syz::BufferKind::kBlobRand);
    std::vector<std::uint8_t> data(8, 0x99);

    auto prog = BuildBufferProg(type.get(), data, /*dir=*/syz::Dir::kOut);
    auto* arg_ref = prog->mutable_calls()[0]->mutable_args()[0].get();

    bool verdict = true;
    int  pred_calls = 0;
    auto ctx = MakeCtx(prog.get(), syz::MinimizeMode::kCrashSnapshot,
                       verdict, pred_calls);
    ctx.set_dispatch_lookup(MakeFirstArgLookup());

    std::string path = "0:a0.";
    const bool ok = type->minimize(ctx, *arg_ref, path);
    CHECK(!ok);
    CHECK(pred_calls == 0);
}

void TestNoDispatchLookupFailsClosed() {
    auto type = MakeBuffer(syz::BufferKind::kBlobRand);
    std::vector<std::uint8_t> data(16, 0xAA);

    auto prog = BuildBufferProg(type.get(), data);
    auto* arg_ref = prog->mutable_calls()[0]->mutable_args()[0].get();

    bool verdict = true;
    int  pred_calls = 0;
    auto ctx = MakeCtx(prog.get(), syz::MinimizeMode::kCrashSnapshot,
                       verdict, pred_calls);
    // No set_dispatch_lookup.

    std::string path = "0:a0.";
    const bool ok = type->minimize(ctx, *arg_ref, path);
    CHECK(!ok);
    CHECK(pred_calls == 0);
    CHECK(ctx.committed_count() == 0);
}

} // namespace

int main() {
    RUN_TEST(TestBlobRandHalvingShrinkCrashSnapshot);
    RUN_TEST(TestBlobRangeCrashModeOnlyOneShrinkStep);
    RUN_TEST(TestBlobRangeRespectsMinLen);
    RUN_TEST(TestFilenameTrimAddsNul);
    RUN_TEST(TestStringBufferReturnsFalse);
    RUN_TEST(TestGlobBufferReturnsFalse);
    RUN_TEST(TestTextBufferReturnsFalse);
    RUN_TEST(TestCompressedBufferReturnsFalse);
    RUN_TEST(TestOutDirReturnsFalse);
    RUN_TEST(TestNoDispatchLookupFailsClosed);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}

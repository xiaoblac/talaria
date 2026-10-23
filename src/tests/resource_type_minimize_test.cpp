// §3.11 follow-up P2 step 6 — ResourceType::minimize virtual override
// behavioral test.
//
// Invariants under test:
//
//   1. ResultArg with non-null res() + kCrashSnapshot + pred accept
//      → committed; live ResultArg has res()==nullptr,
//      val==default_value, op_div==op_add==0; the ex-producer's
//      uses_ no longer contains the consumer (C0 invariant).
//   2. Mode != kCrashSnapshot → early return false; pred not invoked.
//   3. ResultArg with res() already null → early return false.
//   4. Pred reject → rollback restores producer link + values.
//   5. dispatch_lookup absent → fail closed.

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

// Resource desc with values[0] = 0x1234 (default_value).
std::unique_ptr<syz::ResourceDesc> MakeResourceDesc() {
    return std::make_unique<syz::ResourceDesc>(
        std::string("res_test"),
        std::vector<std::string>{"res_test"},
        std::vector<std::uint64_t>{0x1234, 0xCAFE});
}

std::unique_ptr<syz::ResourceType> MakeResourceType(const syz::ResourceDesc* desc) {
    auto rt = std::make_unique<syz::ResourceType>();
    rt->set_name("test_resource");
    rt->set_size(8);
    rt->set_align(8);
    rt->set_desc(desc);
    return rt;
}

// Build a 2-call prog: call0 produces a resource (ret = ResultArg),
// call1 consumes it (args[0] = ResultArg with res() pointing to call0's ret).
//
// minimize is invoked on call1.args[0]; the dispatch_lookup returns
// that arg in any Prog.
struct ResourceFixture {
    std::unique_ptr<syz::Prog>          prog;
    syz::ResultArg*                     producer = nullptr;     // call0 ret
    syz::ResultArg*                     consumer = nullptr;     // call1 args[0]
    std::unique_ptr<syz::ResourceDesc>  desc;
    std::unique_ptr<syz::ResourceType>  type;
};

ResourceFixture BuildProg(std::uint64_t consumer_val,
                          std::uint64_t consumer_op_div,
                          std::uint64_t consumer_op_add) {
    ResourceFixture f;
    f.desc = MakeResourceDesc();
    f.type = MakeResourceType(f.desc.get());

    f.prog = std::make_unique<syz::Prog>();
    f.prog->set_target(&syz::Target::linux_amd64());

    // call0: ret produces a resource.
    auto call0 = std::make_unique<syz::Call>();
    auto ret   = std::make_unique<syz::ResultArg>();
    ret->set_type(f.type.get());
    ret->set_dir(syz::Dir::kOut);
    ret->set_val(0x9999);
    f.producer = ret.get();
    call0->set_ret(std::move(ret));
    f.prog->add_call(std::move(call0));

    // call1: args[0] consumes the resource.
    auto call1   = std::make_unique<syz::Call>();
    auto consumer = std::make_unique<syz::ResultArg>();
    consumer->set_type(f.type.get());
    consumer->set_dir(syz::Dir::kIn);
    consumer->set_val(consumer_val);
    consumer->set_op_div(consumer_op_div);
    consumer->set_op_add(consumer_op_add);
    consumer->set_res(f.producer);   // wires forward-edge in producer.uses_
    f.consumer = consumer.get();
    call1->add_arg(std::move(consumer));
    f.prog->add_call(std::move(call1));
    return f;
}

// dispatch_lookup that returns call1.args[0] in any Prog (matches the
// fixture's arg layout).
syz::MinimizeCtx::DispatchLookup MakeConsumerLookup() {
    return [](syz::Prog& p) -> syz::Arg* {
        if (p.mutable_calls().size() < 2) return nullptr;
        auto& call1 = p.mutable_calls()[1];
        if (call1 == nullptr || call1->mutable_args().empty()) return nullptr;
        return call1->mutable_args()[0].get();
    };
}

syz::MinimizeCtx MakeCtx(syz::Prog* prog, syz::MinimizeMode mode,
                         const bool& verdict, int& pred_calls) {
    syz::MinimizePred pred = [&](syz::Prog&, int) -> bool {
        ++pred_calls;
        return verdict;
    };
    return syz::MinimizeCtx(prog->target(), /*committed=*/nullptr, prog,
                            /*call_index0=*/-1, mode, std::move(pred));
}

// ---------- tests ----------

void TestDefaultsCommit() {
    auto f = BuildProg(/*val=*/0xAA, /*op_div=*/3, /*op_add=*/7);
    auto* arg_ref = f.consumer;

    // Pre: producer's uses_ contains consumer.
    CHECK(f.producer->uses().count(arg_ref) == 1);

    bool verdict = true;
    int  pred_calls = 0;
    auto ctx = MakeCtx(f.prog.get(), syz::MinimizeMode::kCrashSnapshot,
                       verdict, pred_calls);
    ctx.set_dispatch_lookup(MakeConsumerLookup());

    std::string path = "1:a0.";
    const bool ok = f.type->minimize(ctx, *arg_ref, path);
    CHECK(ok);
    CHECK(pred_calls == 1);
    CHECK(ctx.committed_count() == 1);
    CHECK(ctx.last_stage() == "arg resource");

    // Post: live consumer has res()==nullptr, val=default(=0x1234),
    // op_div=op_add=0. (Pointer identity changed via try_in_place
    // clone-mutate.)
    const auto* live_call1 = f.prog->calls()[1].get();
    CHECK(live_call1 != nullptr);
    const auto* live_consumer = syz::as_result_arg(live_call1->args()[0].get());
    CHECK(live_consumer != nullptr);
    CHECK(live_consumer->res() == nullptr);
    CHECK(live_consumer->val() == 0x1234);
    CHECK(live_consumer->op_div() == 0);
    CHECK(live_consumer->op_add() == 0);
}

void TestNonSnapshotModeReturnsFalse() {
    auto f = BuildProg(0xBB, 0, 0);
    auto* arg_ref = f.consumer;

    bool verdict = true;
    int  pred_calls = 0;
    auto ctx = MakeCtx(f.prog.get(), syz::MinimizeMode::kCrash,
                       verdict, pred_calls);
    ctx.set_dispatch_lookup(MakeConsumerLookup());

    std::string path = "1:a0.";
    const bool ok = f.type->minimize(ctx, *arg_ref, path);
    CHECK(!ok);
    CHECK(pred_calls == 0);
    CHECK(ctx.committed_count() == 0);
}

void TestAlreadyNullResReturnsFalse() {
    auto f = BuildProg(0xCC, 0, 0);
    // Manually drop the producer link before invoking minimize.
    f.consumer->set_res(nullptr);

    auto* arg_ref = f.consumer;

    bool verdict = true;
    int  pred_calls = 0;
    auto ctx = MakeCtx(f.prog.get(), syz::MinimizeMode::kCrashSnapshot,
                       verdict, pred_calls);
    ctx.set_dispatch_lookup(MakeConsumerLookup());

    std::string path = "1:a0.";
    const bool ok = f.type->minimize(ctx, *arg_ref, path);
    CHECK(!ok);
    CHECK(pred_calls == 0);
    CHECK(ctx.committed_count() == 0);
}

void TestPredRejectRollsBack() {
    auto f = BuildProg(/*val=*/0xDD, /*op_div=*/5, /*op_add=*/11);
    auto* arg_ref = f.consumer;

    bool verdict = false;
    int  pred_calls = 0;
    auto ctx = MakeCtx(f.prog.get(), syz::MinimizeMode::kCrashSnapshot,
                       verdict, pred_calls);
    ctx.set_dispatch_lookup(MakeConsumerLookup());

    std::string path = "1:a0.";
    const bool ok = f.type->minimize(ctx, *arg_ref, path);
    CHECK(!ok);
    CHECK(pred_calls == 1);
    CHECK(ctx.committed_count() == 0);

    // Rollback: live consumer still references the (cloned) producer
    // and retains original val/op_div/op_add.
    const auto* live_consumer = syz::as_result_arg(
        f.prog->calls()[1]->args()[0].get());
    CHECK(live_consumer != nullptr);
    CHECK(live_consumer->res() != nullptr);
    CHECK(live_consumer->val() == 0xDD);
    CHECK(live_consumer->op_div() == 5);
    CHECK(live_consumer->op_add() == 11);
}

void TestNoDispatchLookupFailsClosed() {
    auto f = BuildProg(0xEE, 0, 0);
    auto* arg_ref = f.consumer;

    bool verdict = true;
    int  pred_calls = 0;
    auto ctx = MakeCtx(f.prog.get(), syz::MinimizeMode::kCrashSnapshot,
                       verdict, pred_calls);
    // Deliberately skip set_dispatch_lookup.

    std::string path = "1:a0.";
    const bool ok = f.type->minimize(ctx, *arg_ref, path);
    CHECK(!ok);
    CHECK(pred_calls == 0);
    CHECK(ctx.committed_count() == 0);
}

} // namespace

int main() {
    RUN_TEST(TestDefaultsCommit);
    RUN_TEST(TestNonSnapshotModeReturnsFalse);
    RUN_TEST(TestAlreadyNullResReturnsFalse);
    RUN_TEST(TestPredRejectRollsBack);
    RUN_TEST(TestNoDispatchLookupFailsClosed);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}

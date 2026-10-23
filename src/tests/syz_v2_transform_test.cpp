// §3.11-C1 P2 — syz_v2 structural transform helpers.
//
// Covers the program::syz-owned helpers that crash/repro minimization
// and v2 mutators share:
//   - RelatedCalls walks typed ResultArg producer/consumer edges.
//   - RemoveCallRange clears dangling ResultArg refs before removed
//     producer calls are destroyed.

#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/transform.hpp"
#include "refuzz/program/syz/type.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstdint>
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

namespace syz = ::refuzz::program::syz;

struct GraphFixture {
    syz::ResourceDesc fd_desc{"fd", {"fd"}, {0xffffffffffffffffULL}};
    syz::ResourceType fd_type;
    syz::Prog prog;

    syz::ResultArg* call0_ret = nullptr;
    syz::ResultArg* call1_arg = nullptr;
    syz::ResultArg* call1_ret = nullptr;
    syz::ResultArg* call2_arg = nullptr;
    syz::ResultArg* call3_ret = nullptr;

    GraphFixture()
    {
        fd_type.set_name("fd");
        fd_type.set_size(8);
        fd_type.set_desc(&fd_desc);

        auto c0 = std::make_unique<syz::Call>();
        auto r0 = MakeResult(/*value=*/10);
        call0_ret = r0.get();
        c0->set_ret(std::move(r0));
        prog.add_call(std::move(c0));

        auto c1 = std::make_unique<syz::Call>();
        auto a1 = MakeResult(/*value=*/11);
        call1_arg = a1.get();
        call1_arg->set_res(call0_ret);
        c1->add_arg(std::move(a1));
        auto r1 = MakeResult(/*value=*/12);
        call1_ret = r1.get();
        c1->set_ret(std::move(r1));
        prog.add_call(std::move(c1));

        auto c2 = std::make_unique<syz::Call>();
        auto a2 = MakeResult(/*value=*/13);
        call2_arg = a2.get();
        call2_arg->set_res(call1_ret);
        c2->add_arg(std::move(a2));
        prog.add_call(std::move(c2));

        auto c3 = std::make_unique<syz::Call>();
        auto r3 = MakeResult(/*value=*/14);
        call3_ret = r3.get();
        c3->set_ret(std::move(r3));
        prog.add_call(std::move(c3));
    }

    std::unique_ptr<syz::ResultArg> MakeResult(std::uint64_t value)
    {
        auto arg = std::make_unique<syz::ResultArg>();
        arg->set_type(&fd_type);
        arg->set_dir(syz::Dir::kOut);
        arg->set_val(value);
        return arg;
    }
};

void TestRelatedCallsUsesTypedGraph()
{
    GraphFixture f;

    const auto keep = syz::RelatedCalls(f.prog, /*anchor_index=*/1);
    CHECK(keep.size() == 4);
    CHECK(keep[0]);
    CHECK(keep[1]);
    CHECK(keep[2]);
    CHECK(!keep[3]);

    CHECK(f.call0_ret->uses().count(f.call1_arg) == 1);
    CHECK(f.call1_ret->uses().count(f.call2_arg) == 1);
}

void TestRemoveCallRangeClearsDanglingRefs()
{
    GraphFixture f;

    CHECK(f.call1_ret->uses().count(f.call2_arg) == 1);
    CHECK(f.call2_arg->res() == f.call1_ret);
    CHECK(f.call2_arg->val() == 13);

    CHECK(syz::RemoveCallRange(f.prog, /*start=*/1, /*count=*/1));

    CHECK(f.prog.calls().size() == 3);
    CHECK(f.call2_arg->res() == nullptr);
    CHECK(f.call2_arg->op_div() == 0);
    CHECK(f.call2_arg->op_add() == 0);
    CHECK(f.call2_arg->val() == f.fd_type.default_value());
    CHECK(f.call0_ret->uses().empty());
    CHECK(f.prog.calls()[0]->ret() == f.call0_ret);
    CHECK(f.prog.calls()[1]->args()[0].get() == f.call2_arg);
    CHECK(f.prog.calls()[2]->ret() == f.call3_ret);
}

void TestRemoveCallRangeRejectsEmptyProgram()
{
    GraphFixture f;

    CHECK(!syz::RemoveCallRange(f.prog, /*start=*/0, /*count=*/4));
    CHECK(f.prog.calls().size() == 4);
}

// §3.11 follow-up B1 — verify RelatedCalls now follows
// BufferType.kFilename string-sharing edges, mirroring upstream
// `prog/minimization.go::uses` BufferFilename branch.
//
// Topology:
//   call 0: mkdir-like — DataArg(filename, "/foo")
//   call 1: noop       — no filename, no resource
//   call 2: mount-like — DataArg(filename, "/foo")  <-- anchor
//   call 3: unlink-like — DataArg(filename, "/foo")
//   call 4: noop       — DataArg(filename, "/bar")  (different filename)
//
// Expected keep set: {0, 2, 3} (filename-shared) + nothing else.
// Pre-fix behavior would keep only {2}.
void TestRelatedCallsFollowsFilenameEdge()
{
    syz::Prog prog;

    syz::BufferType filename_type;
    filename_type.set_name("filename");
    filename_type.set_buffer_kind(syz::BufferKind::kFilename);
    filename_type.set_size(8);

    auto make_filename_arg = [&](const std::string& path) {
        auto data = std::make_unique<syz::DataArg>();
        data->set_type(&filename_type);
        data->set_dir(syz::Dir::kIn);
        std::vector<std::uint8_t> bytes(path.begin(), path.end());
        bytes.push_back(0);  // syzkaller-style trailing NUL
        data->set_data(std::move(bytes));
        return data;
    };

    auto add_call = [&](std::unique_ptr<syz::Arg> arg_or_null) {
        auto c = std::make_unique<syz::Call>();
        if (arg_or_null) c->add_arg(std::move(arg_or_null));
        prog.add_call(std::move(c));
    };

    add_call(make_filename_arg("/foo"));      // call 0
    add_call(nullptr);                        // call 1 — noop
    add_call(make_filename_arg("/foo"));      // call 2 — anchor
    add_call(make_filename_arg("/foo"));      // call 3
    add_call(make_filename_arg("/bar"));      // call 4 — different filename

    const auto keep = syz::RelatedCalls(prog, /*anchor_index=*/2);
    CHECK(keep.size() == 5);
    CHECK(keep[0]);
    CHECK(!keep[1]);
    CHECK(keep[2]);
    CHECK(keep[3]);
    CHECK(!keep[4]);
}

// §3.11 follow-up B1 — DirOut filename args must NOT participate in
// the filename string graph (mirrors upstream `a.Dir() != DirOut`
// guard).
void TestRelatedCallsIgnoresOutFilenames()
{
    syz::Prog prog;

    syz::BufferType filename_type;
    filename_type.set_name("filename");
    filename_type.set_buffer_kind(syz::BufferKind::kFilename);
    filename_type.set_size(8);

    auto make_filename_arg = [&](const std::string& path, syz::Dir dir) {
        auto data = std::make_unique<syz::DataArg>();
        data->set_type(&filename_type);
        data->set_dir(dir);
        std::vector<std::uint8_t> bytes(path.begin(), path.end());
        bytes.push_back(0);
        data->set_data(std::move(bytes));
        return data;
    };

    auto add_call = [&](std::unique_ptr<syz::Arg> arg) {
        auto c = std::make_unique<syz::Call>();
        c->add_arg(std::move(arg));
        prog.add_call(std::move(c));
    };

    add_call(make_filename_arg("/foo", syz::Dir::kOut));  // call 0 — Out, ignored
    add_call(make_filename_arg("/foo", syz::Dir::kIn));   // call 1 — anchor

    const auto keep = syz::RelatedCalls(prog, /*anchor_index=*/1);
    CHECK(keep.size() == 2);
    CHECK(!keep[0]);  // Out filename does not establish edge
    CHECK(keep[1]);
}

} // namespace

int main()
{
    RUN_TEST(TestRelatedCallsUsesTypedGraph);
    RUN_TEST(TestRemoveCallRangeClearsDanglingRefs);
    RUN_TEST(TestRemoveCallRangeRejectsEmptyProgram);
    RUN_TEST(TestRelatedCallsFollowsFilenameEdge);
    RUN_TEST(TestRelatedCallsIgnoresOutFilenames);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}

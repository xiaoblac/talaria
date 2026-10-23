// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Epic 4 PR-4-B-6 — annotator insertion site verification.
//
// Linux's annotator is no-op; this test installs a RecordingAnnotator
// that returns a sentinel string per WireCall and asserts the
// sentinel appears at the csource.go:362 site (immediately after the
// emitted syscall line, wrapped in `/* ... */`).

#include "refuzz/crash/repro/csource/annotator.hpp"
#include "refuzz/crash/repro/csource/csource.hpp"
#include "refuzz/crash/repro/csource/internal/emit_call.hpp"
#include "refuzz/crash/repro/csource/internal/emit_prog_calls.hpp"
#include "refuzz/program/syz/exec_wire.hpp"
#include "refuzz/program/syz/exec_wire_decode.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstdio>
#include <cstdlib>
#include <format>
#include <memory>
#include <string>
#include <string_view>

namespace {

namespace cs  = ::refuzz::crash::repro::csource;
namespace em  = ::refuzz::crash::repro::csource::internal;
namespace syz = ::refuzz::program::syz;

#define CHECK(expr)                                                       \
    do {                                                                  \
        if (!(expr)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,  \
                         #expr);                                          \
            std::abort();                                                 \
        }                                                                 \
    } while (0)

bool contains(const std::string& s, std::string_view needle) {
    return s.find(needle) != std::string::npos;
}

class RecordingAnnotator final : public cs::ICallAnnotator {
public:
    std::string Annotate(const syz::WireCall& wc,
                         const syz::SyscallMeta& meta) const override {
        return std::format("ANN-{}-{}", meta.call_name(), wc.call_id);
    }
};

std::unique_ptr<syz::Call> make_call(const syz::Target& t,
                                     const std::string& name) {
    auto c = std::make_unique<syz::Call>();
    c->set_meta(t.find_syscall(name));
    return c;
}

} // namespace

int main() {
    const auto& t  = syz::Target::linux_amd64();
    const auto& ti = cs::linux_amd64_target_info();
    RecordingAnnotator ann;
    cs::Options opts;
    opts.Sandbox = "none";

    syz::Prog p;
    p.set_target(&t);
    p.add_call(make_call(t, "getpid"));

    auto bytes = syz::serialize_for_exec(p);
    CHECK(bytes.has_value());
    auto wp = syz::decode_exec_wire(*bytes);
    CHECK(wp.has_value());

    em::EmitCallCtx ctx{
        .target = &t, .target_info = &ti, .opts = &opts, .annotator = &ann,
    };
    auto out = em::emit_prog_calls(p, *wp, ctx, {},
                                   /*trace=*/false, /*add_comments=*/false);
    CHECK(out.has_value());
    CHECK(out->calls.size() == 1);
    std::fprintf(stderr, "  emitted: %s", out->calls[0].c_str());

    // Annotator output must be wrapped in /* ... */ AFTER the syscall;
    // for a getpid emit the line is `\tsyscall(__NR_getpid);` then
    // ` /* ANN-getpid-... */\n`.
    CHECK(contains(out->calls[0], "/* ANN-getpid-"));
    auto syscall_pos = out->calls[0].find("syscall(__NR_getpid");
    auto ann_pos     = out->calls[0].find("/* ANN-getpid-");
    CHECK(syscall_pos != std::string::npos);
    CHECK(ann_pos != std::string::npos);
    CHECK(syscall_pos < ann_pos);

    // Linux's default annotator returns "" — verify Write() with the
    // default annotator does NOT emit `/* */` for getpid.
    auto default_out = em::emit_prog_calls(
        p, *wp, em::EmitCallCtx{
            .target = &t, .target_info = &ti, .opts = &opts,
            .annotator = &cs::linux_amd64_annotator(),
        }, {}, false, false);
    CHECK(default_out.has_value());
    CHECK(!contains(default_out->calls[0], "/* "));

    std::fprintf(stderr, "ALL OK\n");
    return 0;
}

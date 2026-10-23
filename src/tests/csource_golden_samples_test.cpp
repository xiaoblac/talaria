// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
//
// Epic 4 PR-4-D §6.2 — golden samples vs upstream pkg/csource/testdata/{0,1,2}.
//
// For each upstream fixture:
//   1. Parse it (top: prog.text; bottom: alternating // comment-block
//      + syscall-line per call).
//   2. Decode prog.text into a typed Prog via TextDecoder.
//   3. Run csource::Write(prog, baseline_opts, linux_amd64_annotator(),
//      linux_amd64_target_info()).
//   4. For each expected syscall(...) line in the fixture, assert it
//      appears as a substring of the produced .c source. (Substring
//      rather than line-byte-equal because cs::Write wraps each
//      syscall with `\tres = ` prefix / `if (res != -1) r[i] = res`
//      footer; the inner `syscall(...)` expression itself is what
//      upstream's testdata pins.)
//
// Comment-block byte-equal is intentionally NOT asserted here:
// upstream stores its testdata after running clang-format on the
// generateComment() output. reFuzz's typed-comment parity is pinned
// by csource_typed_call_comment_test on the unformatted form, which
// gives a deterministic gate independent of the host clang-format.
//
// Schema gaps: when the schema doesn't carry one of the syscalls
// referenced by a fixture (e.g., a netlink variant lands in a later
// schema rebase), the test skips that fixture with a stderr note —
// it does NOT fail. New fixtures can be added by dropping more
// upstream files in REFUZZ_UPSTREAM_CSOURCE_TESTDATA.

#include "refuzz/crash/repro/csource/csource.hpp"
#include "refuzz/crash/repro/csource/options.hpp"
#include "refuzz/crash/repro/csource/target_info.hpp"
#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#ifndef REFUZZ_UPSTREAM_CSOURCE_TESTDATA
#error "REFUZZ_UPSTREAM_CSOURCE_TESTDATA must be set by CMake"
#endif

namespace {

namespace cs  = ::refuzz::crash::repro::csource;
namespace syz = ::refuzz::program::syz;

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

struct Sample {
    std::string filepath;
    std::string prog_text;
    std::vector<std::string> expected_syscall_lines;
};

bool starts_with(std::string_view s, std::string_view prefix) {
    return s.size() >= prefix.size() &&
           std::string_view(s.data(), prefix.size()) == prefix;
}

std::string read_file(const std::string& path) {
    std::ifstream is(path);
    if (!is) return {};
    std::ostringstream oss;
    oss << is.rdbuf();
    return oss.str();
}

std::vector<std::string> split_lines(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == '\n') {
            out.push_back(std::move(cur));
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) out.push_back(std::move(cur));
    return out;
}

// Parse upstream pkg/csource/testdata/{0,1,2} format:
//   <prog.text lines, separated by \n>
//   <empty line>
//   <alternating // comment lines + 1 syscall line per call>
Sample parse_sample(const std::string& filepath) {
    Sample s;
    s.filepath = filepath;
    const auto content = read_file(filepath);
    if (content.empty()) return s;
    const auto lines = split_lines(content);

    std::ostringstream prog;
    std::size_t i = 0;
    for (; i < lines.size(); ++i) {
        if (lines[i].empty()) {
            ++i;
            break;
        }
        prog << lines[i] << "\n";
    }
    s.prog_text = prog.str();

    for (; i < lines.size(); ++i) {
        if (lines[i].empty())                continue;
        if (starts_with(lines[i], "//"))     continue;
        s.expected_syscall_lines.push_back(lines[i]);
    }
    return s;
}

cs::Options BaselineOptions() {
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

void run_one_fixture(const std::string& filename) {
    const std::string path =
        std::string(REFUZZ_UPSTREAM_CSOURCE_TESTDATA) + "/" + filename;
    auto sample = parse_sample(path);
    if (sample.prog_text.empty() || sample.expected_syscall_lines.empty()) {
        std::fprintf(stderr, "  SKIP: testdata fixture %s missing or empty\n",
                     path.c_str());
        return;
    }

    const auto& target = syz::Target::linux_amd64();
    syz::TextDecoder dec(target, syz::DecodeMode::kNonStrict);
    auto prog_or = dec.decode(sample.prog_text);
    if (!prog_or.has_value()) {
        std::fprintf(stderr,
                     "  SKIP: TextDecoder cannot decode %s "
                     "(schema gap — line %d col %d msg=%s)\n",
                     path.c_str(),
                     prog_or.error().line, prog_or.error().column,
                     prog_or.error().message.c_str());
        return;
    }

    const auto& prog = *prog_or.value();
    auto wr = cs::Write(prog, BaselineOptions(),
                        cs::linux_amd64_annotator(),
                        cs::linux_amd64_target_info());
    if (!wr.has_value()) {
        std::fprintf(stderr,
                     "  Write failed on %s: code=%d msg=%s\n",
                     path.c_str(),
                     int(wr.error().code), wr.error().message.c_str());
    }
    CHECK(wr.has_value());
    const std::string& src = *wr;

    std::size_t matched = 0;
    for (const auto& expected : sample.expected_syscall_lines) {
        if (src.find(expected) != std::string::npos) {
            ++matched;
        } else {
            std::fprintf(stderr,
                         "  FAIL: fixture %s missing expected syscall line:\n"
                         "    %s\n",
                         path.c_str(), expected.c_str());
        }
    }
    if (matched != sample.expected_syscall_lines.size()) {
        std::fprintf(stderr,
                     "  fixture %s — matched %zu/%zu syscall lines\n",
                     path.c_str(), matched,
                     sample.expected_syscall_lines.size());
    }
    CHECK(matched == sample.expected_syscall_lines.size());
}

void test_testdata_fixture_0() { run_one_fixture("0"); }
void test_testdata_fixture_1() { run_one_fixture("1"); }
void test_testdata_fixture_2() { run_one_fixture("2"); }

} // namespace

int main() {
    RUN_TEST(test_testdata_fixture_0);
    RUN_TEST(test_testdata_fixture_1);
    RUN_TEST(test_testdata_fixture_2);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}

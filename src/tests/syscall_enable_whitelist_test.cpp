// [syscall-enable-whitelist] unit test — match_syscall glob semantics,
// compute_enabled_calls resolution (syz pkg/mgrconfig ParseEnabledSyscalls
// parity), and ChoiceTable honoring the per-id enabled mask.
//
// Uses the real linux/amd64 Target (same rationale as
// pseudo_selection_policy_test): a synthetic Target with a valid Type tree
// + finalize is fragile, and the real target exercises the resolver
// against the same data a production fuzz session sees.

#include "refuzz/mutator/linux/syz_v2/choice_table.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
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

namespace syz    = ::refuzz::program::syz;
namespace mut_v2 = ::refuzz::mutator::syz_v2;

// First real (non-pseudo), generatable call — anchors the mask tests.
const syz::SyscallMeta* find_real_enabled(const syz::Target& t) {
    for (const auto& sc : t.syscalls()) {
        if (!sc) continue;
        if (sc->is_pseudo()) continue;
        if (sc->attrs().disabled || sc->attrs().no_generate) continue;
        return sc.get();
    }
    return nullptr;
}

void test_match_syscall() {
    CHECK(syz::match_syscall("read", "read"));            // exact
    CHECK(syz::match_syscall("read$foo", "read"));        // base matches variant
    CHECK(!syz::match_syscall("read", "read$foo"));
    CHECK(syz::match_syscall("openat$x", "open*"));       // trailing-* prefix
    CHECK(syz::match_syscall("readv", "read*"));
    CHECK(!syz::match_syscall("read", "write"));
    CHECK(!syz::match_syscall("read", "rea"));            // prefix w/o '$' or '*'
    CHECK(!syz::match_syscall("read", "*"));              // bare '*' = no match (syz parity)
    CHECK(!syz::match_syscall("readbad", "read"));        // not '$'-bounded
}

void test_compute_empty_returns_full_mask() {
    const auto& t = syz::Target::linux_amd64();
    auto r = syz::compute_enabled_calls(t, {}, {});
    CHECK(r.ok);
    CHECK(!r.mask.empty());   // empty globs → all (minus statically disabled)
    const auto* p = find_real_enabled(t);
    CHECK(p != nullptr);
    CHECK(r.mask[p->id()] == 1);
}

void test_compute_enable_specific() {
    const auto& t = syz::Target::linux_amd64();
    const auto* p = find_real_enabled(t);
    CHECK(p != nullptr);
    auto r = syz::compute_enabled_calls(t, {p->name()}, {});
    CHECK(r.ok);
    CHECK(!r.mask.empty());
    CHECK(p->id() < r.mask.size());
    CHECK(r.mask[p->id()] == 1);
    std::size_t on = 0;
    for (auto v : r.mask) on += (v != 0);
    CHECK(on >= 1);
    CHECK(on < r.mask.size());   // one pattern cannot enable every call
}

void test_compute_unknown_enable_errors() {
    const auto& t = syz::Target::linux_amd64();
    auto r = syz::compute_enabled_calls(t, {"refuzz_not_a_syscall_zzz"}, {});
    CHECK(!r.ok);
    CHECK(r.error.find("unknown enabled") != std::string::npos);
    CHECK(r.mask.empty());
}

void test_compute_disable_subtracts() {
    const auto& t = syz::Target::linux_amd64();
    const auto* p = find_real_enabled(t);
    CHECK(p != nullptr);
    auto r = syz::compute_enabled_calls(t, {}, {p->name()});
    CHECK(r.ok);
    CHECK(!r.mask.empty());
    CHECK(r.mask[p->id()] == 0);   // removed by disable
    std::size_t on = 0;
    for (auto v : r.mask) on += (v != 0);
    CHECK(on > 0);                  // the rest remain enabled
}

void test_compute_unknown_disable_errors() {
    const auto& t = syz::Target::linux_amd64();
    auto r = syz::compute_enabled_calls(t, {}, {"refuzz_not_a_syscall_zzz"});
    CHECK(!r.ok);
    CHECK(r.error.find("unknown disabled") != std::string::npos);
}

void test_compute_all_disabled_errors() {
    const auto& t = syz::Target::linux_amd64();
    const auto* p = find_real_enabled(t);
    CHECK(p != nullptr);
    // Enable then disable the same pattern → empty enabled set → error.
    auto r = syz::compute_enabled_calls(t, {p->name()}, {p->name()});
    CHECK(!r.ok);
    CHECK(r.error.find("all syscalls disabled") != std::string::npos);
}

void test_choice_table_honors_mask() {
    const auto& t      = syz::Target::linux_amd64();

    mut_v2::ChoiceTable ct0;
    ct0.build(t);
    const std::size_t baseline = ct0.enabled_count();
    CHECK(baseline > 1);

    // All-ones mask == no filter.
    std::vector<std::uint8_t> all(t.syscalls().size(), 1);
    mut_v2::ChoiceTable ct1;
    ct1.build(t, all);
    CHECK(ct1.enabled_count() == baseline);

    // Single-call mask → exactly one generatable call.
    const auto* p = find_real_enabled(t);
    CHECK(p != nullptr);
    std::vector<std::uint8_t> one(t.syscalls().size(), 0);
    one[p->id()] = 1;
    mut_v2::ChoiceTable ct2;
    ct2.build(t, one);
    CHECK(ct2.enabled_count() == 1);
    CHECK(ct2.enabled_call(p->id()));
}

} // namespace

int main() {
    std::fprintf(stdout, "Running syscall_enable_whitelist_test...\n");
    RUN_TEST(test_match_syscall);
    RUN_TEST(test_compute_empty_returns_full_mask);
    RUN_TEST(test_compute_enable_specific);
    RUN_TEST(test_compute_unknown_enable_errors);
    RUN_TEST(test_compute_disable_subtracts);
    RUN_TEST(test_compute_unknown_disable_errors);
    RUN_TEST(test_compute_all_disabled_errors);
    RUN_TEST(test_choice_table_honors_mask);
    std::fprintf(stdout, "ALL PASS\n");
    return 0;
}

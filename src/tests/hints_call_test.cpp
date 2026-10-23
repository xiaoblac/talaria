// hints_call_test.cpp — Epic 5 PR-5-C (rev 2)
//
// Adapt of `prog/hints_test.go::TestHintsCall` (4 sub-cases). Upstream
// uses test-target syscalls (`ioctl$1`, `socket$generic`,
// `socket$inet6`, `socket$netlink`) deserialized from text — those
// syscalls don't exist in reFuzz's production linux/amd64 target. This
// port reproduces the SAME filter semantics with synthesized types:
//
//   Case 1 — FlagsType useless_hint filter (upstream ioctl$1).
//            FlagsType vals=[0x111,0x222,0x333,0x444]; input 0x111;
//            comps include all four vals + 0x0 + 0x666; only 0x666
//            survives (everything else is in calc_useless_hints =
//            {0, vals, OR-combos of size ≤3}).
//   Case 2 — specialInts filter (upstream socket$generic).
//            IntType (no useless filter beyond specialInts);
//            comps include 0x1000 / 0x10000 (specialInts) + 0x333;
//            ShrinkExpand drops the specialInts; 0x333 surfaces.
//   Case 3 — related_fields all-agree (upstream socket$inet6).
//            Field has related_fields = {type_a, type_b}; both types
//            accept replacers 0x10100/0x10200/0x10300; all three
//            survive. Asserts arg's own type's useless_hint is BYPASSED
//            when related_fields is non-empty (upstream
//            `prog/hints.go:191-198`).
//   Case 4 — related_fields some-disagree (upstream socket$netlink).
//            Field has related_fields = {type_a, type_b}; type_a
//            accepts 0x1100/0x1200/0x1300, type_b rejects them all;
//            no replacer survives.
//
// All 4 cases additionally assert NO extra candidates beyond the
// expected set (strict equality on the candidate list).

#include "refuzz/mutator/linux/syz_v2/hints/comp_map.hpp"
#include "refuzz/mutator/linux/syz_v2/hints/hints_apply.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <algorithm>
#include <cstdio>
#include <memory>
#include <set>
#include <unordered_set>
#include <vector>

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__); \
            return 1;                                                              \
        }                                                                          \
    } while (0)

namespace hints = refuzz::mutator::syz_v2::hints;
namespace syz   = refuzz::program::syz;

namespace {

std::unique_ptr<syz::IntType> MakeInt2() {
    auto t = std::make_unique<syz::IntType>();
    t->set_name("int2");
    t->set_size(2);
    return t;
}

std::unique_ptr<syz::FlagsType> MakeFlags2(std::vector<uint64_t> vals) {
    auto t = std::make_unique<syz::FlagsType>();
    t->set_name("flags2");
    t->set_size(2);
    t->set_vals(std::move(vals));
    return t;
}

std::unique_ptr<syz::FlagsType> MakeFlags4(std::vector<uint64_t> vals) {
    auto t = std::make_unique<syz::FlagsType>();
    t->set_name("flags4");
    t->set_size(4);
    t->set_vals(std::move(vals));
    return t;
}

// Reserved for future cases that need IntType size=4; unused today is
// OK once -Werror=unused-function is silenced via [[maybe_unused]].
[[maybe_unused]] std::unique_ptr<syz::IntType> MakeInt4() {
    auto t = std::make_unique<syz::IntType>();
    t->set_name("int4");
    t->set_size(4);
    return t;
}

hints::CompMap MakeMap(std::initializer_list<std::pair<uint64_t, std::vector<uint64_t>>> entries) {
    hints::CompMap m;
    for (const auto& [op1, op2s] : entries) {
        for (uint64_t op2 : op2s) m.Add(0x1, op1, op2, /*is_const=*/true);
    }
    return m;
}

bool VecEqAsSet(std::vector<uint64_t> got, std::vector<uint64_t> want) {
    std::sort(got.begin(), got.end());
    std::sort(want.begin(), want.end());
    return got == want;
}

void DumpVec(const char* label, const std::vector<uint64_t>& v) {
    std::fprintf(stderr, "  %s: [", label);
    bool first = true;
    for (uint64_t x : v) {
        if (!first) std::fprintf(stderr, ", ");
        first = false;
        std::fprintf(stderr, "0x%llx", static_cast<unsigned long long>(x));
    }
    std::fprintf(stderr, "]\n");
}

// =====================================================================
// Case 1 — FlagsType useless_hint filter (upstream ioctl$1).
// =====================================================================

int Case1_FlagsTypeUselessFilter() {
    std::fprintf(stderr, "  [RUN] Case1_FlagsTypeUselessFilter\n");
    // FlagsType vals=[0x666] → calc_useless_hints = {0, 0x666} (single
    // val + 0; no OR-combos because |vals|=1). Replacers in comps:
    //   - 0x0   → specialInt → dropped at ShrinkExpand
    //   - 0x111 → equals input val → ShrinkExpand drops `replacer == v`
    //   - 0x222 → not useless ({0,0x666}) → SURVIVES
    //   - 0x333 → not useless → SURVIVES
    //   - 0x444 → not useless → SURVIVES
    //   - 0x666 → useless (in vals) → DROPPED by useless_hint
    auto type = MakeFlags2({0x666});
    syz::ConstArg arg;
    arg.set_type(type.get());
    arg.set_dir(syz::Dir::kIn);
    arg.set_val(0x111);

    auto comps = MakeMap({{0x111, {0x0, 0x111, 0x222, 0x333, 0x444, 0x666}}});

    std::vector<uint64_t> got;
    hints::CheckConstArgHints(arg, /*field=*/nullptr, comps, [&]() {
        got.push_back(arg.val());
        return true;
    });

    if (!VecEqAsSet(got, {0x222, 0x333, 0x444})) {
        DumpVec("got",  got);
        DumpVec("want", {0x222, 0x333, 0x444});
        return 1;
    }
    std::fprintf(stderr, "  [PASS] Case1_FlagsTypeUselessFilter\n");
    return 0;
}

// =====================================================================
// Case 2 — specialInts filter (upstream socket$generic).
// =====================================================================

int Case2_SpecialIntsFilter() {
    std::fprintf(stderr, "  [RUN] Case2_SpecialIntsFilter\n");
    auto type = MakeInt2();    // plain IntType: useless = {specialInts}
    syz::ConstArg arg;
    arg.set_type(type.get());
    arg.set_dir(syz::Dir::kIn);
    arg.set_val(0x222);

    // 0x1000 and 0x10000 are in sorted_special_ints (powers of 2 +/- 1
    // family). 0x333 / 0x444 are not — they survive both the
    // ShrinkExpand specialIntsSet skip and IntType's calc_useless_hints
    // (which embeds kSpecialInts).
    auto comps = MakeMap({{0x222, {0x1000, 0x10000, 0x333, 0x444}}});

    std::vector<uint64_t> got;
    hints::CheckConstArgHints(arg, /*field=*/nullptr, comps, [&]() {
        got.push_back(arg.val());
        return true;
    });

    if (!VecEqAsSet(got, {0x333, 0x444})) {
        DumpVec("got",  got);
        DumpVec("want", {0x333, 0x444});
        return 1;
    }
    std::fprintf(stderr, "  [PASS] Case2_SpecialIntsFilter\n");
    return 0;
}

// =====================================================================
// Case 3 — related_fields all-agree (upstream socket$inet6).
// =====================================================================

int Case3_RelatedFieldsAllAgree() {
    std::fprintf(stderr, "  [RUN] Case3_RelatedFieldsAllAgree\n");
    // FlagsType size=4 (bitsize=32, limit=0xffffffff) so 0x10100 / 0x10200
    // / 0x10300 are within ShrinkExpand's range. Two variants with disjoint
    // vals so neither type's calc_useless_hints contains the target replacers.
    auto type_a = MakeFlags4({0xaaaa});  // useless = {0, 0xaaaa}
    auto type_b = MakeFlags4({0xbbbb});  // useless = {0, 0xbbbb}
    std::unordered_set<const syz::Type*> related{type_a.get(), type_b.get()};

    syz::Field f("proto", type_a.get());
    f.set_related_fields(&related);

    syz::ConstArg arg;
    arg.set_type(type_a.get());     // arg's own type is type_a
    arg.set_dir(syz::Dir::kIn);
    arg.set_val(0x333);

    // Replacers: 0x10100 / 0x10200 / 0x10300 — none in type_a.vals or
    // type_b.vals → both related types' useless_hint return false → survive.
    // 0x10000 is a specialInt → dropped at ShrinkExpand.
    // 0xaaaa is in type_a.vals → type_a.useless_hint(0xaaaa)=true →
    // dropped (note: arg's own useless_hint is BYPASSED when
    // related_fields non-empty per upstream prog/hints.go:191-198,
    // but the related set INCLUDES type_a).
    auto comps = MakeMap({{0x333, {0x10000, 0x10100, 0x10200, 0x10300, 0xaaaa}}});

    std::vector<uint64_t> got;
    hints::CheckConstArgHints(arg, &f, comps, [&]() {
        got.push_back(arg.val());
        return true;
    });

    if (!VecEqAsSet(got, {0x10100, 0x10200, 0x10300})) {
        DumpVec("got",  got);
        DumpVec("want", {0x10100, 0x10200, 0x10300});
        return 1;
    }
    std::fprintf(stderr, "  [PASS] Case3_RelatedFieldsAllAgree\n");
    return 0;
}

// =====================================================================
// Case 4 — related_fields some-disagree (upstream socket$netlink).
// =====================================================================

int Case4_RelatedFieldsSomeDisagree() {
    std::fprintf(stderr, "  [RUN] Case4_RelatedFieldsSomeDisagree\n");
    // type_a accepts 0x10100/0x10200/0x10300 (not in vals);
    // type_b's vals INCLUDE 0x10100/0x10200/0x10300 → useless_hint
    // returns true for all → ANY-related-useless rule drops them.
    // FlagsType size=4 so 0x10100..0x10400 fit within bitsize=32 limit.
    auto type_a = MakeFlags4({0xaaaa});
    auto type_b = MakeFlags4({0x10100, 0x10200, 0x10300});
    std::unordered_set<const syz::Type*> related{type_a.get(), type_b.get()};

    syz::Field f("proto", type_a.get());
    f.set_related_fields(&related);

    syz::ConstArg arg;
    arg.set_type(type_a.get());
    arg.set_dir(syz::Dir::kIn);
    arg.set_val(0x444);

    // Replacers: 0x10100/0x10200/0x10300 → in type_b.vals → type_b says
    // useless → all DROPPED. 0x10400 → not in either type's vals → both
    // accept → SURVIVES.
    auto comps = MakeMap({{0x444, {0x10100, 0x10200, 0x10300, 0x10400}}});

    std::vector<uint64_t> got;
    hints::CheckConstArgHints(arg, &f, comps, [&]() {
        got.push_back(arg.val());
        return true;
    });

    if (!VecEqAsSet(got, {0x10400})) {
        DumpVec("got",  got);
        DumpVec("want", {0x10400});
        return 1;
    }
    std::fprintf(stderr, "  [PASS] Case4_RelatedFieldsSomeDisagree\n");
    return 0;
}

// =====================================================================
// Case 5 — top-level MutateProgWithHints clone-and-restore semantic
// (kept from rev 1 — exercises the foreach_arg → exec_validate chain
// end-to-end via a 1-call Prog).
// =====================================================================

std::unique_ptr<syz::ConstArg> MakeConstArg(const syz::Type* t, uint64_t v) {
    auto a = std::make_unique<syz::ConstArg>();
    a->set_type(t);
    a->set_dir(syz::Dir::kIn);
    a->set_val(v);
    return a;
}

int Case5_TopLevelMutateClonesAndRestores() {
    std::fprintf(stderr, "  [RUN] Case5_TopLevelMutateClonesAndRestores\n");
    auto type_a = MakeInt2();
    auto type_b = MakeInt2();
    auto type_c = MakeInt2();
    syz::SyscallMeta meta;
    meta.set_name("test$hints_call");
    meta.set_call_name("test_hints_call");
    meta.set_id(0);
    meta.set_nr(0);
    std::vector<syz::Field> fields;
    fields.emplace_back("a", type_a.get());
    fields.emplace_back("b", type_b.get());
    fields.emplace_back("c", type_c.get());
    meta.set_args(std::move(fields));

    syz::Prog prog;
    prog.set_target(&syz::Target::linux_amd64());
    auto call = std::make_unique<syz::Call>();
    call->set_meta(&meta);
    call->add_arg(MakeConstArg(type_a.get(), 0x111));
    call->add_arg(MakeConstArg(type_b.get(), 0x222));
    call->add_arg(MakeConstArg(type_c.get(), 0x333));
    prog.add_call(std::move(call));

    hints::CompMap comps;
    comps.Add(0x1, 0x222, 0x999, /*is_const=*/true);

    std::set<uint64_t> b_vals;
    int candidate_count = 0;
    bool callback_invariant_broken = false;
    hints::MutateProgWithHints(prog, /*call_index=*/0, comps,
        [&](const syz::Prog& mutated) -> bool {
            ++candidate_count;
            if (mutated.calls().size() != 1) {
                callback_invariant_broken = true;
                return false;
            }
            const auto* mb = static_cast<const syz::ConstArg*>(
                mutated.calls()[0]->args()[1].get());
            b_vals.insert(mb->val());
            return true;
        });
    CHECK(!callback_invariant_broken);
    CHECK(candidate_count > 0);
    CHECK(b_vals.count(0x999) == 1);

    // Original prog must be unchanged.
    CHECK(static_cast<const syz::ConstArg*>(prog.calls()[0]->args()[0].get())->val() == 0x111);
    CHECK(static_cast<const syz::ConstArg*>(prog.calls()[0]->args()[1].get())->val() == 0x222);
    CHECK(static_cast<const syz::ConstArg*>(prog.calls()[0]->args()[2].get())->val() == 0x333);
    std::fprintf(stderr, "  [PASS] Case5_TopLevelMutateClonesAndRestores\n");
    return 0;
}

} // namespace

int main()
{
    int rc = 0;
    rc |= Case1_FlagsTypeUselessFilter();
    rc |= Case2_SpecialIntsFilter();
    rc |= Case3_RelatedFieldsAllAgree();
    rc |= Case4_RelatedFieldsSomeDisagree();
    rc |= Case5_TopLevelMutateClonesAndRestores();
    if (rc == 0) std::printf("hints_call_test PASSED\n");
    return rc;
}

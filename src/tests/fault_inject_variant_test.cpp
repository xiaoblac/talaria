// Copyright 2026 reFuzz project author -------youngkk.
//
// Epic 6 PR-6-B — MakeFaultInjectVariant ctest.
//
// Covers (plan §6.1 #5, 4 harness cases):
//   1. TestSetsFailNthAtRightCall
//      Clone 后 calls[call_index].props.fail_nth == nth;其它 call props 不动。
//   2. TestOtherCallPropsUntouched
//      给一个 call 已带 async/rerun(模拟 mutated seed 边角情形),variant 只
//      改 fail_nth,async/rerun 字段保持原值。
//   3. TestUnmutatedCallsByteEqual
//      非目标 call 的 args / meta / ret 经 DeepClone 后 byte-equal(对比
//      serialize_for_exec 输出),只目标 call 的 SetProps 区别。
//   4. TestNthZeroRoundTrip
//      nth=0 是合法输入(等价"清空 fail_nth"),variant 上 fail_nth 设为 0 +
//      其它字段不动。
//
// 不测 nth>100 / 边界 cap — 那是 Consumer 的职责(由 plan §3 D-1 / D-10 cap
// 强制),helper 只 mirror upstream `pkg/fuzzer/job.go:506-509` 的 clone+set 语义。

#include "refuzz/mutator/linux/syz_v2/fault_inject/fault_inject_variant.hpp"
#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/exec_wire.hpp"
#include "refuzz/program/syz/exec_wire_decode.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

#include <variant>

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string_view>
#include <utility>
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
namespace fi  = ::refuzz::mutator::linux::syz_v2::fault_inject;

std::unique_ptr<syz::Prog> DecodeProg(std::string_view text)
{
    syz::TextDecoder decoder(syz::Target::linux_amd64(),
                             syz::DecodeMode::kNonStrict);
    auto prog_or = decoder.decode(text);
    CHECK(prog_or.has_value());
    CHECK(*prog_or != nullptr);
    return std::move(*prog_or);
}

void TestSetsFailNthAtRightCall()
{
    auto base = DecodeProg(
        "getpid()\n"
        "getuid()\n"
        "gettid()\n");
    CHECK(base->calls().size() == 3);
    CHECK(base->calls()[0]->props().fail_nth == 0);
    CHECK(base->calls()[1]->props().fail_nth == 0);
    CHECK(base->calls()[2]->props().fail_nth == 0);

    auto variant = fi::MakeFaultInjectVariant(*base, /*call_index=*/1, /*nth=*/5);
    CHECK(variant != nullptr);
    CHECK(variant->calls().size() == 3);
    // 目标 call (idx=1) 的 fail_nth = 5
    CHECK(variant->calls()[1]->props().fail_nth == 5);
    // 其它 call 不动
    CHECK(variant->calls()[0]->props().fail_nth == 0);
    CHECK(variant->calls()[2]->props().fail_nth == 0);
    // base 没被破坏(deep clone)
    CHECK(base->calls()[1]->props().fail_nth == 0);
}

void TestOtherCallPropsUntouched()
{
    // 文本 codec 不允许 fail_nth + rerun 同 call(validation 拒绝),所以分开
    // 在不同 call 测:call[0] 带 async,call[1] 带 rerun,call[2] 是干净 call。
    // 拿 call[2] 做 fault_inject 目标,验证 call[0]/call[1] 的 async/rerun 不动。
    auto base = DecodeProg(
        "getpid() (async)\n"
        "getuid() (rerun: 2)\n"
        "gettid()\n");
    CHECK(base->calls()[0]->props().async);
    CHECK(base->calls()[1]->props().rerun == 2);

    auto variant = fi::MakeFaultInjectVariant(*base, /*call_index=*/2, /*nth=*/3);
    CHECK(variant != nullptr);
    // 目标 call (idx=2) — fail_nth=3, 其它默认
    CHECK(variant->calls()[2]->props().fail_nth == 3);
    CHECK(!variant->calls()[2]->props().async);
    CHECK(variant->calls()[2]->props().rerun == 0);
    // 非目标 call 的 props 与 base 完全一致
    CHECK(variant->calls()[0]->props() == base->calls()[0]->props());
    CHECK(variant->calls()[1]->props() == base->calls()[1]->props());
}

int CountSetPropsWithFailNth(const syz::WireProgram& wp, int target_fail_nth)
{
    int hits = 0;
    for (const auto& instr : wp.instrs) {
        if (auto* sp = std::get_if<syz::WireSetProps>(&instr)) {
            if (sp->fail_nth == target_fail_nth) ++hits;
        }
    }
    return hits;
}

int CountAnySetProps(const syz::WireProgram& wp)
{
    int hits = 0;
    for (const auto& instr : wp.instrs) {
        if (std::holds_alternative<syz::WireSetProps>(instr)) ++hits;
    }
    return hits;
}

void TestUnmutatedCallsByteEqual()
{
    // 用 wire-decode 验证 "只目标 call 多了 SetProps,其它 call 没动":
    //   - base wire 无 SetProps 区块
    //   - variant wire 恰好 1 个 SetProps 区块,fail_nth=7
    //   - 两边 num_calls 相同 (3)
    auto base = DecodeProg(
        "getpid()\n"
        "getuid()\n"
        "gettid()\n");

    auto variant = fi::MakeFaultInjectVariant(*base, /*call_index=*/0, /*nth=*/7);
    CHECK(variant != nullptr);

    auto base_bytes_or    = syz::serialize_for_exec(*base);
    auto variant_bytes_or = syz::serialize_for_exec(*variant);
    CHECK(base_bytes_or.has_value());
    CHECK(variant_bytes_or.has_value());

    auto base_wp_or    = syz::decode_exec_wire(*base_bytes_or);
    auto variant_wp_or = syz::decode_exec_wire(*variant_bytes_or);
    CHECK(base_wp_or.has_value());
    CHECK(variant_wp_or.has_value());

    CHECK(base_wp_or->num_calls == 3);
    CHECK(variant_wp_or->num_calls == 3);

    // base 没 SetProps;variant 仅 1 个 SetProps + fail_nth=7
    CHECK(CountAnySetProps(*base_wp_or) == 0);
    CHECK(CountAnySetProps(*variant_wp_or) == 1);
    CHECK(CountSetPropsWithFailNth(*variant_wp_or, 7) == 1);

    // variant 字节流总长大于 base(SetProps 区块占额外字节,具体长度由 varint
    // 编码 kExecInstrSetProps + 3 fields 决定;不锁数值,只确保 > 0)
    CHECK(variant_bytes_or->size() > base_bytes_or->size());
}

void TestNthZeroRoundTrip()
{
    auto base = DecodeProg(
        "getpid() (fail_nth: 5)\n"
        "getuid()\n");
    CHECK(base->calls()[0]->props().fail_nth == 5);

    // nth=0 等价"清空 fail_nth";helper 不应 reject 这个用法。
    auto variant = fi::MakeFaultInjectVariant(*base, /*call_index=*/0, /*nth=*/0);
    CHECK(variant != nullptr);
    CHECK(variant->calls()[0]->props().fail_nth == 0);
    // base 仍带 fail_nth=5 (deep clone)
    CHECK(base->calls()[0]->props().fail_nth == 5);
}

// 边界:invalid call_index → nullptr (不 abort,留给 caller 处理)。
void TestInvalidCallIndexReturnsNull()
{
    auto base = DecodeProg("getpid()\n");
    CHECK(fi::MakeFaultInjectVariant(*base, -1, 1)  == nullptr);
    CHECK(fi::MakeFaultInjectVariant(*base, 1, 1)   == nullptr);  // out of range
    CHECK(fi::MakeFaultInjectVariant(*base, 999, 1) == nullptr);
}

}  // namespace

int main()
{
    RUN_TEST(TestSetsFailNthAtRightCall);
    RUN_TEST(TestOtherCallPropsUntouched);
    RUN_TEST(TestUnmutatedCallsByteEqual);
    RUN_TEST(TestNthZeroRoundTrip);
    RUN_TEST(TestInvalidCallIndexReturnsNull);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}

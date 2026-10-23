// Copyright 2026 reFuzz project author -------youngkk.
//
// PR-D regression: validate() 在 strict_invariant=true 时拒绝 non-optional
// ptr field 用 special pointer (NULL/0xff..ff/...) 编码的非法组合。
//
// Plan B feature flag:
//   - default opts (strict_invariant=false) → 行为不变,现有 caller 不破
//   - {.strict_invariant=true} → 启用 invariant,拒绝坏 IR
//
// Covers (docs/plans/worker-special-pointer-fix/04_pr_d_draft.md §6):
//   Case A — Plan B 三种断言形态:
//     1. strict on  + non-optional ptr 用 special pointer → fail (核心 invariant)
//     2. strict off + non-optional ptr 用 special pointer → ok (不破现有 caller)
//     3. strict on  + optional ptr 用 special pointer → ok (不误伤合法 NULL 路径)
//   Case B (可选) — TestMemAllocBankruptcyCounterIncrements:atomic 计数器
//     在 bankruptcy 时自增。

#include "refuzz/mutator/linux/syz_v2/generator.hpp"
#include "refuzz/mutator/linux/syz_v2/gen_state.hpp"
#include "refuzz/mutator/linux/syz_v2/random.hpp"
#include "refuzz/program/syz/alloc.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"
#include "refuzz/program/syz/validation.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <memory>
#include <utility>

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
namespace mut = ::refuzz::mutator::syz_v2;

// 构造 valid baseline Prog (走 generate_particular_call → Phase 1 已分配
// 合法 PointerArg.res / address)。
std::unique_ptr<syz::Prog>
BuildValidProgWithSyscall(const syz::Target& target,
                          const syz::SyscallMeta* meta,
                          uint64_t seed = 42)
{
    mut::RandGen r(seed);
    mut::GenState s(target);
    auto calls = mut::generate_particular_call(r, s, meta);
    if (calls.empty()) return nullptr;
    auto prog = std::make_unique<syz::Prog>();
    prog->set_target(&target);
    for (auto& c : calls) {
        prog->add_call(std::move(c));
    }
    return prog;
}

// 在最后一个 call (= 我们指定的那条) 里找:第一个 PointerArg 且其 type
// 满足 want_optional 条件。返回 (slot, type)。
struct PtrSlot {
    std::size_t            slot = 0;
    const syz::PtrType*    type = nullptr;
};
PtrSlot FindPtrArgSlot(const syz::Call& call, bool want_optional)
{
    for (std::size_t i = 0; i < call.args().size(); ++i) {
        const auto* a = call.args()[i].get();
        if (auto* pa = dynamic_cast<const syz::PointerArg*>(a)) {
            if (auto* pt = syz::as_ptr(pa->type())) {
                if (pt->optional() == want_optional) {
                    return {i, pt};
                }
            }
        }
    }
    return {0, nullptr};
}

// 把 args[slot] 替换为 is_special() 形态的 PointerArg
// (vma_size=0, res=null, address=0)。
void InjectSpecialPointerAt(syz::Call& call,
                            std::size_t slot,
                            const syz::PtrType* pt)
{
    auto pa = std::make_unique<syz::PointerArg>();
    pa->set_type(pt);
    pa->set_dir(syz::Dir::kIn);
    pa->set_address(0);   // vma_size=0 (default) + res=null (default)
                          // + address=0 → is_special() 命中,encoder 输出
                          // 0 - data_offset = 0xffffe...0 (special NULL).
    call.mutable_args()[slot] = std::move(pa);
}

// ----------------------------------------------------------------
// Case A — Plan B 三种断言形态合并到一个 test
//
// 本 test 用 syz_genetlink_get_family_id$auto_nbd 做样本 (charter §3 现场
// 样本,name 是 non-optional ptr[in, string["nbd"]])。
// ----------------------------------------------------------------
void TestStrictInvariantNonOptionalSpecialPointer()
{
    const auto& target = syz::Target::linux_amd64();
    const auto* meta =
        target.find_syscall("syz_genetlink_get_family_id$auto_nbd");
    CHECK(meta != nullptr);

    auto prog = BuildValidProgWithSyscall(target, meta);
    CHECK(prog != nullptr);
    CHECK(prog->calls().size() >= 1);

    // baseline 校验(generate_particular_call 产 IR 应当 validate ok)
    {
        auto r = syz::validate(*prog, syz::ValidateOptions{});
        if (!r) {
            std::fprintf(stderr, "  baseline validate failed: %s\n",
                         r.error().message.c_str());
            std::abort();
        }
    }

    // 找最后一个 call 的非 optional ptr arg slot
    auto& last_call = *prog->mutable_calls().back();
    auto found = FindPtrArgSlot(last_call, /*want_optional=*/false);
    if (found.type == nullptr) {
        std::fprintf(stderr,
                     "  SKIP: last call has no non-optional ptr arg "
                     "(test sample diverged from charter §3)\n");
        return;
    }

    // 注入 special pointer 到非 optional 槽位
    InjectSpecialPointerAt(last_call, found.slot, found.type);

    // ★ 形态 1: strict on → fail
    {
        syz::ValidateOptions opts;
        opts.strict_invariant = true;
        auto r = syz::validate(*prog, opts);
        CHECK(!r.has_value());
        CHECK(r.error().message.find(
                  "non-optional ptr arg used as special pointer")
              != std::string::npos);
        std::fprintf(stderr, "  strict on → reject: %s\n",
                     r.error().message.c_str());
    }

    // 形态 2: strict off (default) → ok (Plan B 不破现有 caller)
    {
        auto r = syz::validate(*prog, syz::ValidateOptions{});
        CHECK(r.has_value());
        std::fprintf(stderr, "  strict off → accept (Plan B default-off)\n");
    }
}

// ----------------------------------------------------------------
// Case A 形态 3 — 反向断言:strict on 不该误伤 optional ptr 的合法 NULL 路径
//
// 找一个有 optional ptr 字段的 syscall (扫 schema 自动找,避免硬编码具体
// syscall 名;optional ptr 在 sendmsg/setsockopt 等 sock-style 系统调用
// 里很常见)。
// ----------------------------------------------------------------
const syz::SyscallMeta* FindSyscallWithOptionalPtrField(const syz::Target& t)
{
    for (const auto& meta_up : t.syscalls()) {
        if (meta_up == nullptr) continue;
        for (const auto& field : meta_up->args()) {
            if (auto* pt = syz::as_ptr(field.type()); pt && pt->optional()) {
                return meta_up.get();
            }
        }
    }
    return nullptr;
}

void TestStrictInvariantOptionalSpecialPointerOk()
{
    const auto& target = syz::Target::linux_amd64();
    const auto* meta = FindSyscallWithOptionalPtrField(target);
    CHECK(meta != nullptr);
    std::fprintf(stderr, "  using syscall: %s\n", meta->name().c_str());

    auto prog = BuildValidProgWithSyscall(target, meta);
    CHECK(prog != nullptr);
    CHECK(prog->calls().size() >= 1);

    auto& last_call = *prog->mutable_calls().back();
    auto found = FindPtrArgSlot(last_call, /*want_optional=*/true);
    if (found.type == nullptr) {
        // 该 syscall 在生成时 Phase 1 直接给 optional 字段填了 NULL 等
        // 形态,而该 NULL PointerArg 已经满足 (res=null, address=0) → 已经
        // 是 is_special()。可以跳过 inject,直接 validate。
        // 但如果 PointerArg 在 GroupArg 内部嵌套,FindPtrArgSlot 看不到,
        // 那就 skip。
        std::fprintf(stderr,
                     "  SKIP: last call has no top-level optional ptr arg "
                     "(may be nested inside Group/Union)\n");
        return;
    }

    // 注入 special pointer 到 optional 槽位
    InjectSpecialPointerAt(last_call, found.slot, found.type);

    // ★ 形态 3: strict on + optional → ok (合法 NULL 路径不被误伤)
    {
        syz::ValidateOptions opts;
        opts.strict_invariant = true;
        auto r = syz::validate(*prog, opts);
        if (!r) {
            std::fprintf(stderr,
                         "  UNEXPECTED reject under strict for optional ptr: %s\n",
                         r.error().message.c_str());
        }
        CHECK(r.has_value());
        std::fprintf(stderr, "  strict on + optional → accept ✓\n");
    }
}

// ----------------------------------------------------------------
// Case B — MemAlloc bankruptcy counter 自增 (sanity)
//
// 实现技巧:用 note_alloc 一次性把整个 16 MiB bitmap 标满,然后单次 alloc
// 找不到空 slot → 进 bankruptcy。比反复 alloc 填满快几个数量级。
// ----------------------------------------------------------------
void TestMemAllocBankruptcyCounterIncrements()
{
    syz::MemAlloc::reset_bankruptcy_count();
    CHECK(syz::MemAlloc::bankruptcy_count() == 0);

    syz::MemAlloc ma(syz::MemAlloc::kMaxMem);

    // 标满整个 16 MiB bitmap (262144 个 granule)。
    ma.note_alloc(0, syz::MemAlloc::kMaxMem);

    // 此时 alloc 任何大小都找不到空槽,必走 bankruptcy 分支。
    (void)ma.alloc(/*size=*/64, /*align=*/64);

    const uint64_t count = syz::MemAlloc::bankruptcy_count();
    std::fprintf(stderr, "  bankruptcy_count after pre-filled alloc = %llu\n",
                 static_cast<unsigned long long>(count));
    CHECK(count == 1);

    // 再触发一次,验证累积语义。
    ma.note_alloc(0, syz::MemAlloc::kMaxMem);
    (void)ma.alloc(64, 64);
    CHECK(syz::MemAlloc::bankruptcy_count() == 2);

    // reset 复位
    syz::MemAlloc::reset_bankruptcy_count();
    CHECK(syz::MemAlloc::bankruptcy_count() == 0);
}

} // namespace

int main()
{
    RUN_TEST(TestStrictInvariantNonOptionalSpecialPointer);
    RUN_TEST(TestStrictInvariantOptionalSpecialPointerOk);
    RUN_TEST(TestMemAllocBankruptcyCounterIncrements);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}

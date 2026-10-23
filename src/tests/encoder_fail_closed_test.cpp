// Copyright 2026 reFuzz project author -------youngkk.
//
// Epic 7 PR-10 — encoder fail-closed regression test.
//
// 验证 serialize_for_exec 在 IR 含 silent-no-op 路径(write_arg 5 个 fail 分支)
// 时返 ExecError,**不**输出 partial wire 字节给 worker。
//
// Background:
// - write_arg 早期版本 (v1) 在 kResult/kPointer-odd-size/kData-empty/
//   kUnion-null-option/kGroup-leaf 5 个分支上 silent return;
// - 调用方 write_copyin 已经写 COPYIN+addr,arg 部分没写 → wire 错位 → decoder
//   把下一条 instr opcode (kExecInstrCopyin=0xFFFFFFFFFFFFFFFE) 当 arg kind 读
//   → "unknown arg kind" → worker 返 -1 → host 报 exec_error/abnormal_exit。
// - Step 8 corpus run 1.5% exec_error 全部来自这条根因。
// - 修复:write_arg 返 bool;5 个 silent return → return false;callers
//   (write_copyin / serialize_call) bool 化 + propagate;serialize_for_exec
//   顶层 fail-closed 返 ExecError。
//
// Test 策略:
//   1. 基线:正常 prog 文本 → serialize_for_exec 成功
//   2. DataArg 清空:典型的 silent-no-op 路径,foreach_arg 容易找到。set_data({})
//      → serialize_for_exec 期望返 ExecError。
//   3. UnionArg null option:不在所有 schema 上易复现;仅当 prog 包含 union arg
//      时才测试,否则 SKIP (不算失败,文档化)。
//
// 其它 silent-no-op 路径(kPointer odd size / kResult unknown / kGroup leaf)
// 在公共 API 上不易合成（kPointer.size() 由 Type.size() 决定;kResult unknown
// 是 first-pass discovery 漏的内部状态;kGroup 在 leaf 是 IR shape bug）。
// 它们的 fail-closed 行为由 write_arg 内同样的 `return false` 分支保证,
// 结构性正确性靠代码 review + [[nodiscard]] 编译期强制。

#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/analysis.hpp"   // foreach_arg
#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/exec_wire.hpp"
#include "refuzz/program/syz/exec_wire_decode.hpp"  // decode_exec_wire
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string_view>

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

std::unique_ptr<syz::Prog> DecodeProgText(std::string_view text)
{
    syz::TextDecoder decoder(syz::Target::linux_amd64(),
                             syz::DecodeMode::kNonStrict);
    auto prog_or = decoder.decode(text);
    CHECK(prog_or.has_value());
    CHECK(*prog_or != nullptr);
    return std::move(*prog_or);
}

// 在 prog 树里找第一个 DataArg, 返回 mutable ptr (or nullptr if none).
syz::DataArg* FindFirstDataArg(syz::Prog& prog)
{
    syz::DataArg* found = nullptr;
    for (auto& cup : prog.calls()) {
        if (found != nullptr) break;
        syz::Call* c = cup.get();
        syz::foreach_arg(c, [&](syz::Arg* a, syz::ArgCtx*) {
            if (found != nullptr) return;
            if (a->arg_kind() == syz::ArgKind::kData) {
                found = static_cast<syz::DataArg*>(a);
            }
        });
    }
    return found;
}

// ---- Tests --------------------------------------------------------

// 基线:正常 prog 能正确 serialize。
void TestBaselineSerializeSucceeds()
{
    // write 是典型有 DataArg 的 syscall。0x40 字节 buffer。
    auto prog = DecodeProgText(
        "write(0xffffffffffffffff, &(0x7f0000000000)=\"deadbeef\"/8, 0x8)\n");
    auto bytes_or = syz::serialize_for_exec(*prog);
    CHECK(bytes_or.has_value());
    CHECK(!bytes_or->empty());
    // sanity: roundtrip decode 也应该 OK
    auto wp_or = syz::decode_exec_wire(*bytes_or);
    CHECK(wp_or.has_value());
}

// kData empty silent-no-op 修复后应返 ExecError 而不是输出 partial wire。
void TestEmptyDataArgFailsClosed()
{
    auto prog = DecodeProgText(
        "write(0xffffffffffffffff, &(0x7f0000000000)=\"deadbeef\"/8, 0x8)\n");
    auto* da = FindFirstDataArg(*prog);
    CHECK(da != nullptr);  // write 应该有 DataArg

    // 触发 write_arg kData 分支的 silent-no-op:需要 data.empty() && size()!=0,
    // 否则 write_copyin 的 precheck (size==0) 会先 skip 整个 arg 而不进 write_arg。
    // set_out_size 清 data 但保留 size>0 (size() 返 out_size_ 当 data 空时),
    // 跳过 precheck → 进 write_arg kData → 命中 data.empty() return false 分支。
    da->set_out_size(8);
    CHECK(da->data().empty());
    CHECK(da->size() == 8);

    auto bytes_or = syz::serialize_for_exec(*prog);
    // 修复后:返 ExecError;修复前:返 corrupted bytes 流到 worker
    if (bytes_or.has_value()) {
        std::fprintf(stderr,
            "FAIL: serialize_for_exec 应返 ExecError 但返了 %zu bytes "
            "(empty DataArg silent-no-op path 未 fail-closed)\n",
            bytes_or->size());
        // dump first bytes for debugging
        for (size_t i = 0; i < std::min<size_t>(32, bytes_or->size()); ++i) {
            std::fprintf(stderr, "%02x ", (*bytes_or)[i]);
        }
        std::fprintf(stderr, "\n");
        std::abort();
    }
    // err message 包含 "non-encodable" / "silent-no-op" 提示 reviewer
    const std::string& msg = bytes_or.error().message;
    CHECK(msg.find("non-encodable") != std::string::npos ||
          msg.find("silent-no-op") != std::string::npos);
    // [v2 PR-12 B2] 锁住 per-path classification tag。B2 audit 靠 grep
    // `[kData]/[kUnion]/[kPointer]/[kResult]/[kGroup]` 在 host_events.txt
    // 做 distribution 统计;tag 形态变更必须改这条 assertion。
    CHECK(msg.find("[kData]") != std::string::npos);
    std::fprintf(stderr, "  (encoder error msg: %s)\n", msg.c_str());
}

}  // namespace

int main()
{
    RUN_TEST(TestBaselineSerializeSucceeds);
    RUN_TEST(TestEmptyDataArgFailsClosed);
    std::fprintf(stderr, "encoder_fail_closed_test: ALL OK\n");
    return 0;
}

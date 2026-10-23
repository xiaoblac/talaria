// Copyright 2026 reFuzz project author -------youngkk.
//
// PR-A regression: KernelWireDriver wire-addr reversal correctness.
//
// Covers (docs/plans/worker-special-pointer-fix/02_pr_a_draft.md §6):
//   1. TestNullPointerArgResolvesToZero       — special_pointers_[0]=0
//   2. TestNegOneSentinelResolvesToFFFF       — special_pointers_[1]=0xff..ff
//   3. TestPoisonResolvesToLiteral             — special_pointers_[2]=0x99..99
//   4. TestKernelCanonicalResolvesToLiteral    — special_pointers_[3]
//   5. TestVdsoResolvesToLiteral               — special_pointers_[4]
//   6. TestNormalScratchOffsetResolvesToVA     — wire_addr=0x40 (in-range)
//   7. TestOutOfRangeResolvesToLiteralVa       — wire_addr=0x1001000 (>16MiB)
//   8. TestGenetlinkWrapAddrResolvesToNull     — dynamically-built genetlink call
//      whose underflow wire_addr VA-wraps to 0 (NULL) via Execute, no SIGSEGV.
//
// Test seam: CapturingDispatcher records (nr, args) of each Dispatch.
// 我们绕过 TextDecoder + encoder,直接 encode_wire_program 一份手工
// WireProgram —— 这样能精确控制 wire_addr 字段去命中 special pointer
// 编码 (TextDecoder 路径默认 generator 修好的 IR 不容易再生成 res=null)。

#include "refuzz/program/syz/exec_wire_decode.hpp"
#include "refuzz/program/syz/target.hpp"
#include "worker/backend/pseudo/pseudo_result.hpp"
#include "worker/backend/pseudo/pseudo_runtime.hpp"
#include "worker/backend/syz_exec_runner.hpp"
#include "worker/dispatcher/dispatcher.hpp"
#include "worker/driver/kernel_wire_driver.hpp"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iterator>
#include <memory>
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
namespace worker = ::refuzz::worker;

// 与 host 端 Target schema 同步;PR-A helper 内常量。
constexpr uint64_t kDataOffset = 0x2000'0000'0000ULL;   // 32 TiB

// Capture 每条 Dispatch 调用的 (nr, args)。每个 Execute 后检查
// dispatcher.calls 即可看到 wire-addr 反演结果。
class CapturingDispatcher final : public worker::IDispatcher {
public:
    struct CallRecord {
        uint64_t nr = 0;
        std::vector<intptr_t> args;
    };

    worker::PseudoResult Dispatch(uint64_t nr,
                                  const intptr_t* args,
                                  uint32_t argc,
                                  worker::PseudoRuntimeContext*) override
    {
        CallRecord rec;
        rec.nr = nr;
        rec.args.assign(args, args + argc);
        calls.push_back(std::move(rec));
        return worker::PseudoResult{0, 0, nullptr};
    }
    const char* Name() const override { return "capturing"; }

    std::vector<CallRecord> calls;
};

// 拿一个稳定的 call_id 用 (任何真 syscall 都行,这里挑 read)。
uint64_t StableCallId()
{
    const auto& target = syz::Target::linux_amd64();
    const auto* meta = target.find_syscall("read");
    CHECK(meta != nullptr);
    return meta->id();
}

// 构造一份最小 WireProgram: 一条 syscall 一个 WireAddr arg,
// arg.addr = wire_addr。返回 encode 后的 wire 字节流。
std::vector<uint8_t> BuildOneCallWithAddr(uint64_t call_id, uint64_t wire_addr,
                                          uint8_t ptr_size = 8)
{
    syz::WireProgram wp;
    wp.num_calls = 1;

    syz::WireCall cl;
    cl.call_id = call_id;
    cl.copyout_idx = ~uint64_t{0};   // kExecNoCopyout

    syz::WireAddr addr;
    addr.ptr_size = ptr_size;
    addr.addr = wire_addr;
    cl.args.emplace_back(addr);

    wp.instrs.emplace_back(std::move(cl));
    return syz::encode_wire_program(wp);
}

// 把 wire 字节喂给 KernelWireDriver。driver 接管 dispatcher 所有权,
// driver 析构时 dispatcher 也销毁;所以必须在 driver 还活着时把
// calls 复制出来 —— DriveResult 不持有 dispatcher 指针。
struct DriveResult {
    int rc = 0;
    uint32_t output_len = 0;
    std::vector<CapturingDispatcher::CallRecord> calls;
};

template <std::size_t N>
DriveResult RunDriver(const std::vector<uint8_t>& bytes,
                      std::array<uint8_t, N>& output)
{
    auto dispatcher_ptr = std::make_unique<CapturingDispatcher>();
    auto* dispatcher = dispatcher_ptr.get();   // driver 析构前一直有效

    worker::KernelWireDriver driver(
        std::move(dispatcher_ptr),
        /*pid=*/0,
        /*inject_fault_fn=*/nullptr,
        /*fault_injected_fn=*/nullptr);

    DriveResult r;
    r.rc = driver.Execute(bytes.data(),
                          static_cast<uint32_t>(bytes.size()),
                          output.data(),
                          static_cast<uint32_t>(output.size()),
                          &r.output_len);
    r.calls = dispatcher->calls;   // 复制,driver 离开作用域 dispatcher 析构
    return r;
}

// ----------------------------------------------------------------
// 1. NULL (special_pointers_[0] = 0)
// ----------------------------------------------------------------
void TestNullPointerArgResolvesToZero()
{
    // wire_addr = 0 - data_offset = 0xffffe000_00000000 (uint64 underflow)
    constexpr uint64_t kWireNull = 0ULL - kDataOffset;
    const auto bytes = BuildOneCallWithAddr(StableCallId(), kWireNull);

    std::array<uint8_t, 4096> output{};
    auto r = RunDriver(bytes, output);

    CHECK(r.rc == 0);
    CHECK(r.calls.size() == 1);
    CHECK(r.calls[0].args.size() == 1);
    CHECK(r.calls[0].args[0] == static_cast<intptr_t>(0));
}

// ----------------------------------------------------------------
// 2. -1 sentinel (special_pointers_[1] = 0xffffffffffffffff)
// ----------------------------------------------------------------
void TestNegOneSentinelResolvesToFFFF()
{
    // wire_addr = 0xff..ff - data_offset = 0xffffdfff_ffffffff
    constexpr uint64_t kWireNegOne = 0xFFFF'FFFF'FFFF'FFFFULL - kDataOffset;
    const auto bytes = BuildOneCallWithAddr(StableCallId(), kWireNegOne);

    std::array<uint8_t, 4096> output{};
    auto r = RunDriver(bytes, output);

    CHECK(r.rc == 0);
    CHECK(r.calls.size() == 1);
    CHECK(r.calls[0].args[0]
          == static_cast<intptr_t>(0xFFFF'FFFF'FFFF'FFFFULL));
}

// ----------------------------------------------------------------
// 3. poison (special_pointers_[2] = 0x99..99)
// ----------------------------------------------------------------
void TestPoisonResolvesToLiteral()
{
    constexpr uint64_t kPoison = 0x9999'9999'9999'9999ULL;
    constexpr uint64_t kWirePoison = kPoison - kDataOffset;
    const auto bytes = BuildOneCallWithAddr(StableCallId(), kWirePoison);

    std::array<uint8_t, 4096> output{};
    auto r = RunDriver(bytes, output);

    CHECK(r.rc == 0);
    CHECK(r.calls[0].args[0] == static_cast<intptr_t>(kPoison));
}

// ----------------------------------------------------------------
// 4. kernel canonical (special_pointers_[3] = 0xffffffff81000000)
// ----------------------------------------------------------------
void TestKernelCanonicalResolvesToLiteral()
{
    constexpr uint64_t kKernel = 0xFFFF'FFFF'8100'0000ULL;
    constexpr uint64_t kWireKernel = kKernel - kDataOffset;
    const auto bytes = BuildOneCallWithAddr(StableCallId(), kWireKernel);

    std::array<uint8_t, 4096> output{};
    auto r = RunDriver(bytes, output);

    CHECK(r.rc == 0);
    CHECK(r.calls[0].args[0] == static_cast<intptr_t>(kKernel));
}

// ----------------------------------------------------------------
// 5. vdso (special_pointers_[4] = 0xffffffffff600000)
// ----------------------------------------------------------------
void TestVdsoResolvesToLiteral()
{
    constexpr uint64_t kVdso = 0xFFFF'FFFF'FF60'0000ULL;
    constexpr uint64_t kWireVdso = kVdso - kDataOffset;
    const auto bytes = BuildOneCallWithAddr(StableCallId(), kWireVdso);

    std::array<uint8_t, 4096> output{};
    auto r = RunDriver(bytes, output);

    CHECK(r.rc == 0);
    CHECK(r.calls[0].args[0] == static_cast<intptr_t>(kVdso));
}

// ----------------------------------------------------------------
// 6. 普通 scratch 偏移 (wire_addr=0x40, in-range)
//    应翻译成当前进程真实 scratch VA — 不是 raw wire_addr。默认 fixed
//    scratch layout 下它会等于 upstream VA；关闭 fixed layout 时则是普通
//    mmap 返回的进程 VA。
// ----------------------------------------------------------------
void TestNormalScratchOffsetResolvesToVA()
{
    constexpr uint64_t kWireNormal = 0x40;   // < scratch_cap (16 MiB)
    const auto bytes = BuildOneCallWithAddr(StableCallId(), kWireNormal);

    std::array<uint8_t, 4096> output{};
    auto r = RunDriver(bytes, output);

    CHECK(r.rc == 0);
    CHECK(r.calls.size() == 1);

    const intptr_t v = r.calls[0].args[0];
    // v 不是 raw wire_addr (会让 kernel deref 0x40 失败)
    CHECK(v != static_cast<intptr_t>(0x40));
    // v 是真实 process-VA: 远大于任何 wire offset。
    CHECK(v > static_cast<intptr_t>(0x1'0000));

    // 一致性: 同一 wire_addr 每次反演结果相同 (scratch 是 thread-local mmap,
    // 同一线程内固定;说明 scratch base 没漂)。
    auto bytes2 = BuildOneCallWithAddr(StableCallId(), kWireNormal);
    std::array<uint8_t, 4096> output2{};
    auto r2 = RunDriver(bytes2, output2);
    CHECK(r2.rc == 0);
    CHECK(r2.calls[0].args[0] == v);
}

// ----------------------------------------------------------------
// 7. 越界 wire_addr (>16 MiB scratch_cap, <data_offset+巨大值的中间地带)
//    走 special pointer 路径,写 literal va_upstream。这是 charter
//    Review log #1 提到的"中间地带"已知限制 — 测试覆盖防回归。
// ----------------------------------------------------------------
void TestOutOfRangeResolvesToLiteralVa()
{
    constexpr uint64_t kWireOOR = 0x1001000;   // 16 MiB + 4 KiB
    constexpr uint64_t kExpectedVa = kDataOffset + kWireOOR;
    const auto bytes = BuildOneCallWithAddr(StableCallId(), kWireOOR);

    std::array<uint8_t, 4096> output{};
    auto r = RunDriver(bytes, output);

    CHECK(r.rc == 0);
    CHECK(r.calls[0].args[0] == static_cast<intptr_t>(kExpectedVa));
}

// ----------------------------------------------------------------
// 8. genetlink pseudo call 的下溢 wire_addr 经 KernelWireDriver::Execute 反演成
//    0 (NULL) —— 证明 worker 把 wire 0xffffe..0 正确还原成 NULL、不 SIGSEGV。
//    动态编码构造(不再依赖固定 prog0.bin fixture),call_id/nr 走 schema 动态查,
//    抗 pseudo catalog / schema drift(原固定 .bin 里的 call_id 漂移正是它挂的根因)。
// ----------------------------------------------------------------
void TestGenetlinkWrapAddrResolvesToNull()
{
    // [PR-A VA-wrap] 动态构造(替代原读固定 prog0.bin fixture 的写法 —— 固定 .bin 里的
    // call_id 会随 pseudo catalog 变动漂移;动态编码 + schema 动态查 call_id/nr 天然抗漂移)。
    // 一条 genetlink pseudo call,其指针 arg 的 wire_addr 下溢 (0 - data_offset =
    // 0xffffe000_00000000);上游 VA wrap 应把它还原成 0 (NULL),driver 不得 SIGSEGV。
    const auto& target = syz::Target::linux_amd64();
    const auto* genetlink_meta =
        target.find_syscall("syz_genetlink_get_family_id$auto_nbd");
    CHECK(genetlink_meta != nullptr);

    constexpr uint64_t kWrapAddr = 0ULL - kDataOffset;  // uint64 下溢 → 0xffffe000_00000000
    const auto bytes = BuildOneCallWithAddr(genetlink_meta->id(), kWrapAddr);

    std::array<uint8_t, 4096> output{};
    auto r = RunDriver(bytes, output);

    CHECK(r.rc == 0);                                      // 没 SIGSEGV
    CHECK(r.calls.size() == 1);
    CHECK(r.calls[0].nr == genetlink_meta->nr());          // schema 动态查,抗 nr 漂移
    CHECK(r.calls[0].args.size() == 1);
    CHECK(r.calls[0].args[0] == static_cast<intptr_t>(0)); // wire 0xffffe..0 → NULL (PR-A 核心)
}

// ----------------------------------------------------------------
// 9. WireResult + fmt=kStrDec copyin renders ASCII zero-padded decimal.
//    Regression cover for fuse mount EINVAL root cause (Tier 3): mount
//    opts string contains "fd=<ResultArg>"; the ResultArg's BinaryFormat
//    on the wire is StrDec / StrHex / StrOct. Before fix, apply_copyin's
//    WireResult branch ignored fmt and binary-memcpy'd 5 raw bytes → kernel
//    mount opts parser saw garbage → -EINVAL.
//
//    This test wires a single Copyin (WireResult, fmt=StrDec, size=20)
//    into scratch[0..20] with default_val=42 (idx never set by copyout
//    since no prior call wrote it), then has the dispatcher read the 20
//    bytes back via the pointer arg. Expected scratch content:
//    "00000000000000000042" (no NUL).
// ----------------------------------------------------------------

// Specialized dispatcher that reads the first N bytes pointed to by args[0]
// at Dispatch time, so the test can assert on scratch byte content (the
// driver never exposes its scratch directly).
class ScratchPeekingDispatcher final : public worker::IDispatcher {
public:
    worker::PseudoResult Dispatch(uint64_t /*nr*/,
                                  const intptr_t* args,
                                  uint32_t argc,
                                  worker::PseudoRuntimeContext*) override
    {
        if (argc >= 1 && args[0] != 0 && peek_len > 0) {
            scratch_bytes.assign(peek_len, 0);
            std::memcpy(scratch_bytes.data(),
                        reinterpret_cast<const void*>(args[0]),
                        peek_len);
        }
        return worker::PseudoResult{0, 0, nullptr};
    }
    const char* Name() const override { return "scratch_peeking"; }

    std::size_t peek_len = 0;
    std::vector<uint8_t> scratch_bytes;
};

// Build a 2-instr WireProgram: WireCopyin(WireResult fmt=fmt, default=val)
// then a single Call carrying a WireAddr pointing at scratch addr 0.
std::vector<uint8_t> BuildCopyinResultThenCall(uint64_t call_id,
                                               syz::BinaryFormat fmt,
                                               uint64_t size,
                                               uint64_t default_val)
{
    syz::WireProgram wp;
    wp.num_calls = 1;

    syz::WireResult r;
    r.idx = 9999;          // intentionally out-of-range / never set → default
    r.fmt = fmt;
    r.size = size;
    r.default_val = default_val;
    wp.instrs.emplace_back(syz::WireCopyin{/*addr=*/0, syz::WireArg{r}});

    syz::WireCall cl;
    cl.call_id = call_id;
    cl.copyout_idx = ~uint64_t{0};
    syz::WireAddr a;
    a.ptr_size = 8;
    a.addr = 0;            // points at scratch[0]
    cl.args.emplace_back(a);
    wp.instrs.emplace_back(std::move(cl));

    return syz::encode_wire_program(wp);
}

template <std::size_t N>
void RunPeekDriverInline(const std::vector<uint8_t>& bytes,
                         std::array<uint8_t, N>& output,
                         std::size_t peek_len,
                         std::vector<uint8_t>* out_scratch_bytes,
                         int* out_rc)
{
    auto dispatcher_ptr = std::make_unique<ScratchPeekingDispatcher>();
    dispatcher_ptr->peek_len = peek_len;
    auto* dispatcher = dispatcher_ptr.get();

    worker::KernelWireDriver driver(
        std::move(dispatcher_ptr),
        /*pid=*/0,
        /*inject_fault_fn=*/nullptr,
        /*fault_injected_fn=*/nullptr);

    uint32_t output_len = 0;
    int rc = driver.Execute(bytes.data(),
                            static_cast<uint32_t>(bytes.size()),
                            output.data(),
                            static_cast<uint32_t>(output.size()),
                            &output_len);
    *out_rc = rc;
    *out_scratch_bytes = dispatcher->scratch_bytes;
}

void TestWireResultStrDecCopyinRendersAscii()
{
    const auto bytes =
        BuildCopyinResultThenCall(StableCallId(),
                                  syz::BinaryFormat::kStrDec,
                                  /*size=*/20,
                                  /*default_val=*/42);
    std::array<uint8_t, 4096> output{};
    std::vector<uint8_t> scratch;
    int rc = 0;
    RunPeekDriverInline(bytes, output, /*peek_len=*/20, &scratch, &rc);

    CHECK(rc == 0);
    CHECK(scratch.size() == 20);
    // Upstream "%020llu" → 20 chars, no NUL
    const char* kExpected = "00000000000000000042";
    for (std::size_t i = 0; i < 20; ++i) {
        CHECK(scratch[i] == static_cast<uint8_t>(kExpected[i]));
    }
}

void TestWireResultStrHexCopyinRendersAscii()
{
    const auto bytes =
        BuildCopyinResultThenCall(StableCallId(),
                                  syz::BinaryFormat::kStrHex,
                                  /*size=*/18,
                                  /*default_val=*/0xDEAD);
    std::array<uint8_t, 4096> output{};
    std::vector<uint8_t> scratch;
    int rc = 0;
    RunPeekDriverInline(bytes, output, /*peek_len=*/18, &scratch, &rc);

    CHECK(rc == 0);
    CHECK(scratch.size() == 18);
    // Upstream "0x%016llx" → "0x00000000000000ead" wait that's 19 chars,
    // let me check: "0x" + 16 hex → 18 chars total. 0xDEAD lowercase → "dead".
    const char* kExpected = "0x000000000000dead";
    for (std::size_t i = 0; i < 18; ++i) {
        CHECK(scratch[i] == static_cast<uint8_t>(kExpected[i]));
    }
}

void TestWireResultNativeCopyinKeepsBinary()
{
    // Native fmt: binary memcpy (no ASCII rendering). 4-byte int 0x12345678
    // → little-endian bytes 78 56 34 12.
    const auto bytes =
        BuildCopyinResultThenCall(StableCallId(),
                                  syz::BinaryFormat::kNative,
                                  /*size=*/4,
                                  /*default_val=*/0x12345678);
    std::array<uint8_t, 4096> output{};
    std::vector<uint8_t> scratch;
    int rc = 0;
    RunPeekDriverInline(bytes, output, /*peek_len=*/4, &scratch, &rc);

    CHECK(rc == 0);
    CHECK(scratch.size() == 4);
    CHECK(scratch[0] == 0x78);
    CHECK(scratch[1] == 0x56);
    CHECK(scratch[2] == 0x34);
    CHECK(scratch[3] == 0x12);
}

void TestWireResultStrDecBadSizeRejected()
{
    const auto bytes =
        BuildCopyinResultThenCall(StableCallId(),
                                  syz::BinaryFormat::kStrDec,
                                  /*size=*/8,
                                  /*default_val=*/42);
    std::array<uint8_t, 4096> output{};
    std::vector<uint8_t> scratch;
    int rc = 0;
    RunPeekDriverInline(bytes, output, /*peek_len=*/8, &scratch, &rc);

    CHECK(rc == -1);
    CHECK(scratch.empty());
}

void TestWireResultNativeBadSizeRejected()
{
    const auto bytes =
        BuildCopyinResultThenCall(StableCallId(),
                                  syz::BinaryFormat::kNative,
                                  /*size=*/3,
                                  /*default_val=*/0x123456);
    std::array<uint8_t, 4096> output{};
    std::vector<uint8_t> scratch;
    int rc = 0;
    RunPeekDriverInline(bytes, output, /*peek_len=*/3, &scratch, &rc);

    CHECK(rc == -1);
    CHECK(scratch.empty());
}

} // namespace

int main()
{
    RUN_TEST(TestNullPointerArgResolvesToZero);
    RUN_TEST(TestNegOneSentinelResolvesToFFFF);
    RUN_TEST(TestPoisonResolvesToLiteral);
    RUN_TEST(TestKernelCanonicalResolvesToLiteral);
    RUN_TEST(TestVdsoResolvesToLiteral);
    RUN_TEST(TestNormalScratchOffsetResolvesToVA);
    RUN_TEST(TestOutOfRangeResolvesToLiteralVa);
    RUN_TEST(TestGenetlinkWrapAddrResolvesToNull);
    RUN_TEST(TestWireResultStrDecCopyinRendersAscii);
    RUN_TEST(TestWireResultStrHexCopyinRendersAscii);
    RUN_TEST(TestWireResultNativeCopyinKeepsBinary);
    RUN_TEST(TestWireResultStrDecBadSizeRejected);
    RUN_TEST(TestWireResultNativeBadSizeRejected);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}

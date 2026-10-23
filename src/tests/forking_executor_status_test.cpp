// ForkingProgramExecutor 的 child-exit 分类测试 — 直接 fork + 控制 child 死法
// 验证 v3 重写后的 status-based 分流。
//
// 5 个 case:
//   (1) Normal: backend 返 0,child commit result page + _exit(0)
//       → done.status=0, done.output_len=backend_out
//   (2) SIGSEGV inside backend: WIFSIGNALED+SIGSEGV → crashed,status=-1,
//       output_len=0(test 没装 crash handler,crash_len=0;**progress 必须被忽略**)
//   (3) SIGKILL inside backend: WIFSIGNALED+SIGKILL → kKilledOrCleanExit
//       progress completed>0 + partial_len>0 → status=0, output_len=partial_len
//   (4) _exit(2) inside backend: WIFEXITED+status=2(非零非 128+sig) → kAbnormal
//       progress 必须被忽略,status=-1
//   (5) progress 后卡住:watchdog kill + reap → timeout,不能降成 partial
//
// 共享 result/progress page + output via MAP_SHARED|MAP_ANONYMOUS,parent 在 child
// 死后 ACQUIRE-load 验证。

#include "worker/backend/exec_backend.hpp"
#include "worker/engine/program_runtime.hpp"
#include "worker/engine/runtime_messages.hpp"
#include "worker/observation/observation_bus.hpp"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

#include <atomic>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>

// program_runtime.cpp 内 LOG/SIGCHLD 路径会读 g_running(其它 unit test 也是
// volatile sig_atomic_t)。这里同样要定义,否则 link 失败。
volatile sig_atomic_t g_running = 1;

namespace {

enum class CrashMode {
    kNormal,        // backend 正常返回 0
    kSigsegv,       // backend 内 raise(SIGSEGV) — handler 没装 → WIFSIGNALED
    kSigkillSelf,   // backend 内 kill(getpid(), SIGKILL) — WIFSIGNALED+SIGKILL
    kExitTwo,       // backend 内 _exit(2) — WIFEXITED+status=2
    kHangAfterProgress,
    kKcovFatal,
    kProcessSetup,
    kFdSweep,
};

constexpr std::size_t kOutputBytes = 256;
constexpr std::size_t kSharedBytes =
    sizeof(ProgramResultPageV3) + kOutputBytes + sizeof(std::uint32_t);
constexpr std::uint32_t kPublishedLoopMask = 1u << 5;
constexpr int kFdSweepProbe = 10;

struct SharedRegion {
    ProgramResultPageV3* result_page;
    std::uint32_t* progress_completed;
    std::uint32_t* progress_output_len;
    std::uint32_t* crash_len;
    std::uint32_t* fd_sweep_observed;
    std::uint8_t*  output;
    void*          base;
    std::size_t    size;
};

SharedRegion MapShared()
{
    void* p = ::mmap(nullptr, kSharedBytes, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    assert(p != MAP_FAILED);
    std::memset(p, 0, kSharedBytes);
    auto* b = static_cast<std::uint8_t*>(p);
    auto* result_page = reinterpret_cast<ProgramResultPageV3*>(b);
    return {
        result_page,
        &result_page->progress_completed_calls,
        &result_page->progress_output_len,
        &result_page->crash_len,
        reinterpret_cast<std::uint32_t*>(
            b + sizeof(ProgramResultPageV3) + kOutputBytes),
        b + sizeof(ProgramResultPageV3),
        p,
        kSharedBytes,
    };
}

class FdSweepObservationSink final
    : public refuzz::worker::IObservationSink {
public:
    explicit FdSweepObservationSink(std::uint32_t* observed)
        : observed_(observed)
    {}

    void OnEvent(refuzz::worker::ObservationEvent event,
                 const refuzz::worker::ObservationContext&) override
    {
        if (event != refuzz::worker::ObservationEvent::kSessionEnd) {
            return;
        }
        errno = 0;
        const int rc = ::fcntl(kFdSweepProbe, F_GETFD);
        const std::uint32_t state =
            rc == -1 && errno == EBADF ? 1u : 2u;
        __atomic_store_n(observed_, state, __ATOMIC_RELEASE);
    }

    void PackFeedback(std::uint8_t*, std::uint32_t,
                      std::uint32_t*) override
    {}

    const char* Name() const override { return "fd-sweep-observer"; }

private:
    std::uint32_t* observed_;
};

void UnmapShared(const SharedRegion& r)
{
    ::munmap(r.base, r.size);
}

// [early-publish] captures whatever ForkingProgramExecutor delivers through the
// ProgramRuntimeInput::publish_result hook. Committed results must flow through
// it exactly once and match the post-reap out_done; uncommitted crash/kill/exit
// paths must never fire it (production publishes those via the loop fallback).
struct PublishCapture {
    int count = 0;
    refuzz::worker::engine::DoneMsg last{};
};

bool CapturePublish(void* ctx, const refuzz::worker::engine::DoneMsg& done)
{
    auto* cap = static_cast<PublishCapture*>(ctx);
    ++cap->count;
    cap->last = done;
    return true; // stand in for a successful done-pipe write
}

// 测试 backend:在指定的 CrashMode 下模拟 driver "写部分 progress → 然后死/正常返"。
// 永远先写 progress=2/64(模拟 driver 跑了 2 个 call 写了 64 字节),然后:
//   kNormal      → memset output 一些字节 + 返 0(let parent write pipe + _exit(0))
//   kSigsegv     → raise(SIGSEGV) — child 死,无 handler
//   kSigkillSelf → kill(getpid(), SIGKILL) — child 死,无 handler
//   kExitTwo     → _exit(2)
class CrashModeBackend : public refuzz::worker::IExecBackend {
public:
    explicit CrashModeBackend(CrashMode mode) : mode_(mode) {}

    int Execute(const std::uint8_t* /*input*/, std::uint32_t /*input_len*/,
                std::uint8_t* output, std::uint32_t output_cap,
                std::uint32_t* output_len,
                refuzz::worker::ExecMode /*mode*/ = {}) override
    {
        // 模拟 driver 写 2 个 SyzExecResult head + 部分 tail = 64 字节。
        const std::uint32_t kSimulatedPartial = 64;
        if (output_cap >= kSimulatedPartial) {
            std::memset(output, 0xAB, kSimulatedPartial);
        }
        if (progress_completed_ != nullptr) {
            __atomic_store_n(progress_completed_, 2u, __ATOMIC_RELEASE);
        }
        if (progress_output_len_ != nullptr) {
            __atomic_store_n(progress_output_len_,
                             kSimulatedPartial, __ATOMIC_RELEASE);
        }
        loop_devices_used_mask_ |= kPublishedLoopMask;
        if (loop_devices_used_mask_cursor_ != nullptr) {
            __atomic_fetch_or(loop_devices_used_mask_cursor_,
                              kPublishedLoopMask,
                              __ATOMIC_RELEASE);
        }

        switch (mode_) {
        case CrashMode::kNormal:
            *output_len = kSimulatedPartial;
            return 0;
        case CrashMode::kSigsegv:
            ::raise(SIGSEGV);
            // unreachable
            std::abort();
        case CrashMode::kSigkillSelf:
            ::kill(::getpid(), SIGKILL);
            // unreachable
            std::abort();
        case CrashMode::kExitTwo:
            ::_exit(2);
        case CrashMode::kHangAfterProgress:
            for (;;) {
                ::pause();
            }
        case CrashMode::kKcovFatal:
            runtime_failure_ =
                refuzz::worker::RuntimeFailure::kKcovStateInvalid;
            return -1;
        case CrashMode::kProcessSetup: {
            int parent_death_signal = 0;
            if (::prctl(PR_GET_PDEATHSIG, &parent_death_signal) != 0 ||
                parent_death_signal != SIGKILL || ::getpgrp() != ::getpid()) {
                return -1;
            }
            *output_len = kSimulatedPartial;
            return 0;
        }
        case CrashMode::kFdSweep: {
            const int fd = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
            if (fd < 0) {
                return -1;
            }
            if (fd != kFdSweepProbe) {
                if (::dup2(fd, kFdSweepProbe) < 0) {
                    ::close(fd);
                    return -1;
                }
                ::close(fd);
            }
            *output_len = kSimulatedPartial;
            return 0;
        }
        }
        return 0;
    }

    const char* Name() const override { return "crash-mode-test-backend"; }

    void SetProgressCursors(std::uint32_t* completed,
                            std::uint32_t* output_len) override
    {
        progress_completed_ = completed;
        progress_output_len_ = output_len;
    }

    bool SetLoopDevicesUsedMaskCursor(std::uint32_t* cursor) override
    {
        loop_devices_used_mask_cursor_ = cursor;
        if (cursor != nullptr) {
            loop_devices_used_mask_ = 0;
        }
        return true;
    }

    std::uint32_t TakeLoopDevicesUsedMask() override
    {
        const std::uint32_t mask = loop_devices_used_mask_;
        loop_devices_used_mask_ = 0;
        return mask;
    }

    refuzz::worker::RuntimeFailure RuntimeFailureState() const override
    {
        return runtime_failure_;
    }

private:
    CrashMode      mode_;
    std::uint32_t* progress_completed_  = nullptr;
    std::uint32_t* progress_output_len_ = nullptr;
    std::uint32_t* loop_devices_used_mask_cursor_ = nullptr;
    std::uint32_t  loop_devices_used_mask_ = 0;
    refuzz::worker::RuntimeFailure runtime_failure_ =
        refuzz::worker::RuntimeFailure::kNone;
};

void RunCase(CrashMode mode,
             const char* name,
             int expected_status,
             refuzz::worker::engine::RuntimeResultKind expected_kind,
             std::uint32_t expected_crash_signal,
             // -1 = "don't care, any non-negative"; -2 = "must be 0"; > 0 = exact
             int expected_output_len_marker,
             std::uint32_t timeout_ms = 30000,
             refuzz::worker::engine::HarnessFatalReason expected_fatal_reason =
                 refuzz::worker::engine::HarnessFatalReason::kNone)
{
    auto region = MapShared();
    CrashModeBackend backend(mode);
    refuzz::worker::ObservationBus bus;
    if (mode == CrashMode::kFdSweep) {
        bus.AddSink(std::make_unique<FdSweepObservationSink>(
            region.fd_sweep_observed));
    }
    refuzz::worker::engine::ForkingProgramExecutor executor(
        backend, bus, /*worker_id=*/0, /*proc_id=*/0, timeout_ms);

    // ChildExecuteTask 要求 input_len >= 4 + non-null buffer(防 fake 输入)。
    // 真实 input 内容不重要 — 走 backend.Execute 时 backend 拿到这块 buffer
    // 但 CrashModeBackend 忽略它。这里只是让 ChildExecuteTask 早期 sanity check 过。
    static std::uint8_t fake_input[4] = {0, 0, 0, 0};
    refuzz::worker::engine::ProgramRuntimeInput input{};
    input.input = fake_input;
    input.input_len = sizeof(fake_input);
    input.output = region.output;
    input.output_cap = kOutputBytes;
    input.crash_len_ptr = region.crash_len;
    input.progress_completed_calls = region.progress_completed;
    input.progress_output_len      = region.progress_output_len;
    input.executor_id = 1001;
    input.dispatch_gen = 7;
    input.result_page = region.result_page;
    region.result_page->executor_id = input.executor_id;
    region.result_page->dispatch_gen = input.dispatch_gen;
    __atomic_store_n(&region.result_page->loop_devices_used_mask,
                     UINT32_MAX,
                     __ATOMIC_RELEASE);
    program_result_store_state_v3(region.result_page, PROGRAM_RESULT_RUNNING);

    PublishCapture capture;
    input.publish_result = &CapturePublish;
    input.publish_result_ctx = &capture;

    refuzz::worker::engine::DoneMsg done{};
    executor.ExecuteProgram(input, &done);

    std::fprintf(stderr,
                 "[case %s] done.status=%d output_len=%u  "
                 "kind=%u crash_signal=%u loop_mask=0x%08x "
                 "(shmem progress completed=%u partial_len=%u crash_len=%u)\n",
                 name, done.status, done.output_len,
                 static_cast<unsigned>(done.result_kind),
                 done.crash_signal,
                 done.loop_devices_used_mask,
                 __atomic_load_n(region.progress_completed, __ATOMIC_ACQUIRE),
                 __atomic_load_n(region.progress_output_len, __ATOMIC_ACQUIRE),
                 __atomic_load_n(region.crash_len, __ATOMIC_ACQUIRE));

    if (done.status != expected_status) {
        std::fprintf(stderr, "FAIL [%s]: status expected=%d got=%d\n",
                     name, expected_status, done.status);
        UnmapShared(region);
        std::abort();
    }
    if (done.result_kind != expected_kind) {
        std::fprintf(stderr, "FAIL [%s]: result_kind expected=%u got=%u\n",
                     name,
                     static_cast<unsigned>(expected_kind),
                     static_cast<unsigned>(done.result_kind));
        UnmapShared(region);
        std::abort();
    }
    if (done.crash_signal != expected_crash_signal) {
        std::fprintf(stderr, "FAIL [%s]: crash_signal expected=%u got=%u\n",
                     name, expected_crash_signal, done.crash_signal);
        UnmapShared(region);
        std::abort();
    }
    if (done.fatal_reason != expected_fatal_reason) {
        std::fprintf(stderr, "FAIL [%s]: fatal_reason expected=%u got=%u\n",
                     name,
                     static_cast<unsigned>(expected_fatal_reason),
                     static_cast<unsigned>(done.fatal_reason));
        UnmapShared(region);
        std::abort();
    }
    if (done.loop_devices_used_mask != kPublishedLoopMask) {
        std::fprintf(stderr,
                     "FAIL [%s]: loop mask expected=0x%08x got=0x%08x\n",
                     name, kPublishedLoopMask, done.loop_devices_used_mask);
        UnmapShared(region);
        std::abort();
    }
    if (expected_output_len_marker == -2) {
        // must be 0
        if (done.output_len != 0) {
            std::fprintf(stderr,
                         "FAIL [%s]: output_len expected=0 got=%u "
                         "(partial 救回 leaked into crash/abnormal path!)\n",
                         name, done.output_len);
            UnmapShared(region);
            std::abort();
        }
    } else if (expected_output_len_marker > 0) {
        if (static_cast<int>(done.output_len) != expected_output_len_marker) {
            std::fprintf(stderr, "FAIL [%s]: output_len expected=%d got=%u\n",
                         name, expected_output_len_marker, done.output_len);
            UnmapShared(region);
            std::abort();
        }
    }
    // expected_output_len_marker == -1: don't check

    if (mode == CrashMode::kHangAfterProgress &&
        (__atomic_load_n(region.progress_completed, __ATOMIC_ACQUIRE) != 2 ||
         __atomic_load_n(region.progress_output_len, __ATOMIC_ACQUIRE) != 64)) {
        std::fprintf(stderr,
                     "FAIL [%s]: timeout case did not publish partial progress\n",
                     name);
        UnmapShared(region);
        std::abort();
    }
    if (mode == CrashMode::kFdSweep &&
        __atomic_load_n(region.fd_sweep_observed, __ATOMIC_ACQUIRE) != 1u) {
        std::fprintf(stderr,
                     "FAIL [%s]: fd %d was still open at SessionEnd\n",
                     name, kFdSweepProbe);
        UnmapShared(region);
        std::abort();
    }

    // [early-publish] committed results (clean exit / harness-fatal-from-child)
    // publish through the hook exactly once, before reap; the delivered DoneMsg
    // must carry the same functional result the post-reap out_done ended up
    // with. Uncommitted results (real crash / SIGKILL / _exit(N) / hang) never
    // commit the page, so the hook must stay silent — production sends those via
    // the loop fallback after the post-reap waitpid classification.
    const bool expect_committed =
        mode == CrashMode::kNormal || mode == CrashMode::kKcovFatal ||
        mode == CrashMode::kProcessSetup || mode == CrashMode::kFdSweep;
    if (expect_committed) {
        if (capture.count != 1) {
            std::fprintf(stderr,
                         "FAIL [%s]: early-publish hook fired %d times, want 1\n",
                         name, capture.count);
            UnmapShared(region);
            std::abort();
        }
        if (capture.last.status != done.status ||
            capture.last.output_len != done.output_len ||
            capture.last.result_kind != done.result_kind ||
            capture.last.crash_signal != done.crash_signal ||
            capture.last.fatal_reason != done.fatal_reason ||
            capture.last.loop_devices_used_mask !=
                done.loop_devices_used_mask) {
            std::fprintf(stderr,
                         "FAIL [%s]: early-published DoneMsg diverged from "
                         "out_done (status %d/%d len %u/%u kind %u/%u sig %u/%u "
                         "fatal %u/%u mask 0x%08x/0x%08x)\n",
                         name, capture.last.status, done.status,
                         capture.last.output_len, done.output_len,
                         static_cast<unsigned>(capture.last.result_kind),
                         static_cast<unsigned>(done.result_kind),
                         capture.last.crash_signal, done.crash_signal,
                         static_cast<unsigned>(capture.last.fatal_reason),
                         static_cast<unsigned>(done.fatal_reason),
                         capture.last.loop_devices_used_mask,
                         done.loop_devices_used_mask);
            UnmapShared(region);
            std::abort();
        }
    } else if (capture.count != 0) {
        std::fprintf(stderr,
                     "FAIL [%s]: early-publish hook fired %d times for an "
                     "uncommitted result, want 0\n",
                     name, capture.count);
        UnmapShared(region);
        std::abort();
    }

    UnmapShared(region);
}

}  // namespace

int main()
{
    // This host test can observe the host's user-session FUSE mounts. The
    // shared AbortFuseConnections gate keeps timeout cleanup from aborting
    // those unrelated connections; production fuzz VMs leave it unset.
    ::setenv("REFUZZ_DISABLE_STOP_FUSE_ABORT", "1", 1);
    std::fprintf(stdout, "Running forking_executor_status_test...\n");

    // ── Case 1: Normal — child commit result page → _exit(0) → status=0 ──
    // backend 写了 64 字节 output + 返 0,child 把 output_len=64 commit 到
    // result page,parent wait 后读取。fallback 没触发。
    RunCase(CrashMode::kNormal, "normal",
            /*status=*/0,
            refuzz::worker::engine::RuntimeResultKind::kNormal,
            /*crash_signal=*/0,
            /*output_len=*/64);

    // ── Case 2: SIGSEGV — kCrashed → status=-1, output_len=0 ──────────────
    // **关键**:progress cursors 写了 2/64,但分类必须是 crashed,**不能** 把
    // partial 救回当 success。这是 reviewer 之前抓到的 v2 漏洞。
    RunCase(CrashMode::kSigsegv, "sigsegv-real-crash",
            /*status=*/-1,
            refuzz::worker::engine::RuntimeResultKind::kCrash,
            /*crash_signal=*/SIGSEGV,
            /*output_len_must_be_0=*/-2);

    // ── Case 3: SIGKILL self — kKilledOrCleanExit → partial 救回 ─────────
    // progress 写了 2/64,SIGKILL 后 buffer 干净(无 handler 动过),partial
    // fallback 触发:status=0, output_len=64。对齐 syzkaller reply_execute(0)。
    RunCase(CrashMode::kSigkillSelf, "sigkill-self-partial",
            /*status=*/0,
            refuzz::worker::engine::RuntimeResultKind::kPartial,
            /*crash_signal=*/0,
            /*output_len=*/64);

    // ── Case 4: _exit(2) — kAbnormal → status=-1, no partial ─────────────
    // ── Case 4: _exit(N≠0) — 程序行为,救回 partial ───────────────────────
    // [归类修正] `exit_group(非零)` 是**被测程序自己的行为**,不是执行错误 ——
    // program-child 本层只有 _exit(0) / _exit(128+sig)(crash handler),非 crash 的
    // 非零退出码只可能来自程序自己的 exit_group(N)。buffer 没被 crash handler 动过 →
    // progress cursors 可信 → 救回 partial:status=0, output_len=64。
    // 对齐 syzkaller `WEXITSTATUS != kFailStatus → reply_execute(0)`(common.h:736-740)。
    // 曾被强判 kNoResult(丢数据 + 误报执行错误),那是 exec_error 口袋的一部分。
    RunCase(CrashMode::kExitTwo, "exit-nonzero-is-program-behavior",
            /*status=*/0,
            refuzz::worker::engine::RuntimeResultKind::kPartial,
            /*crash_signal=*/0,
            /*output_len=*/64);

    // ── Case 5: progress then watchdog — 标签 kTimeout,但数据照带 ──────────
    // [两层语义 — 标签与处理分离]
    // watchdog 用 SIGKILL 杀 child,ground truth 与 Case 3 的自 SIGKILL 完全相同
    // (WIFSIGNALED+SIGKILL,无 handler 动过 buffer)→ progress cursors 同样可信,
    // 所以**数据处理与 Case 3 完全一样**:status=0, output_len=64,不清空。
    // 但**标签不同**:kTimeout 陈述"是 program watchdog 判的超时",Case 3 是
    // kPartial"程序自己提前结束" —— 事实层不做信息压缩,超时是事实、已发布的数据
    // 也是事实,两个都上报。
    //
    // 下游 channel 按 (COMP_STATUS_TIMEOUT, ERR_TIMEOUT) 把它分流到 Completion 侧
    // (CompletionKind::kTimeout),与 kPartial 同等处理。真正的 task hang 是上一层
    // daemon watchdog(ERR_DOMAIN_WATCHDOG_TIMEOUT),那个才走 Abnormal。
    RunCase(CrashMode::kHangAfterProgress, "progress-then-timeout-keeps-data",
            /*status=*/0,
            refuzz::worker::engine::RuntimeResultKind::kTimeout,
            /*crash_signal=*/0,
            /*output_len=*/64,
            /*timeout_ms=*/250);

    RunCase(CrashMode::kKcovFatal, "kcov-harness-fatal",
            /*status=*/-1,
            refuzz::worker::engine::RuntimeResultKind::kHarnessFatal,
            /*crash_signal=*/0,
            /*output_len_must_be_0=*/-2,
            /*timeout_ms=*/30000,
            refuzz::worker::engine::HarnessFatalReason::kKcovStateInvalid);

    // setup_test 的进程级契约不能依赖 workdir。本测试的 input.workdir=nullptr，
    // 仍必须观察到 PDEATHSIG=SIGKILL 且 PGID 等于 program-child PID。
    RunCase(CrashMode::kProcessSetup, "unconditional-process-setup",
            /*status=*/0,
            refuzz::worker::engine::RuntimeResultKind::kNormal,
            /*crash_signal=*/0,
            /*output_len=*/64);

    // syzkaller closes the program ABI fd range before collecting final
    // observation feedback. The sink runs at SessionEnd and must already see
    // the backend-created low fd as closed.
    RunCase(CrashMode::kFdSweep, "fd-sweep-before-session-end",
            /*status=*/0,
            refuzz::worker::engine::RuntimeResultKind::kNormal,
            /*crash_signal=*/0,
            /*output_len=*/64);

    std::fprintf(stdout, "OK\n");
    return 0;
}

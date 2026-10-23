#pragma once

#include "worker/coverage/coverage_collector.hpp"

#include <cstddef>
#include <cstdint>

namespace refuzz::worker {

// KCOV area entry count (area_[1..N] usable; area_[0] is the kernel cursor).
// Default keeps parity with upstream syzkaller's Linux executor `kCoverSize`:
// 512 Ki entries × 8B = 4 MiB/collector on 64-bit Linux.
inline constexpr std::size_t kDefaultKcovEntries = 512u << 10;
inline constexpr std::size_t kMinKcovEntries = 1024u;
inline constexpr std::size_t kMaxKcovEntries = kDefaultKcovEntries;
// Backward-compatible name for code that needs the default/worst-case size.
inline constexpr std::size_t kKcovEntries = kDefaultKcovEntries;

// [v2 Epic 5 PR-5-B] KcovMode — KCOV ioctl mode selector.
//   kPc  : KCOV_TRACE_PC (default; PC bytes in area as N × uint64).
//   kCmp : KCOV_TRACE_CMP (Epic 5; comparison records as 4 × uint64 per record).
// Mode is per-task; KcovSink chooses based on ObservationContext.collect_comps.
enum class KcovMode : uint8_t {
    kPc  = 0,
    kCmp = 1,
};

enum class KcovChildMode : uint8_t {
    kFreshPerProgram = 0,
    kInheritedFromLoop = 1,
};

class KcovCollector : public ICoverageCollector {
public:
    // [v2 Epic 7 PR-1] explicit ownership: KcovCollector 持 fd_/area_ 资源,
    // 析构里 close + munmap (kcov_collector.cpp:74)。禁 copy/move 防止误用
    // 浅拷贝导致 double-close;同时让 KcovSink 安全把它放进
    // std::vector<std::unique_ptr<KcovCollector>> (vector grow 时移的是
    // unique_ptr,对象地址稳定)。
    explicit KcovCollector(std::size_t entry_count = kDefaultKcovEntries,
                           bool delay_mmap = false,
                           KcovChildMode child_mode =
                               KcovChildMode::kFreshPerProgram);
    ~KcovCollector() override;
    KcovCollector(const KcovCollector&) = delete;
    KcovCollector& operator=(const KcovCollector&) = delete;
    KcovCollector(KcovCollector&&) = delete;
    KcovCollector& operator=(KcovCollector&&) = delete;

    bool Init() override;

    bool Enabled() const override;
    // Kind() returns kCoverageKcov (PC) by default. Cmp-mode wire region is
    // emitted by KcovSink via AppendKcovCmpFeedbackRaw, NOT through this
    // collector's Kind/SnapshotFeedback path — that path stays PC-only so
    // SnapshotForCrash (async-signal-safe) doesn't need to branch on mode.
    refuzz::proto::FeedbackKind Kind() const override;

    // [v1 Begin() — ROLLBACK: keep override + remove v2 Begin(KcovMode)]
    void Begin() override;
    // [v2 Epic 5 PR-5-B] mode-aware Begin returns bool so callers can detect
    // a transient KCOV_ENABLE failure (e.g. KCOV_TRACE_CMP unsupported on
    // this kernel) WITHOUT poisoning the fd: enabled_ stays true, the fd
    // is still good for the next PC-mode Begin. KcovSink uses the return
    // value to choose between "this session collects" vs "this session
    // emits empty", but never tears the collector down.
    [[nodiscard]] bool Begin(KcovMode mode);

    void End(std::vector<uint64_t>* out_entries) override;
    // [v2 Epic 5 PR-5-B] EndAsCmp drains area as cmp records (4 × uint64
    // per record). Caller must have entered cmp mode via Begin(kCmp);
    // calling on a PC-mode collector returns empty.
    void EndAsCmp(std::vector<uint64_t>* out_records);

    uint32_t SnapshotFeedback(uint8_t* out, uint32_t out_cap) const override;
    size_t BufferBytes() const override;

    // Child fd-table hygiene: syzkaller exec-wire programs assume low fds
    // (3, 4, 5, ...) are available to the fuzz program. ChildMain calls this
    // after Init() opens /dev/kcov and before the first task executes.
    bool RemapFdAtOrAbove(int* next_fd);
    int InternalFd() const { return fd_; }

    // Diagnostic accessor for tests.
    KcovMode CurrentMode() const { return current_mode_; }
    KcovChildMode ChildMode() const { return child_mode_; }
    std::size_t EntryCount() const { return entry_count_; }
    bool NeedsReopenForTesting() const { return needs_reopen_; }

    // Per-call KCOV collection — PC mode only.
    //
    // This follows upstream syzkaller's boundary model:
    //   Begin(kPc) enables KCOV once for this task/thread.
    //   ResetForCall() clears area_[0] immediately before one syscall dispatch.
    //   CollectForCall() reads area_[1..area_[0]] immediately after dispatch.
    //   End(out) disables KCOV and does not return a program-level PC packet.
    //
    // CMP mode remains task-level for now because hints consume cmp records as
    // session feedback.

    // 开/结束 per-call session。PC mode 下生效;CMP mode no-op。
    void BeginCallSession();
    void EndCallSession();

    // ResetForCall: clear the KCOV write cursor for the next syscall. PC mode
    // + session active + enabled 才返回 true。
    bool ResetForCall();

    // CollectForCall: read the current syscall's area_[1..area_[0]] into *out,
    // then update per_call_cursor_ as a defensive duplicate-collect guard.
    // CMP mode / 非 session active / 非 enabled 时 *out 保持空,no-op。
    void CollectForCall(std::vector<uint64_t>* out);

    // [当前版本 zero-copy-pc-cov] CollectForCallView:跟 CollectForCall 同语义
    // (advance per_call_cursor_),但不分配 vector 也不 push_back,把当前
    // syscall 的 PC 范围 [area_ + start + 1, area_ + end + 1) 作 view 返回。
    //
    // 调用者承诺:在主线程把 view 内容 memcpy 到 output 之前,worker thread
    // 不会跑下个 syscall(state machine kDone → 主 ack → kIdle → ScheduleCall
    // 才下一个,期间 area_ 不被 write)。
    //
    // PerCallCovView{nullptr,0} 表示 CMP mode / 非 session active / 非 enabled。
    struct PerCallCovView {
        const uint64_t* data = nullptr;
        uint32_t        size = 0;
    };
    PerCallCovView CollectForCallView();

    // [threaded end-drain partial coverage] Main-thread snapshot of the current
    // syscall's KCOV window for a call STILL executing in its worker thread at
    // program-end drain. Mirrors upstream executor.cc:1149-1150
    // `cover_collect(&th->cov)` on a thread that is still `executing`: the
    // kernel keeps appending PCs to the (shared-mmap) area as the blocked
    // syscall runs in the background, and we read the prefix accumulated so far.
    //
    // Unlike CollectForCallView this is const and does NOT advance
    // per_call_cursor_: the owning worker thread is blocked inside Dispatch and
    // may still run CollectForCallView itself if it eventually returns, so the
    // drain reader must not mutate shared per-call state. Reading area_[0] then
    // area_[1..count] is a benign race (the kernel bumps area_[0] only after
    // writing the PC at that slot), identical to upstream's cross-thread
    // cover_collect. Returns {nullptr,0} when not in an active PC per-call
    // session. Window is [per_call_cursor_ .. area_[0]] so a call the worker
    // never CollectForCallView'd yields its full coverage-so-far.
    PerCallCovView SnapshotPerCallView() const;

    // Test accessor.
    bool CallSessionActive() const { return per_call_session_; }

    // Legacy fresh mode child reset. Production inherited mode does not call
    // this from atfork and keeps the loop mapping/fd intact.
    void ResetMappingForChild();

private:
    bool EnsureMapped();
    // [shared-kcov fix] Replace the (post-fork inherited) struct kcov on fd_
    // with a fresh PRIVATE one, keeping the same fd number. KCOV is single
    // owner; concurrent orphan children sharing the worker-template kcov
    // contend (KCOV_ENABLE -> EINVAL). Driven lazily from EnsureMapped() when
    // needs_reopen_ is set, and as EINVAL recovery in Begin().
    bool ReopenFreshKcov();

    std::size_t entry_count_ = kDefaultKcovEntries;
    int fd_ = -1;
    uint64_t* area_ = nullptr;
    // [shared-kcov fix] Set by ResetMappingForChild(); the next EnsureMapped()
    // swaps the inherited shared kcov for a private one before mmapping.
    bool needs_reopen_ = false;
    bool delay_mmap_ = false;
    KcovChildMode child_mode_ = KcovChildMode::kFreshPerProgram;
    bool enabled_ = false;
    // [v2 Epic 5 PR-5-B] tracks mode set at Begin; consumed by End/EndAsCmp
    // and (informally) by SnapshotFeedback. Default kPc matches v1 behavior.
    KcovMode current_mode_ = KcovMode::kPc;

    // [v2 batch 3 PR-X — 2nd-pass review fix] 跟踪 Begin/EndAsCmp 是否已 KCOV_ENABLE
    // 成功(true 表示当前 KCOV 内核状态 enabled,可读 area_)。Begin 入口先清零,
    // 成功路径置 true;End/EndAsCmp 成功 KCOV_DISABLE 后清零。
    //
    // 用途(invariant 收紧):BeginCallSession guard 多一层防御 — 即使
    // current_mode_ 是上次 kPc 残留(本次 Begin(kCmp) 失败未更新),
    // begin_succeeded_=false 阻止 per_call_session_ 错误置 true,也避免在
    // KCOV_ENABLE 失败后错误清 area_[0] 或读取旧 mmap 内容。
    bool begin_succeeded_ = false;

    // [v2 batch 3 PR-X — review revise] per-call session state(PC mode only)。
    bool per_call_session_ = false;
    // Current syscall window cursor. ResetForCall sets it to 0 after clearing
    // area_[0]; CollectForCall advances it to the observed count so accidental
    // repeated CollectForCall calls do not duplicate entries.
    uint64_t per_call_cursor_ = 0;
};

} // namespace refuzz::worker

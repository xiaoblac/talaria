#include "worker/coverage/kcov_collector.hpp"

#include "refuzz/proto_wire/feedback_wire.hpp"
#include "worker/log/log_macros.hpp"

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef KCOV_INIT_TRACE
#define KCOV_INIT_TRACE  _IOR('c', 1, unsigned long)
#define KCOV_ENABLE      _IO('c', 100)
#define KCOV_DISABLE     _IO('c', 101)
#define KCOV_TRACE_PC    0
#endif
// [v2 Epic 5 PR-5-B] KCOV_TRACE_CMP — kcov.h kernel constant; emit cmp records.
#ifndef KCOV_TRACE_CMP
#define KCOV_TRACE_CMP   1
#endif
#define REFUZZ_HAVE_KCOV 1

#include <cerrno>
#include <cstdio>
#include <cstring>

namespace refuzz::worker {

namespace {

std::size_t NormalizeKcovEntries(std::size_t entries)
{
    if (entries < kMinKcovEntries) {
        return kMinKcovEntries;
    }
    if (entries > kMaxKcovEntries) {
        return kMaxKcovEntries;
    }
    return entries;
}

} // namespace

KcovCollector::KcovCollector(std::size_t entry_count,
                             bool delay_mmap,
                             KcovChildMode child_mode)
    : entry_count_(NormalizeKcovEntries(entry_count))
    , delay_mmap_(delay_mmap)
    , child_mode_(child_mode)
{}

bool KcovCollector::Init()
{
#if REFUZZ_HAVE_KCOV
    fd_ = open("/sys/kernel/debug/kcov", O_RDWR);
    if (fd_ < 0) {
        ::refuzz::worker::log::WorkerLog("[Worker] kcov open failed: %s (errno=%d)\n",
                                         strerror(errno),
                                         errno);
        return false;
    }
    if (ioctl(fd_, KCOV_INIT_TRACE, entry_count_) < 0) {
        ::refuzz::worker::log::WorkerLog("[Worker] kcov KCOV_INIT_TRACE failed: %s (errno=%d)\n",
                                         strerror(errno),
                                         errno);
        close(fd_);
        fd_ = -1;
        return false;
    }
    if (!delay_mmap_) {
        if (!EnsureMapped()) {
            close(fd_);
            fd_ = -1;
            return false;
        }
    }
    enabled_ = true;
    return true;
#else
    return false;
#endif
}

KcovCollector::~KcovCollector()
{
#if REFUZZ_HAVE_KCOV
    if (area_ != nullptr) {
        munmap(area_, entry_count_ * sizeof(uint64_t));
    }
    if (fd_ >= 0) {
        close(fd_);
    }
#endif
}

bool KcovCollector::ReopenFreshKcov()
{
#if REFUZZ_HAVE_KCOV
    if (child_mode_ != KcovChildMode::kFreshPerProgram) {
        return false;
    }
    // Swap whatever struct kcov this fd currently refers to (the shared
    // worker-template one inherited via copy_files after fork, or a poisoned
    // stale session) for a brand-new PRIVATE struct kcov, KEEPING the same fd
    // number so callers / the reserved-fd layout are unchanged. KCOV is a
    // single-owner resource; without this, every concurrent orphan program
    // child shares one struct kcov and their [enable..disable] intervals
    // contend -> KCOV_ENABLE returns EINVAL (mode != INIT).
    if (area_ != nullptr) {
        munmap(area_, entry_count_ * sizeof(uint64_t));
        area_ = nullptr;
    }
    const int tmp = open("/sys/kernel/debug/kcov", O_RDWR);
    if (tmp < 0) {
        ::refuzz::worker::log::WorkerLog("[Worker] kcov reopen open failed: %s (errno=%d)\n",
                                         strerror(errno), errno);
        return false;
    }
    if (ioctl(tmp, KCOV_INIT_TRACE, entry_count_) < 0) {
        ::refuzz::worker::log::WorkerLog("[Worker] kcov reopen KCOV_INIT_TRACE failed: %s (errno=%d)\n",
                                         strerror(errno), errno);
        close(tmp);
        return false;
    }
    if (fd_ >= 0) {
        // dup2 atomically points fd_ at the fresh kcov and drops the inherited
        // (shared) reference this child still held.
        if (dup2(tmp, fd_) < 0) {
            ::refuzz::worker::log::WorkerLog("[Worker] kcov reopen dup2 failed: %s (errno=%d)\n",
                                             strerror(errno), errno);
            close(tmp);
            return false;
        }
        close(tmp);
    } else {
        fd_ = tmp;
    }
    return true;
#else
    return false;
#endif
}

bool KcovCollector::EnsureMapped()
{
#if REFUZZ_HAVE_KCOV
    // [shared-kcov fix] First touch in a freshly forked program child: trade the
    // inherited (shared) struct kcov for a private one. Lazy — only collectors
    // the child actually uses pay the ~tens-of-µs reopen; unused ones stay free.
    if (needs_reopen_) {
        needs_reopen_ = false;
        if (!ReopenFreshKcov()) {
            return false;
        }
    }
    if (area_ != nullptr) {
        return true;
    }
    if (fd_ < 0) {
        return false;
    }
    const size_t map_bytes = entry_count_ * sizeof(uint64_t);
    area_ = static_cast<uint64_t*>(
        mmap(nullptr, map_bytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0));
    if (area_ == MAP_FAILED) {
        ::refuzz::worker::log::WorkerLog("[Worker] kcov mmap failed: %s (errno=%d)\n",
                                         strerror(errno),
                                         errno);
        area_ = nullptr;
        return false;
    }
    // [C 方案 — fork-skip KCOV mmap] Annotate VM_DONTCOPY so dup_mmap
    // skips this VMA during program-child fork. Saves the per-PTE copy
    // cost in copy_page_range (≈ 1024 PTE × KASAN-instrumented set_ptes
    // per premapped collector — the biggest single contributor to fork
    // wall time when kcov_collector_count×premap is non-trivial).
    //
    // The trade-off: child no longer inherits the mapping, so its area_
    // pointer points at unmapped memory and would SIGSEGV on first read.
    // Pair this with KcovSink::OnChildPostFork (pthread_atfork child
    // handler) that resets area_ to nullptr, so the next EnsureMapped()
    // — driven by Begin() inside the worker thread — does a fresh mmap
    // in the child.
    if (child_mode_ == KcovChildMode::kFreshPerProgram &&
        madvise(area_, map_bytes, MADV_DONTFORK) != 0) {
        // Non-fatal: parent mapping still works, and the only cost is
        // that child will inherit it (i.e. we lose the optimization for
        // this collector). Log once for visibility.
        ::refuzz::worker::log::WorkerLog(
            "[Worker] kcov madvise(MADV_DONTFORK) failed: %s (errno=%d) "
            "— child will inherit this mapping instead of remapping\n",
            strerror(errno), errno);
    }
    return true;
#else
    return false;
#endif
}

void KcovCollector::ResetMappingForChild()
{
#if REFUZZ_HAVE_KCOV
    if (child_mode_ == KcovChildMode::kFreshPerProgram) {
        area_ = nullptr;
        needs_reopen_ = true;
    } else {
        needs_reopen_ = false;
    }
    // Per-call session and KCOV_ENABLE state are per-thread in the kernel;
    // the child fork already loses them implicitly. Clear our mirrors so
    // Begin() / BeginCallSession() guards take the fresh path.
    per_call_session_ = false;
    per_call_cursor_  = 0;
    begin_succeeded_  = false;
#endif
}

bool KcovCollector::Enabled() const
{
    return enabled_;
}

bool KcovCollector::RemapFdAtOrAbove(int* next_fd)
{
#if REFUZZ_HAVE_KCOV
    if (next_fd == nullptr) {
        return false;
    }
    if (fd_ < 0) {
        return true;
    }
    if (fd_ >= *next_fd) {
        *next_fd = fd_ + 1;
        return true;
    }
    const int new_fd = ::fcntl(fd_, F_DUPFD_CLOEXEC, *next_fd);
    if (new_fd < 0) {
        return false;
    }
    ::close(fd_);
    fd_ = new_fd;
    *next_fd = new_fd + 1;
    return true;
#else
    (void)next_fd;
    return true;
#endif
}

refuzz::proto::FeedbackKind KcovCollector::Kind() const
{
    return refuzz::proto::FeedbackKind::kCoverageKcov;
}

void KcovCollector::Begin()
{
    // [v2 Epic 5 PR-5-B] forward to mode-aware overload with default kPc.
    // Discard return value: legacy callers via the ICoverageCollector vtable
    // don't have a way to surface ioctl failure; Enabled() and the next
    // End() observation are the only signal they use.
    (void)Begin(KcovMode::kPc);
}

bool KcovCollector::Begin(KcovMode mode)
{
#if REFUZZ_HAVE_KCOV
    // [v2 batch 3 PR-X — 2nd-pass review fix] 入口先清零 begin_succeeded_。
    // 失败路径 return false 时 begin_succeeded_ 保持 false,后续 BeginCallSession
    // guard 拒绝 per-call session 启动,避免 current_mode_ 残留误启 per-call。
    begin_succeeded_ = false;
    if (!enabled_) {
        return false;
    }
    if (!EnsureMapped()) {
        return false;
    }
    area_[0] = 0;
    const unsigned long kcov_mode =
        (mode == KcovMode::kCmp) ? static_cast<unsigned long>(KCOV_TRACE_CMP)
                                 : static_cast<unsigned long>(KCOV_TRACE_PC);
    if (ioctl(fd_, KCOV_ENABLE, kcov_mode) < 0) {
        // [shared-kcov fix — defensive belt] EINVAL == kcov->mode != INIT: a
        // stale/shared session poisoned this fd (an orphan child still owning
        // the worker-template struct kcov this fd was inherited from). The main
        // fix (ReopenFreshKcov on first post-fork EnsureMapped) makes it rare,
        // but retry ONCE on a fresh private kcov — this also independently
        // rescues the skip_cleanup permanent-stuck case.
        if (child_mode_ == KcovChildMode::kFreshPerProgram &&
            errno == EINVAL && ReopenFreshKcov() && EnsureMapped()) {
            area_[0] = 0;
            if (ioctl(fd_, KCOV_ENABLE, kcov_mode) == 0) {
                current_mode_ = mode;
                begin_succeeded_ = true;
                return true;
            }
        }
        // [v2 Epic 5 PR-5-B fix #3] Transient KCOV_ENABLE failure (e.g. the
        // kernel doesn't support KCOV_TRACE_CMP) MUST NOT poison enabled_ —
        // doing so kills PC coverage on every subsequent task too. The fd
        // is still good; current_mode_ stays at its previous value and the
        // caller (KcovSink) uses our return value to mark this session as
        // not-collecting.
        ::refuzz::worker::log::WorkerLog(
            "[KCOV] Begin: KCOV_ENABLE failed fd=%d mode=%lu errno=%d (%s)\n",
            fd_, kcov_mode, errno, strerror(errno));
        return false;
    }
    current_mode_ = mode;
    begin_succeeded_ = true;  // [v2 2nd-pass review fix] 仅 ENABLE 成功才置位
    return true;
#else
    (void)mode;
    return false;
#endif
}

void KcovCollector::End(std::vector<uint64_t>* out_entries)
{
#if REFUZZ_HAVE_KCOV
    if (!enabled_ || out_entries == nullptr) {
        return;
    }
    if (ioctl(fd_, KCOV_DISABLE, 0) < 0) {
        ::refuzz::worker::log::WorkerLog(
            "[KCOV] End: KCOV_DISABLE failed fd=%d errno=%d (%s)\n",
            fd_, errno, strerror(errno));
        enabled_ = false;
        // [v2 review revise] tear-down per-call state on KCOV_DISABLE failure 也要做,
        // 否则下次 Begin/BeginCallSession 拿到陈旧 cursor。
        // [v2 2nd-pass review fix] 同时 clear begin_succeeded_ — KCOV state 已坏。
        per_call_session_ = false;
        per_call_cursor_  = 0;
        begin_succeeded_  = false;
        return;
    }
    // PC coverage is returned per syscall through SyzExecResult's coverage
    // tail. Task end only disables KCOV; it must not append a second
    // program-level kCoverageKcov packet.
    if (current_mode_ == KcovMode::kPc) {
        out_entries->clear();
        area_[0] = 0;
        per_call_session_ = false;
        per_call_cursor_  = 0;
        begin_succeeded_  = false;
        return;
    }

    uint64_t n = area_[0];
    if (n > entry_count_ - 1) {
        n = entry_count_ - 1;
    }

    out_entries->clear();
    out_entries->reserve(static_cast<size_t>(n));
    for (uint64_t i = 0; i < n; ++i) {
        out_entries->push_back(area_[i + 1]);
    }

    // [v2 review revise] tear-down per-call state(下次 BeginCallSession 重置)。
    // [v2 2nd-pass review fix] 同时 clear begin_succeeded_ — KCOV 已 DISABLE。
    per_call_session_ = false;
    per_call_cursor_  = 0;
    begin_succeeded_  = false;
#else
    (void)out_entries;
#endif
}

// Per-call API — PC mode only。CMP mode 全 no-op。
// ResetForCall clears the KCOV area cursor before each syscall, and
// CollectForCall reads the current syscall's area_[1..area_[0]] after dispatch.
void KcovCollector::BeginCallSession()
{
#if REFUZZ_HAVE_KCOV
    // [v2 2nd-pass review fix] guard 多 begin_succeeded_:即使 current_mode_ 是
    // 上次 kPc 残留(本次 Begin(kCmp) 失败未更新 current_mode_),
    // begin_succeeded_=false 阻止 per_call_session_ 错置 true,避免 driver 在
    // KCOV ENABLE 状态不一致时清 area_[0] 或读取旧 mmap 内容。
    if (!enabled_ || !begin_succeeded_ || current_mode_ != KcovMode::kPc) {
        return;
    }
    per_call_session_ = true;
    // Begin() already zeroed area_[0]; ResetForCall will also zero it before
    // every syscall boundary.
    per_call_cursor_ = 0;
#endif
}

void KcovCollector::EndCallSession()
{
#if REFUZZ_HAVE_KCOV
    // 显式 end (eg. driver tear-down 路径);End() 也会自动 clear。
    per_call_session_ = false;
    per_call_cursor_  = 0;
#endif
}

bool KcovCollector::ResetForCall()
{
#if REFUZZ_HAVE_KCOV
    if (!enabled_ || area_ == nullptr || !begin_succeeded_ || !per_call_session_ ||
        current_mode_ != KcovMode::kPc) {
        return false;
    }

    // Upstream syzkaller resets KCOV at syscall boundaries. For PC mode,
    // writing area_[0]=0 is the cheap reset path used by older kernels too.
    area_[0] = 0;
    per_call_cursor_ = 0;
    return true;
#else
    return false;
#endif
}

void KcovCollector::CollectForCall(std::vector<uint64_t>* out)
{
#if REFUZZ_HAVE_KCOV
    if (out == nullptr) return;
    out->clear();
    if (!enabled_ || area_ == nullptr || !begin_succeeded_ || !per_call_session_ ||
        current_mode_ != KcovMode::kPc) {
        // CMP mode / 非 session active / 非 enabled — no-op。
        return;
    }

    // area_[0] was reset immediately before this syscall, so the current
    // count is already the per-call coverage length.
    uint64_t now = area_[0];
    if (now > entry_count_ - 1) {
        now = entry_count_ - 1;
    }
    if (now <= per_call_cursor_) {
        // 没新 entry — 可能 dispatch 没产生 cov(ENOSYS / KCOV 满 / 早返)。
        return;
    }
    const uint64_t start = per_call_cursor_;  // exclusive; normally 0 after ResetForCall
    const uint64_t end   = now;
    out->reserve(static_cast<size_t>(end - start));
    for (uint64_t i = start; i < end; ++i) {
        out->push_back(area_[i + 1]);
    }
    per_call_cursor_ = end;
#else
    (void)out;
#endif
}

KcovCollector::PerCallCovView KcovCollector::CollectForCallView()
{
#if REFUZZ_HAVE_KCOV
    if (!enabled_ || area_ == nullptr || !begin_succeeded_ || !per_call_session_ ||
        current_mode_ != KcovMode::kPc) {
        // CMP mode / 非 session active / 非 enabled — empty view。
        return PerCallCovView{};
    }
    uint64_t now = area_[0];
    if (now > entry_count_ - 1) {
        now = entry_count_ - 1;
    }
    if (now <= per_call_cursor_) {
        // 没新 entry — view 空,cursor 不动。
        return PerCallCovView{};
    }
    const uint64_t start = per_call_cursor_;
    const uint64_t end   = now;
    per_call_cursor_ = end;
    // area_ + start + 1 因 area_[0] 是 kernel cursor,实际 PC 从 area_[1] 起算。
    return PerCallCovView{
        /*data=*/area_ + start + 1,
        /*size=*/static_cast<uint32_t>(end - start),
    };
#else
    return PerCallCovView{};
#endif
}

KcovCollector::PerCallCovView KcovCollector::SnapshotPerCallView() const
{
#if REFUZZ_HAVE_KCOV
    if (!enabled_ || area_ == nullptr || !begin_succeeded_ || !per_call_session_ ||
        current_mode_ != KcovMode::kPc) {
        // CMP mode / 非 session active / 非 enabled — empty view。
        return PerCallCovView{};
    }
    // Read the kernel cursor once. The worker thread owning this collector is
    // blocked inside its syscall; the kernel keeps bumping area_[0] as more PCs
    // land. We snapshot the prefix [per_call_cursor_ .. now] — const, so we do
    // NOT advance per_call_cursor_ (see header: the worker may still consume it).
    uint64_t now = area_[0];
    if (now > entry_count_ - 1) {
        now = entry_count_ - 1;
    }
    if (now <= per_call_cursor_) {
        // 还没有新 entry(syscall 仍未产生 PC,或刚 ResetForCall)— view 空。
        return PerCallCovView{};
    }
    const uint64_t start = per_call_cursor_;
    const uint64_t end   = now;
    return PerCallCovView{
        /*data=*/area_ + start + 1,
        /*size=*/static_cast<uint32_t>(end - start),
    };
#else
    return PerCallCovView{};
#endif
}

// [v2 Epic 5 PR-5-B] EndAsCmp — drains area as cmp records.
//
// Wire layout in kcov_area when KCOV_TRACE_CMP is active (per
// Documentation/dev-tools/kcov.rst):
//   area[0]                  = number of records
//   area[1..1+4*record_count] = records, 4 × uint64 each (type, arg1, arg2, pc)
//
// `out_records` receives the records as a flat uint64 sequence (4 × record_count
// uint64s). KcovSink::PackFeedback hands it to AppendKcovCmpFeedbackRaw which
// expects record count.
//
// Capacity guard: entry_count-1 uint64 slots are usable; max records = (entry_count-1)/4.
void KcovCollector::EndAsCmp(std::vector<uint64_t>* out_records)
{
#if REFUZZ_HAVE_KCOV
    if (!enabled_ || out_records == nullptr) {
        return;
    }
    if (ioctl(fd_, KCOV_DISABLE, 0) < 0) {
        enabled_ = false;
        // [v2 2nd-pass review fix] KCOV state 已坏 — 同步 clear begin_succeeded_。
        begin_succeeded_ = false;
        return;
    }
    uint64_t record_count = area_[0];
    constexpr uint64_t kUint64sPerRecord = 4;
    const uint64_t max_records = (entry_count_ - 1) / kUint64sPerRecord;
    if (record_count > max_records) {
        record_count = max_records;
    }

    const uint64_t total_uint64s = record_count * kUint64sPerRecord;
    out_records->clear();
    out_records->reserve(static_cast<size_t>(total_uint64s));
    for (uint64_t i = 0; i < total_uint64s; ++i) {
        out_records->push_back(area_[i + 1]);
    }
    // [v2 2nd-pass review fix] KCOV DISABLE 成功 — clear begin_succeeded_,
    // 与 End() 的 tear-down 行为对齐。
    begin_succeeded_ = false;
#else
    (void)out_records;
#endif
}

size_t KcovCollector::BufferBytes() const
{
    // Delayed collectors may not have mmap'ed yet in the daemon fork
    // template, but the program child can mmap on first Begin(). Keep this as
    // the declared worst-case VA budget for sandbox RLIMIT_AS sizing.
    return entry_count_ * sizeof(uint64_t);
}

uint32_t KcovCollector::SnapshotFeedback(uint8_t* out, uint32_t out_cap) const
{
#if REFUZZ_HAVE_KCOV
    if (!enabled_ || area_ == nullptr || out == nullptr || out_cap <= sizeof(refuzz::proto::WorkerFeedbackHeader)) {
        return 0;
    }

    // [v2 Epic 5 PR-5-B] dispatch on mode. Crash-time snapshot must emit the
    // wire kind matching what the host expects. AppendXxxRaw helpers are
    // async-signal-safe (memcpy + header write, no allocation, no locks).
    //
    // [v2 Epic 5 PR-5-B fix #2] area_[0] semantics differ by mode:
    //   PC mode  → uint64 entry count;       max = entry_count_ - 1
    //   CMP mode → record count (4 × uint64); max = (entry_count_ - 1) / 4
    // Clamp by mode-correct upper bound BEFORE downstream sizing, mirror
    // EndAsCmp's record cap.
    constexpr uint64_t kUint64sPerCmpRecord = 4;
    const uint64_t kArea_max_records = (entry_count_ - 1) / kUint64sPerCmpRecord;
    uint64_t raw_count = area_[0];
    if (current_mode_ == KcovMode::kCmp) {
        if (raw_count > kArea_max_records) {
            raw_count = kArea_max_records;
        }
    } else {
        if (raw_count > entry_count_ - 1) {
            raw_count = entry_count_ - 1;
        }
    }
    if (raw_count == 0) {
        return 0;
    }

    uint32_t out_len = 0;
    if (current_mode_ == KcovMode::kCmp) {
        uint64_t records = raw_count;
        const uint64_t max_uint64s_for_records =
            (out_cap - sizeof(refuzz::proto::WorkerFeedbackHeader)) / sizeof(uint64_t);
        const uint64_t max_records = max_uint64s_for_records / kUint64sPerCmpRecord;
        if (records > max_records) {
            records = max_records;
        }
        if (records == 0) {
            return 0;
        }
        const auto status = AppendKcovCmpFeedbackRaw(
            out,
            out_cap,
            &out_len,
            area_ + 1,
            static_cast<uint32_t>(records));
        return status == FeedbackAppendStatus::kOk ? out_len : 0;
    }

    // PC mode (kPc): each kcov entry is a single PC uint64.
    uint64_t n = raw_count;
    const size_t max_cov_count =
        (out_cap - sizeof(refuzz::proto::WorkerFeedbackHeader)) / sizeof(uint64_t);
    if (n > max_cov_count) {
        n = max_cov_count;
    }
    if (n == 0) {
        return 0;
    }
    const auto status = AppendCoverageFeedbackRaw(
        out,
        out_cap,
        &out_len,
        Kind(),
        area_ + 1,
        static_cast<uint32_t>(n));
    return status == FeedbackAppendStatus::kOk ? out_len : 0;
#else
    (void)out;
    (void)out_cap;
    return 0;
#endif
}

} // namespace refuzz::worker

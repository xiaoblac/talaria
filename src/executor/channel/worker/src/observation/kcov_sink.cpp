// Copyright 2026 reFuzz project author -------youngkk.
//
// KcovSink 实现：薄壳,按事件驱动 KcovCollector。
// R2 引入。

#include "worker/observation/kcov_sink.hpp"

#include "worker/log/log_macros.hpp"
#include "worker/perf/worker_perf.hpp"

#include <algorithm>
#include <iterator>
#include <mutex>
#include <unordered_set>

#include <pthread.h>
#include <sched.h>     // sched_yield — remote-kcov async settle window
#include <ctime>       // nanosleep
#include <cstdlib>     // getenv / strtol

namespace refuzz::worker {

// Legacy fresh-per-program registry and one-time pthread_atfork dispatcher.
//
// Why a registry: pthread_atfork takes plain C function pointers, no
// captures. The child handler iterates every live KcovSink and calls
// OnChildPostFork() so all KcovCollector area_ pointers get nulled
// before the child runs any KCOV-touching code (Begin → EnsureMapped
// will re-mmap on demand).
//
// Only kFreshPerProgram sinks register. Production exec domains use
// kInheritedFromLoop and never register a handler, so program fork does not
// enter this registry or acquire its mutex.
//
// Multi-thread safety: the worker is single-threaded around fork()
// (pthread pool is lazy in the child), so the registry mutex is only
// for paranoia + tests that instantiate KcovSink off the main thread.
namespace {

std::mutex& AtForkRegistryMutex()
{
    static std::mutex m;
    return m;
}

std::unordered_set<KcovSink*>& AtForkRegistry()
{
    static std::unordered_set<KcovSink*> s;
    return s;
}

void AtForkChildHandler()
{
    // Async-signal-safe-ish: we hold no kernel-side mutex, and the only
    // mutation is `area_ = nullptr` per collector. mmap/munmap not done
    // here — pushed to next Begin() in the child.
    std::lock_guard<std::mutex> lk(AtForkRegistryMutex());
    for (KcovSink* sink : AtForkRegistry()) {
        sink->OnChildPostFork();
    }
}

void RegisterAtForkOnce()
{
    static std::once_flag once;
    std::call_once(once, [] {
        // prepare = nullptr (no parent locks to release): fork-handler
        // contract is "called once per process lifetime"; reFuzz worker
        // forks frequently, so call_once is the appropriate gate.
        pthread_atfork(nullptr, nullptr, &AtForkChildHandler);
    });
}

} // namespace

// [v2 Epic 7 PR-1 — review fix + PR-4] 在 ctor 里把 size=N 池建好,Init()
// 只负责触发底层 fd/mmap 打开。理由:ChildMain 在 bus.InitAll() 之前已经
// 装好 crash handlers,SnapshotForCrash 路径会迭代 collectors_;如果让
// Init() 还在 emplace_back,那段窗口里 signal 进来可能观测到半构造的
// vector。提前在 ctor 把 pool 建好则 vector 在 KcovSink 存在的整个生命
// 周期内结构稳定,Init() 退化成纯"打开 collector 资源"。
//
    // [v2 Epic 7 PR-4] thread_count 由 profile 传入。N==1 时行为与 PR-1
    // 完全等价;N>1 时按配置把实际 collector 槽位裁剪到最多
    // collector_count(profile 提供,默认 8)。
    // [当前版本 threaded-kcov-parity] driver 不再把 logical pool 钳到 slot
    // 数;KernelThreadPool::ScheduleCall 会拒绝 tid >= provider->ThreadCount()
    // 的 coverage-required call,对齐 syzkaller delayed-KCOV fail path。
KcovSink::KcovSink(int thread_count, std::size_t kcov_entries,
                   int collector_count_in, int premap_count_in,
                   uint32_t extra_instance,
                   KcovChildMode child_mode)
{
    if (thread_count < 1) {
        thread_count = 1;
    }
    if (collector_count_in <= 0) {
        collector_count_in = kDefaultThreadedKcovCollectorCount;
    }
    if (premap_count_in < 0) {
        premap_count_in = kDefaultThreadedKcovPremapCount;
    }
    if (premap_count_in > collector_count_in) {
        premap_count_in = collector_count_in;
    }
    const int collector_count = std::min(thread_count, collector_count_in);
    const bool threaded = thread_count > 1;
    threaded_ = threaded;
    extra_instance_ = extra_instance;
    child_mode_ = child_mode;
    collectors_.reserve(static_cast<size_t>(collector_count));
    for (int i = 0; i < collector_count; ++i) {
        const bool delay_mmap = threaded && i >= premap_count_in;
        collectors_.emplace_back(
            std::make_unique<KcovCollector>(kcov_entries, delay_mmap,
                                            child_mode_));
    }

    // [remote-kcov S1] Construct the extra remote KCOV buffer only when
    // threaded. Remote coverage (async/softirq/kthread) only materializes once
    // the program-child forks pool threads that inherit kcov_handle; in serial
    // mode there are no such threads and the per-task local KCOV already
    // captures everything. Construction here keeps the buffer's lifetime stable
    // across SnapshotForCrash like the collector pool; Init() opens it. Its
    // capacity is independent of local collector tuning and matches
    // syzkaller's 1M-entry kExtraCoverSize.
    if (threaded) {
        extra_ = std::make_unique<RemoteKcovBuffer>(
            kSyzkallerExtraKcovEntries, extra_instance, child_mode_);
    }

    if (child_mode_ == KcovChildMode::kFreshPerProgram) {
        RegisterAtForkOnce();
        {
            std::lock_guard<std::mutex> lk(AtForkRegistryMutex());
            AtForkRegistry().insert(this);
        }
        atfork_registered_ = true;
    }
}

void KcovSink::ConfigureProcId(uint32_t proc_id)
{
    if (!threaded_) {
        return;
    }
    const uint32_t next_instance = proc_id + 1u;
    if (extra_ != nullptr && extra_instance_ == next_instance) {
        return;
    }
    extra_ = std::make_unique<RemoteKcovBuffer>(
        kSyzkallerExtraKcovEntries, next_instance, child_mode_);
    extra_instance_ = next_instance;
}

KcovSink::~KcovSink()
{
    if (!atfork_registered_) {
        return;
    }
    std::lock_guard<std::mutex> lk(AtForkRegistryMutex());
    AtForkRegistry().erase(this);
}

void KcovSink::OnChildPostFork()
{
    // Legacy fresh mode only. Called by AtForkChildHandler inside the
    // just-forked program child.
    // Walk all collectors and reset their mmap pointer; KcovCollector
    // marks the parent mapping MADV_DONTFORK, so child has no PTEs for
    // area_ and would SIGSEGV on first read otherwise.
    for (auto& c : collectors_) {
        if (c) c->ResetMappingForChild();
    }
    // [remote-kcov S2] The extra buffer's parent mapping is MADV_DONTFORK too,
    // so the child has no PTEs for its area_; reset the pointer so the next
    // EnsureMapped() re-mmaps. PackFeedback's EnsureMappedAndCollectPCs() drives
    // that re-mmap in the program-child at kSessionEnd. The fd is inherited
    // (copy_files) and the kcov_handle registration is shared, so the child
    // keeps feeding the same remote area.
    if (extra_) {
        extra_->ResetMappingForChild();
    }
    // Drain-side state is per-task in the parent; child starts fresh.
    last_session_entries_.clear();
    collecting_ = false;
}

bool KcovSink::Init()
{

    // [v2 Epic 7 PR-1/PR-4] 各 collector 独立打开 /sys/kernel/debug/kcov +
    // KCOV_INIT_TRACE;threaded path 只有前 3 个预 mmap,其余在 Begin() lazy
    // mmap。一个 collector Init 失败 → sink 整体失败,
    // child 不会进 ChildMain。理由:threaded path 期望 N 个全部 ready,partial
    // ready 语义复杂,且 KCOV 失败通常是系统级问题(权限/kernel 版本)而非
    // per-thread。
    for (auto& c : collectors_) {
        if (!c->Init()) {
            return false;
        }
    }

    // [remote-kcov S1] Bring up the extra remote KCOV buffer. This runs in
    // loop_child (bus.InitAll(), loop_runtime.cpp) BEFORE PrepareChildFdTableAbi
    // and BEFORE the program loop forks any program-child / pool thread — so
    // EnableRemote()'s task->kcov_handle=H is inherited by the whole forked
    // tree (kcov_task_init). EVERYTHING here is best-effort: a failure (no
    // remote-KCOV kernel support, open/mmap/enable error) is logged and the
    // sink still returns true. Local KCOV (the collector pool) must keep
    // working unchanged regardless.
    if (extra_) {
        if (!extra_->Init()) {
            ::refuzz::worker::log::WorkerLog(
                "[remote-kcov] Init failed — extra remote KCOV disabled this "
                "session (local KCOV unaffected)\n");
        } else if (!extra_->EnableRemote()) {
            ::refuzz::worker::log::WorkerLog(
                "[remote-kcov] EnableRemote failed — extra remote KCOV disabled "
                "this session (local KCOV unaffected)\n");
        }
    }
    return true;
}

bool KcovSink::Enabled() const
{
    if (collectors_.empty()) return false;
    return collectors_[0]->Enabled();
}

refuzz::proto::FeedbackKind KcovSink::Kind() const
{
    if (collectors_.empty()) return refuzz::proto::FeedbackKind::kNone;
    return collectors_[0]->Kind();
}

KcovCollector* KcovSink::GetCollector(int tid)
{
    if (tid < 0 || static_cast<size_t>(tid) >= collectors_.size()) {
        return nullptr;
    }
    return collectors_[static_cast<size_t>(tid)].get();
}

int KcovSink::ThreadCount() const
{
    return static_cast<int>(collectors_.size());
}

// [v2 Epic 7 PR-4] IKcovDrainSink 实现。
//
// StartThreadedSession 由 driver 在 task start (threaded path) 调用,锁定
// 本 task 的 KcovMode 并清空累积器 last_session_entries_。serial path 走
// 现有 OnEvent(kTaskStart),不会 touch 这里。
//
// AppendThreadDrained 由 driver 在 task end iterate active worker thread,
// 把各 thread 已 drain 的 CMP records 推回来。PC mode 的 syscall coverage
// 已经在 driver 的 per-call tail 中返回,PackFeedback 不再 emit program-level
// PC packet。
void KcovSink::StartThreadedSession(KcovMode mode)
{
    last_mode_ = mode;
    last_session_entries_.clear();
    // collecting_ 保持 false:OnEvent(kSessionEnd) 不再调 collector.End()
    // (threaded 下 End 已经在 worker thread 内执行了)。这与 OnEvent(kTaskStart)
    // 的 serial-gate 行为一致 — collecting_=false 意味着"sink 不主动 drain",
    // 但 last_session_entries_ 由 AppendThreadDrained 填充。
}

void KcovSink::AppendThreadDrained(std::vector<uint64_t> entries)
{
    if (entries.empty()) {
        return;
    }
    // reserve 一次再插入,减少 grow 次数。
    last_session_entries_.reserve(last_session_entries_.size() + entries.size());
    last_session_entries_.insert(
        last_session_entries_.end(),
        std::make_move_iterator(entries.begin()),
        std::make_move_iterator(entries.end()));
}

void KcovSink::OnEvent(ObservationEvent ev, const ObservationContext& ctx)
{
    switch (ev) {
    case ObservationEvent::kTaskStart: {
        runtime_failure_ = RuntimeFailure::kNone;
        // KCOV 是 per-thread 的：threaded mode 下 worker thread 未 open kcov fd,
        // 跳过避免假数据。(Step 4 之后 threaded path 改为 worker thread 自己
        // 在自己上下文 Begin;Step 1 这里仍是 main thread serial-only。)
        const bool serial = (ctx.exec_mode.intra == IntraTaskMode::kSerial);
        // [v2 Epic 5 PR-5-B] derive KCOV mode from ctx.collect_comps. In
        // threaded mode this does not Begin here, but CurrentMode() exposes the
        // requested PC/CMP mode to KernelWireDriver before it starts the worker
        // pool session.
        const KcovMode mode = ctx.collect_comps ? KcovMode::kCmp : KcovMode::kPc;
        last_mode_ = mode;

        // [v2 Epic 7 PR-1] vectorized: Step 1 永远走 collectors_[0],等价 v1。
        // 注意 KCOV 同线程约束:Begin (这里调) 与后续 End/EndAsCmp / per-call
        // Reset+Collect 必须在同一线程。Step 1 = main thread 全部,OK。
        // Step 4 把 Begin 下沉到 worker thread,这里只在 serial 路径保留。
        if (!collectors_.empty() &&
            collectors_[0]->Enabled() && serial &&
            collectors_[0]->Begin(mode)) {
            collecting_ = true;
        } else {
            collecting_ = false;
            if (serial && child_mode_ == KcovChildMode::kInheritedFromLoop) {
                runtime_failure_ = RuntimeFailure::kKcovStateInvalid;
            }
        }
        last_session_entries_.clear();
        break;
    }
    case ObservationEvent::kSessionEnd:
        if (collecting_) {
            // [v2 Epic 7 PR-1] vectorized — collectors_[0] in Step 1。Step 4
            // (threaded) 会把 End/EndAsCmp 调用下沉到各 worker thread,
            // 这里改成迭代 active threads 各自取已 drain 的 entries。
            if (last_mode_ == KcovMode::kCmp) {
                collectors_[0]->EndAsCmp(&last_session_entries_);
            } else {
                collectors_[0]->End(&last_session_entries_);
            }
            collecting_ = false;
        }
        break;
    case ObservationEvent::kActionBefore:
    case ObservationEvent::kActionAfter:
        // KCOV 由内核自动累加,sink 不做 per-call 事件处理。
        break;
    }
}

void KcovSink::PackFeedback(uint8_t* out, uint32_t out_cap, uint32_t* inout_len)
{
    // [remote-kcov S2] Emit program-level extra (remote/softirq/kthread)
    // coverage as a kCoverageKcov packet. This runs in the program-child at
    // kSessionEnd (after the pool threads finished). KcovSink is registered
    // BEFORE PseudoDispatchSink (kernel_syz_profile.cpp), so this packet lands
    // right after the per-call SyzExecResult cover tail and BEFORE the pseudo
    // packet — preserving the host peel order (pseudo outermost → this packet →
    // raw per-call tail). It is ADDITIVE to the per-call local KCOV in the tail
    // (KCOV_REMOTE_ENABLE never captures the enabling task's synchronous cover),
    // mirroring syzkaller info.Extra.Cover (program-level, not attributed to a
    // call). PC mode only: in CMP mode the hints path consumes the tail and a
    // PC packet would not belong there. Best-effort: NoSpace silently drops it,
    // matching the CMP path's contract.
    if (extra_ && last_mode_ != KcovMode::kCmp) {
        // [syz-aligned 异步结算] 镜像 syz executor.cc:1162-1174。程序触发的延迟
        // 内核工作(USB-core workqueue 的 root-hub resume、RX 软中断、RCU/延迟
        // free)在 syscall 返回后才被调度执行;立即 drain remote buffer 它们还没
        // 跑 → 远程覆盖丢失(exec-oracle 实测 usb_hcd_resume_root_hub /
        // wg_receive ref_rate=0)。syz 对含 `remote_cover` 属性调用的程序,以
        // kSleepMs=100ms 为步长、最多 prog_extra_cover_timeout=500ms,循环
        // re-drain extra cover(write_extra_output)。
        //
        // [remote-kcov R2] 结算门 = program_uses_remote_cover_(由 program loop
        // 经 SetProgramUsesRemoteCover 按 typed-Target 的 remote_cover 属性下发)
        // OR 首次 drain 已见远程覆盖。前者覆盖 USB 枚举这类 async-but-slow 工作
        // (khubd hub_event 在 syscall 返回后才被调度,首次 drain 为空 → 旧的纯
        // `!extra_pcs.empty()` 门会漏掉它);后者是 framework 尚未下发标记时的回退,
        // 仍能捕获首次 drain 即可见的远程覆盖。命中后进入 100ms×(≤5)重 drain
        // 循环累积,直到不再增长(静默早退,避免对仅有瞬时远程覆盖的程序白付满
        // 500ms)或到上限;两者都不命中则单 drain、零成本(= syz
        // prog_extra_cover_timeout=0 路径)。remote buffer 是累积的(area[0] 计数
        // 单调增,ResetExtraProgram 才清零),故重读得到增量并集。
        // env 可调:REFUZZ_REMOTE_KCOV_SETTLE_MS(步长 ms,默认 100)/
        //           REFUZZ_REMOTE_KCOV_SETTLE_MAX_MS(上限 ms,默认 500);任一 0=关。
        static const long kStepMs = [] {
            const char* e = std::getenv("REFUZZ_REMOTE_KCOV_SETTLE_MS");
            return e ? std::strtol(e, nullptr, 10) : 100L;
        }();
        static const long kMaxMs = [] {
            const char* e = std::getenv("REFUZZ_REMOTE_KCOV_SETTLE_MAX_MS");
            return e ? std::strtol(e, nullptr, 10) : 500L;
        }();
        std::vector<uint64_t> extra_pcs;
        extra_->EnsureMappedAndCollectPCs(&extra_pcs);
        if (kStepMs > 0 && kMaxMs > 0 &&
            (program_uses_remote_cover_ || !extra_pcs.empty())) {
            const int max_iters = static_cast<int>(kMaxMs / kStepMs);
            struct timespec ts;
            ts.tv_sec = kStepMs / 1000L;
            ts.tv_nsec = (kStepMs % 1000L) * 1000000L;
            std::size_t prev = extra_pcs.size();
            for (int i = 0; i < max_iters; ++i) {
                sched_yield();  // 先跑本 CPU 上挂起的软中断
                auto* perf_sample =
                    ::refuzz::worker::perf::CurrentSample();
                const uint64_t sleep_start_us =
                    perf_sample != nullptr
                        ? ::refuzz::worker::perf::NowUs()
                        : 0;
                if (perf_sample != nullptr) {
                    ::refuzz::worker::perf::AddSaturating(
                        &perf_sample->remote_kcov_settles, 1);
                }
                nanosleep(&ts, nullptr);  // 给 workqueue/RCU kworker 时间
                if (perf_sample != nullptr) {
                    ::refuzz::worker::perf::AddStage(
                        perf_sample,
                        ::refuzz::worker::perf::WorkerStage::
                            kRemoteKcovSettleSleep,
                        ::refuzz::worker::perf::NowUs() - sleep_start_us);
                }
                extra_->EnsureMappedAndCollectPCs(&extra_pcs);  // 累积重读
                if (extra_pcs.size() == prev) {
                    break;  // 静默:本步无新远程覆盖 → 早退
                }
                prev = extra_pcs.size();
            }
        }
        if (!extra_pcs.empty()) {
            AppendCoverageFeedbackRaw(out, out_cap, inout_len,
                                      refuzz::proto::FeedbackKind::kCoverageKcov,
                                      extra_pcs.data(),
                                      static_cast<uint32_t>(extra_pcs.size()));
        }
    }

    if (last_session_entries_.empty()) {
        return;
    }
    // PC coverage is owned by KernelWireDriver's per-call SyzExecResult tail.
    // A task-end PC packet here duplicates the same task and can inflate most
    // executions toward an output-pool-sized payload (14 MiB ivshmem fixed
    // budget / 6 MiB stdio default), while the collector itself is 4 MiB.
    if (last_mode_ != KcovMode::kCmp) {
        last_session_entries_.clear();
        return;
    }

    // CMP remains session-wide for the hints path. entry_count is record count
    // = uint64s/4.
    constexpr size_t kUint64sPerRecord = 4;
    // [v2 Epic 5 PR-5-B fix #1] Worker-local cmp filters — mirror upstream
    // executor.cc:1841-1851. Two filters:
    //   (a) Output-buffer pointer rejection: drop any record whose
    //       arg1 OR arg2 lands inside the worker's output region.
    //       Without this, the fuzzer can discover the output buffer's
    //       VA via cmp records and corrupt it through hint-driven
    //       mutations. reFuzz forwards the contiguous output buffer span
    //       passed by ChildExecuteTask (= area->output_pool /
    //       MAX_OUTPUT_SIZE); FilterCmpRecordsByOutputBuffer applies the
    //       upstream inclusive-end comparison.
    //   (b) PC coverage_filter allowlist — upstream gates on
    //       cover_filter->Contains(pc); when no filter is loaded
    //       upstream returns true (accept all). reFuzz does NOT yet
    //       ship a CoverFilter, so the upstream-equivalent default
    //       holds (no PC filtering applied here). Hook deferred to
    //       Epic 5 plan §10 (out of scope) until a CoverFilter lands.
    //
    // Filter logic lives in `FilterCmpRecordsByOutputBuffer` for direct
    // unit testability; this site only forwards record-count buffers.
    const size_t total_records = last_session_entries_.size() / kUint64sPerRecord;
    if (total_records == 0) {
        return;
    }
    const uint64_t out_start = reinterpret_cast<uint64_t>(out);
    const uint64_t out_end   = out_start + out_cap;
    std::vector<uint64_t> filtered;
    const uint32_t kept = FilterCmpRecordsByOutputBuffer(
        last_session_entries_.data(),
        static_cast<uint32_t>(total_records),
        out_start, out_end,
        &filtered);
    if (kept == 0) {
        return;
    }
    AppendKcovCmpFeedbackRaw(out, out_cap, inout_len,
                             filtered.data(),
                             kept);
    // 注意:append 失败 (NoSpace) 时由 caller 决定是否 LOG;此处保持沉默,
    // 因为 sink 不应该持有 logger 依赖。
}

uint32_t KcovSink::SnapshotForCrash(uint8_t* out, uint32_t out_cap) const
{
    // async-signal-safe: KcovCollector::SnapshotFeedback 直接读 mmap area,
    // 调用 AppendCoverageFeedbackRaw (memcpy,不分配)。

    // [v2 Epic 7 PR-1] 读 collectors_[0] (Step 1 唯一 collector)。vector
    // 索引访问是 memcpy-free,async-signal-safe 不破坏。Step 4 (threaded
    // crash) 需要 iterate 所有 active collector 各自 snapshot 后串联,届
    // 时再扩;此处签名不变。
    if (collectors_.empty()) return 0;
    return collectors_[0]->SnapshotFeedback(out, out_cap);
}

size_t KcovSink::BufferBytes() const
{

    // [v2 Epic 7 PR-1] sum across pool (Step 1 size=1,等价 v1)。RLIMIT_AS
    // 预算 ApplySandbox 时按 sink 总 mmap 占用算,Step 4 池扩到 N 后这里
    // 自动反映 N × configured KCOV bytes。
    size_t total = 0;
    for (const auto& c : collectors_) {
        total += c->BufferBytes();
    }
    // [remote-kcov S1] include the extra buffer's VA budget when present.
    if (extra_) {
        total += extra_->BufferBytes();
    }
    return total;
}

bool KcovSink::RemapInternalFds(int* next_fd, std::vector<int>* preserved_fds)
{
    if (next_fd == nullptr) {
        return false;
    }
    bool ok = true;
    for (auto& c : collectors_) {
        if (!c->RemapFdAtOrAbove(next_fd)) {
            ok = false;
            continue;
        }
        const int fd = c->InternalFd();
        if (fd >= 0 && preserved_fds != nullptr) {
            preserved_fds->push_back(fd);
        }
    }
    // [remote-kcov S1] move the extra buffer's fd into the high reserved band
    // too, so PrepareChildFdTableAbi's CloseUnpreservedFds doesn't clobber it
    // and the program ABI keeps fds 3-199 free.
    if (extra_) {
        if (!extra_->RemapFdAtOrAbove(next_fd)) {
            ok = false;
        } else {
            const int fd = extra_->InternalFd();
            if (fd >= 0 && preserved_fds != nullptr) {
                preserved_fds->push_back(fd);
            }
        }
    }
    return ok;
}

void KcovSink::ResetExtraProgram()
{
    // [remote-kcov R2] Per-program default: no forced settle unless the program
    // loop marks this program as containing a remote_cover call.
    program_uses_remote_cover_ = false;
    if (extra_) {
        extra_->ResetProgram();
    }
}

} // namespace refuzz::worker

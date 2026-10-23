#pragma once
// Job-loop 重设计 —— Step 1:job 视角(唯一触达世界的通道)。
//
// 一条 job = 一条 OS 线程上的直线代码;JobContext 是它**唯一**的 channel:
// exec() 是唯一挂起点。协议/不变量见 docs/job-loop-redesign/010_step1_job_scheduler.md。
//
// 本头只定 job 侧类型(Request / ExecResult / JobContext / JobFn);控制侧
// (Job / JobScheduler)见 job_scheduler.hpp。

#include "refuzz/program/artifact.hpp"
#include "refuzz/proto_domain/types.hpp"
#include "refuzz/queue/task_tier.hpp"   // [Step 5] TaskTier(Request 打档)

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

namespace refuzz::control::job {

// Whether a routed job completion may also perform the syz processResult()
// triage side effect. Routing the result back to the waiting job and spawning
// fresh core-path triage from newly observed signal are orthogonal.
enum class CompletionTriagePolicy : std::uint8_t {
    kAllowCatchAllTriage = 0,
    kSuppressCatchAllTriage = 1,
};

// 一条 job 请求执行的**一次** op:一个待跑程序(占一个 worker 槽)。字段镜像
// HostFuzzTask 的 artifact/payload 双轨,让 Step 2 的生产 wiring 是直接字段拷贝。
struct Request {
    std::shared_ptr<const ::refuzz::program::ProgramArtifact> artifact;  // v2 typed 权威
    std::vector<std::uint8_t>  payload;   // explicit wire bytes or profile-gated bytes-only path
    ::refuzz::proto::ExecOpts  opts;
    // [Step 5] 通用 lineage:产**新程序**的 job(smash/gen/mut)设它,arbiter submit 透传到
    // HostFuzzTask → 下游 lineage-yield / seed-value-shadow / mutation-stat 按 origin_seed_id!=0
    // 消费。route-back re-exec(core-path/fault/hints)不设 → 0 → 下游跳过(与现在逐字节同)。
    std::uint64_t seed_id        = 0;
    std::uint64_t origin_seed_id = 0;
    // [Step 5] 调度档位:job 按自身语义打(core-path→Triage/CandidateTriage、fault/hints/smash
    // →Smash、explore→Explore);arbiter 的 submit/submit_exploration 据它入 task_queue 对应档。
    // 默认 Triage(③)—— 未打档的 job 落现场-triage 档;直接 Push 的旧 stage 同默认 → 单档 FIFO。
    ::refuzz::queue::TaskTier tier = ::refuzz::queue::TaskTier::Triage;
    CompletionTriagePolicy completion_triage_policy =
        CompletionTriagePolicy::kAllowCatchAllTriage;
};

// 一次 op 里单个 call 的信号快照。生产由 reaper 从 event 的 per-call 观测投影;
// minimize job 再映射到 MinimizeDriver::ExecSignalSnapshot::per_call。
struct CallSignal {
    std::vector<std::uint64_t> coverage_hashes;
    std::vector<std::uint64_t> edge_hashes;
    // [per-call novelty] signal THIS call first-owned in the max-signal store on this
    // exec (投影自 KernelCallObservation::novel_signal_hashes)。core-path deflake 每次
    // re-exec 把它并进 chased_calls[i](= syz deflake 里再调 triageProgCall 补 newSignal)。
    std::vector<std::uint64_t> novel_signal_hashes;
    std::int32_t  errno_value = 0;
    std::uint32_t syscall_id  = 0;
    // [Step 4a] 该 call 命中 fault injection(投影自 KernelCallObservation::fault_injected)。
    // 只有 fault-inject job 读它(判依赖循环 continue/break);其余 job 忽略。
    bool          fault_injected = false;
    std::uint8_t  signal_priority = 0;
};

// 一次 op 的结果,路由回挂起的 job。生产里由 reaper 从 ChannelEvent 的
// EngineOutput 投影;单测里直接填。[Step 2b] 扩出 minimize 要的 per-call 快照 +
// exec_status(= MinimizeDriver::ExecSignalSnapshot 的字段)。
struct ExecResult {
    bool cancelled = false;                      // 挂起期间被取消 → job 应 unwind 返回
    // [Step 4a] 事件是否 AbnormalCompletion(kTimeout/kExecError/kWorkerCrashed/...)。
    // 投影自 event.IsAbnormal()。原始信号,供 metrics/日志用;job 的停/不停决策不要直接读
    // 这个字段 —— 见下面 hard_stop(两者不等价:并非每种 AbnormalKind 都该让 job 停)。
    bool abnormal = false;
    // [narrowed job-stop signal] 只有底层 AbnormalKind 属于"这条请求(乃至同一 worker 的
    // 后续请求)已经拿不到任何有效结果"这一类才为 true —— 对应 syz result.Stop() 里
    // ExecFailure(harness 级)/Crashed/Hanged 的真实含义。真值集合见
    // minimize_admit.cpp::ProjectExecResult,当前为 6 个:kTimeout / kWorkerCrashed /
    // kWorkerSignaled / kCancelled / kHarnessRecovered / kHarnessFatal。
    //   kTimeout —— 只由 daemon watchdog 产生(= syz queue.Hanged);program 级 watchdog
    //     走 partial 救回(COMP_STATUS_PARTIAL,= syz reply_execute(0)),不到这里。
    //   kChildAborted(程序自己 crash,worker 健在 —— syz 里这就是 Status=Success,异常只
    //     体现在 per-call Info)和 kExecError(拿不到数据,但只是这一次 task 失败,不代表
    //     worker 坏了)是 false,交给各 job 自己已有的正常结果处理逻辑(per-call 检查/空
    //     replay 容忍/exec_status 一致性投票等)判断要不要继续 —— 不在这层强行整条 job 中止。
    // 命名对齐既有的 MinimizeDriver::ExecSignalSnapshot::hard_stop /
    // InlineVerdict::hard_stopped(本字段就是它们的上游输入)。
    bool hard_stop = false;
    std::vector<std::uint64_t> signal_hashes;    // 程序级 signal(足够驱动 deflake 一步)
    std::vector<CallSignal>    per_call;         // 逐 call 快照(minimize per-call signal-match)
    int                        exec_status = 0;  // ResultCode(0 = kOk),映射 target_exec_status
    // [Step 3 Slice C3] program-level EXTRA/remote cover (syz Info.Extra: async
    // USB khubd/softirq/kthread PCs). deflake unions it into the corpus COVER
    // (not per-call voted). Only the core-path job's deflake reads it; minimize
    // ignores it. Populated by ProjectExecResult from KernelExecutionObservation.
    std::vector<std::uint64_t> extra_cover;
    // Admission-unit signal for EXTRA/remote: edge signal in cover_edges mode,
    // raw PC otherwise. Mirrors KernelExecutionObservation::extra_signal_hashes.
    std::vector<std::uint64_t> extra_signal_hashes;
    bool extra_signal_hashes_are_edges = false;
    // [per-call novelty] EXTRA/remote (call=-1) novel signal this re-exec(投影自
    // KernelExecutionObservation::extra_novel_signal_hashes)。core-path deflake 并进
    // chased_calls[-1]。
    std::vector<std::uint64_t> extra_novel_signal_hashes;
    // [Step 4b] 原始 worker output 字节(**未** decode)。hints job 的 collect-comps 前缀
    // 把它透传给控制线程 batch,那里 CoverageFeedbackCodec.Extract 出**完整** CmpRecord
    // 向量建 CompMap(feedback engine 的 EngineOutput 只留去重增量,不含全量 cmp —— 故
    // 必须由 raw output 独立 decode,同旧 HintsConsumer)。只有 hints 用;其余 job 忽略。
    // ProjectExecResult 从 event 的 Completion/Abnormal output 拷入。
    std::vector<std::uint8_t> output;
};

class Job;  // 控制侧 handle,定义见 job_scheduler.hpp

// [Step 5] emit 的 post-submit 回调:control 线程在 arbiter 分配 exec_id + 提交后**立即**调。
// 让 fire-and-forget 的 job 把 exec_id 绑到自己的账(如 MAB RecordProduced / seed 归因)。
// **job 提供、调度器只负责跑** → 调度器/loop 不懂 job 的归因细节(模块化保住)。
using OnSubmitted = std::function<void(std::uint64_t /*exec_id*/)>;

// [Step 5] emit 的 completion observer:结果仍然不路由回 job,仍先落 catch-all；这个回调只让
// 无栈 job 在 completion 回来后做观测/收尾计数。loop 只按 executor_id 兑现回调,不理解来源。
using OnCompleted = std::function<void(const ExecResult&)>;

// 按引用传给 job 函数。job 只经它触达世界。exec() 是唯一阻塞原语。
class JobContext {
public:
    // **唯一挂起点。** 把 req 登记为本 job 的 pending continuation,让出给调度器
    // (strict alternation),阻塞到调度器把对应结果路由回来。返回该结果;若挂起
    // 期间 job 被取消,返回 {cancelled=true}(此时 job 必须 unwind 返回、**不得**
    // 再发 exec —— 不变量 #9)。
    ExecResult exec(Request req);

    // [Step 5] fire-and-forget 提交:把 req 经调度器提交(= 与 exec 同一 submit funnel),但
    // **不**把结果路由回本 job —— 结果落 catch-all(triage)。提交后**立即恢复**本 job(不挂起
    // 等结果),job 接着发下一个。`on_submitted(exec_id)` 在 control 线程 post-submit 跑(给 job
    // 绑归因,如 MAB)。返回 false = 挂起期间被取消(job 应 unwind、不得再发 —— 不变量 #9)。
    //   有栈数据依赖 op 用 `exec`(要结果才能定下一步);无栈 fire-and-forget op(generation /
    //   mutation)用 `emit` —— 一个 job 两种原语 = 有栈/无栈都是 job。smash/hints 变体现在也
    //   要结果才能推进 completion-gated 计数,故都用 `exec`,不用 `emit`。
    bool emit(Request req, OnSubmitted on_submitted = {},
              OnCompleted on_completed = {});

    // 协作取消轮询。job 可在 CPU 步之间查它提前退出;exec() 也经 ExecResult::cancelled
    // 报告取消。
    [[nodiscard]] bool cancelled() const noexcept;

    // [Step 2b] 非阻塞:登记一个"入库/收尾动作"。由 **control 线程**在本 job **正常完成后**
    // 执行(单一所有者 —— 动作碰 corpus/admit 等共享态,不在 job 线程跑);被取消的 job
    // 的 retain **不执行**(不变量 #8:最后一次 handoff 之后的活丢弃)。minimize job 完成时
    // 用它把 minimized seed 交给 corpus admit。
    void retain(std::function<void()> action);

    // spawn() 在后续步落这里(elaboration spawn)。Step 2b 暂不引入。

private:
    friend class Job;
    explicit JobContext(Job& owner) noexcept : owner_(owner) {}
    JobContext(const JobContext&)            = delete;
    JobContext& operator=(const JobContext&) = delete;
    Job& owner_;
};

// 一个 job body:直线代码,跑在自己的线程上,可任意多次 ctx.exec(),做完 return。
// 必须**取消安全**(RAII 清理;见到 ExecResult::cancelled 或 ctx.cancelled() 时 unwind
// 返回,且**不再** exec —— 不变量 #9)。
using JobFn = std::function<void(JobContext&)>;

} // namespace refuzz::control::job

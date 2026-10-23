#pragma once
// Job runtime primitives + request-window submit pump.
//
// FuzzerLoop owns job runtime/handoff and pulls ready requests from jobs.
// JobScheduler only owns request-window credits and the executor transport
// handoff for requests the loop has already pulled.

#include "refuzz/control/job/job_context.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <unordered_set>
#include <utility>
#include <vector>

// libaco 协程句柄(vendored;真正定义在 third_party/libaco/aco.h)。这里只前向声明,
// 避免把 aco.h 的 C 宏/系统头泄漏进所有 include 本头的 TU;只有 job.cpp include aco.h 本体。
struct aco_s;

// 诊断注入的前向声明(真身由 job.cpp include):job 异常 fail-soft 时写 HostLogger error +
// 计 fuzzer.job_aborted。头文件只用指针,不把这两个大依赖拉进所有 include 者。
namespace refuzz::logging { class HostLogger; }
namespace refuzz::core::metrics { class Counter; }

namespace refuzz::control {
class FuzzerLoop;
}

namespace refuzz::control::job {

// 一条在飞 job:一条 libaco 有栈协程(所有 job 共享同一条运行栈)+ 它与控制协程交换的
// strict-alternation 信箱。每条 job 通过 JobContext::exec/emit 与控制协程 handoff —— 这是
// 一次**协程切换**(aco_yield/aco_resume),不是线程唤醒,没有 MinimizeDriver 内部 worker。
// 任意时刻只有一条 job 在跑,且全部 Job::* 与 job 主体都在同一条控制线程上执行 → 无并发,
// 信箱/状态都是普通成员,不需要 mutex/cv/atomic。
class Job {
public:
    // logger/job_aborted:诊断注入(FuzzerLoop 传入;nullptr = 单测/无注入 → 退 stderr / 不计数)。
    // 见 job.cpp RunBody:job 抛未捕获异常时 fail-soft 上报。
    Job(std::uint64_t job_id, JobFn fn,
        refuzz::logging::HostLogger*    logger      = nullptr,
        refuzz::core::metrics::Counter* job_aborted = nullptr);
    ~Job();                                   // 若协程还活:CancelAndJoin(幂等)
    Job(const Job&)            = delete;
    Job& operator=(const Job&) = delete;

    std::uint64_t id() const noexcept { return job_id_; }

private:
    friend class JobContext;
    friend class ::refuzz::control::FuzzerLoop;
    friend struct JobTestAccess;   // 单测经此访问控制侧私有接口(tests/job_coroutine_smoke_test.cpp)

    // ── job 线程侧(经 JobContext::exec / emit / retain 调)──
    ExecResult Exec(Request req);             // 登记 pending → notify ctrl → wait → 返回结果/取消
    bool       Emit(Request req, OnSubmitted on_submitted,
                    OnCompleted on_completed);  // [Step 5] fire-and-forget:登记 emit → notify → 等 submit-ack(不等结果)→ 返回(false=取消)
    bool       IsCancelled() const noexcept { return abort_; }
    void       Retain(std::function<void()> action);   // 登记收尾动作(mu_ 下)

    // ── 控制线程侧(FuzzerLoop 调)──
    void        Launch();                     // 起线程,跑到首个 yield(首个 pending / done)
    bool        SuspendedWithRequest() const; // 有等槽的 pending Request(= ready continuation)
    bool        PendingIsEmit() const;        // [Step 5] 本次 yield 是 emit(fire-and-forget)否则 exec(route-back)
    // [tier-aware arbitration] 只读:pending request 的调度档(不消费)。ArbitrateJobs 用它在
    // TakePendingRequest 之前按 syz Order(candidate_triage,candidate,triage,
    // Alternate(smash,3),explore) 语义选人;routed/emit 都要能读,因为两者共用同一套 tier
    // (例如 HintsJob 的 collect-comps 是 routed 但 tier=Smash)。无 pending 或已 done → nullopt。
    std::optional<::refuzz::queue::TaskTier> PeekPendingTier() const;
    Request     TakePendingRequest();         // 控制取走它去 submit(消费 pending)
    OnSubmitted TakePendingOnSubmitted();     // [Step 5] 取走 emit 的 post-submit 回调(消费 emit 标记)
    OnCompleted TakePendingOnCompleted();     // [Step 5] 取走 emit 的 completion observer
    void        Deliver(ExecResult r);        // 投结果 + handoff:把 job 推到下一个 yield / done
    void        ResumeAfterEmit();            // [Step 5] emit 无结果:置 ack + handoff 到下一 yield / done
    bool        Done() const;                 // job 函数已返回
    void    CancelAndJoin() noexcept;         // abort + 唤醒 + join(join 阻塞控制 → 只 job unwind)
    void    JoinDone() noexcept;              // job 已 done 时 join(不阻塞)
    std::vector<std::function<void()>> TakeRetains();  // control 侧:取走收尾动作(job 已 join 后)

    // ── 协程入口/主体(job co 跑在控制线程上)──
    static void CoEntry();   // libaco co trampoline:arg=this → RunBody() → aco_exit()(不返回)
    void        RunBody();   // 跑 fn_(ctx_)(取消安全 RAII);兜住异常;结束置 done_
    void        ReportAborted(const char* what);  // fail-soft 上报:job_aborted +1 + HostLogger error

    std::uint64_t job_id_;
    JobFn         fn_;
    refuzz::logging::HostLogger*    logger_      = nullptr;  // 诊断:job 异常 error 日志(nullptr → stderr)
    refuzz::core::metrics::Counter* job_aborted_ = nullptr;  // 诊断:被吞异常计数(nullptr → 不计)
    JobContext    ctx_{*this};
    // libaco 协程句柄:整条 job 跑在(共享)运行栈上,exec/emit = 切回控制协程。
    // nullptr 直到 Launch();所有访问都在控制线程(strict alternation → 无并发,无需锁)。
    ::aco_s*      co_ = nullptr;

    std::optional<Request>    pending_request_;   // job → 控制(要一个槽)
    bool                      request_ready_ = false;
    bool                      pending_is_emit_ = false;   // [Step 5] 本次 pending 是 emit(fire-forget)否则 exec
    OnSubmitted               pending_on_submitted_;      // [Step 5] emit 的 post-submit 回调(control 线程跑)
    OnCompleted               pending_on_completed_;      // [Step 5] emit 的 completion observer(control 线程跑)
    std::optional<ExecResult> delivered_;         // 控制 → job(结果)
    bool                      done_          = false;
    bool                      abort_         = false;   // 取消标记(单线程 → 普通 bool)
    std::vector<std::function<void()>> pending_retains_;   // job 登记、control 完成后执行(不变量 #8:取消不执行)
};

// request-window submit pump. It does not own jobs, does not pull jobs, does
// not deliver results, and does not run business logic. FuzzerLoop pulls ready
// requests from jobs when HasRoom() is true, then calls TrySubmit to hand them
// to executor transport.
class JobScheduler {
public:
    struct Deps {
        // [request-window] pull/window 窗口上限:scheduler 最多允许多少个 request 处于
        // "已提交给执行侧但尚未 accepted 确认"的状态(= syz `requests − executing < 2·procs`)。
        // >0 时 FuzzerLoop 的 pull 门改用本调度器**自持**的 awaiting-accept 窗口(submit 时
        // 计入、MarkAccepted 时释放)。释放点从"task_queue 被 pop"精确到
        // "Channel::Submit kAccepted"。0 = 无 dispatch 窗口,调度器不派发 request。
        std::size_t dispatch_window_limit = 0;

        // 授槽:以 exec_id 派发 req 到 executor transport。这里不是生产 push;request 已经
        // 由 FuzzerLoop 在 HasRoom() 成立后从 job pull 出来。
        std::function<void(std::uint64_t exec_id, const Request& req)> submit;

        // [Step 5 —— 可空] emit(fire-and-forget)提交口:同 submit 入 executor transport,
        // 但结果**不路由回 job**(unrouted → catch-all/triage)。无栈 op(smash/gen/mut job)经
        // emit 用它。空 = 不支持 emit。
        std::function<void(std::uint64_t exec_id, const Request& req)> submit_exploration;

        // [可空 —— 共享 id 空间] 分配 exec_id。生产绑到 FuzzerLoop::next_executor_id_
        // (与老 stage 同一计数器 → 全局唯一、可 demux)。空 = 内部 next_exec_id_++。
        std::function<std::uint64_t()> alloc_exec_id;

        // [request-stream capture —— 可空] 每个被派发的 request 在进入 transport 前
        // 经过这里。挂在 TrySubmit 而不是 emit/exec 任一原语上:两个原语都汇到本漏斗,
        // 只挂其一必漏另一半。空 = 不采集(生产默认),开销为零。
        // 观察者语义:不得修改 req、不得抛异常、不得挂起 —— 它跑在 control 线程的
        // 派发路径上。
        std::function<void(const Request& req)> observe_submit;
    };

    explicit JobScheduler(Deps deps);
    ~JobScheduler();                          // 若未 Shutdown 则 Shutdown

    JobScheduler(const JobScheduler&)            = delete;
    JobScheduler& operator=(const JobScheduler&) = delete;

    bool HasRoom() const;
    // 调用方(FuzzerLoop::ArbitrateJobs)已在 while(HasRoom()) 下派发,故此处无失败路径:
    // 计入窗口 + 走 submit funnel。
    void TrySubmit(std::uint64_t exec_id, const Request& req, bool exploration);
    std::uint64_t AllocExecId() { return deps_.alloc_exec_id ? deps_.alloc_exec_id() : next_exec_id_++; }

    // [request-window] pull/window 生命周期的 credit 释放点:某 executor_id 的派发到达
    // "执行侧已接管"(channeldispatcher 上报 Channel::Submit kAccepted;或 host 侧
    // fail-closed kRejected —— 两者都释放窗口以防泄漏)。控制线程从 lifecycle 队列排干后
    // 逐个调。幂等(erase);与 result/routing 线完全分开。未知 exec_id 也只是 no-op。
    void MarkAccepted(std::uint64_t exec_id) { awaiting_accept_.erase(exec_id); }

    void Shutdown();

private:
    Deps          deps_;
    std::uint64_t next_exec_id_ = 1;
    // [request-window] 已 submit 到 executor transport、但尚未收到 accepted/rejected 生命周期事件的
    // executor_id 集合(= syz `requests − executing`)。用 set 而非计数器:释放幂等、
    // 天然防重(每个 executor_id 唯一)。
    std::unordered_set<std::uint64_t>       awaiting_accept_;
};

} // namespace refuzz::control::job

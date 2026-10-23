// Job-loop —— Job 实现 + JobContext 转发(libaco 有栈协程版)。
//
// 每条 job 不再是一条 OS 线程,而是一条 libaco 有栈协程(coroutine)。所有 job 共享
// **一条**运行栈(strict alternation:任意时刻只有一条 job 在跑),每条 job 只保留一份
// 按实际栈深自增长的 save buffer。控制线程 = libaco 的 main co;Exec/Emit(唯一挂起点)
// = aco_yield() 切回控制协程;Deliver/ResumeAfterEmit = aco_resume() 切回 job。
//
// 因为控制协程与 job 协程都跑在同一条 OS 线程上、且严格交替,永远不会并发 →
// 信箱(pending_request_/delivered_)与状态位都是普通成员,不需要 mutex/cv/atomic。
// 取消 = abort_ 置位 + 恢复 job,让挂起的 exec() 返回 {cancelled=true} / emit() 返回 false,
// job 走 RAII unwind 后自然结束(不变量 #5/#9)。
//
// 前身是"一条 job = 一条 std::thread(8MB 栈)"的实现:在飞 job 达数万条时会同时耗尽
// 内存(OOM)与 cgroup 线程数上限(thread constructor failed)。协程版把 N 条线程压成 1 条。

#include "refuzz/control/job/job_scheduler.hpp"  // 完整 Job 定义(+ job_context.hpp)

#include "aco.h"   // vendored libaco(third_party/libaco);仅本 TU 引入其 C 头

#include "refuzz/core/metrics/counter.hpp"   // [#3] fuzzer.job_aborted 计数
#include "refuzz/logging/host_logger.hpp"    // [#3] job 异常 error 日志

#include <cstdio>
#include <exception>
#include <utility>

namespace refuzz::control::job {

namespace {

// 共享运行栈大小:取 8MB,和旧模型每线程默认栈一致 —— 任何 job 的栈深上限不变,
// 零回归风险。但这是**一份**共享栈(不是每 job 一份),故 8MB 是常量开销,不随 job 数增长。
constexpr std::size_t kJobShareStackSize = 8u * 1024u * 1024u;

// libaco 运行时:一个 main co(代表控制协程)+ 一条共享运行栈。
struct AcoRuntime {
    ::aco_t*             main_co     = nullptr;
    ::aco_share_stack_t* share_stack = nullptr;
};

// [#1] **按驱动线程隔离**(thread_local),不是进程级 singleton。libaco 的 main_co /
// share_stack / aco_thread_init 存的 FPU-MXCSR 环境 / aco_gtls_co 全是**线程绑定**的:一条 co
// 只能在创建它的那条线程上 resume,否则 aco_yield 会按另一条线程 main_co 的 SP 跳栈(UB)。
// 本框架实际是单控制线程,但用 thread_local 保证「谁驱动 job,谁就有自己的 aco_thread_init +
// main_co + 共享栈」—— 未来多线程测试/嵌入也安全。每条驱动线程首次 Launch 时懒初始化。
// 进程生命周期资源,故意泄漏:避免静态/线程析构顺序的风险(实际就一条控制线程,可忽略)。
AcoRuntime& JobAcoRuntime()
{
    thread_local AcoRuntime* rt = [] {
        aco_thread_init(nullptr);
        auto* r = new AcoRuntime();
        r->main_co     = aco_create(nullptr, nullptr, 0, nullptr, nullptr);
        r->share_stack = aco_share_stack_new2(kJobShareStackSize, /*guard_page_enabled=*/1);
        return r;
    }();
    return *rt;
}

}  // namespace

// ── JobContext(job 侧,转发到 owner Job)────────────────────────────────────
ExecResult JobContext::exec(Request req) { return owner_.Exec(std::move(req)); }
bool JobContext::emit(Request req, OnSubmitted on_submitted,
                      OnCompleted on_completed)
{
    return owner_.Emit(std::move(req), std::move(on_submitted),
                       std::move(on_completed));
}
bool JobContext::cancelled() const noexcept { return owner_.IsCancelled(); }
void JobContext::retain(std::function<void()> action) { owner_.Retain(std::move(action)); }

// ── Job ────────────────────────────────────────────────────────────────────
Job::Job(std::uint64_t job_id, JobFn fn,
         refuzz::logging::HostLogger* logger,
         refuzz::core::metrics::Counter* job_aborted)
    : job_id_(job_id), fn_(std::move(fn)),
      logger_(logger), job_aborted_(job_aborted)
{}

Job::~Job() { CancelAndJoin(); }

// libaco co 入口 trampoline(跑在 job 协程栈上)。arg = 本 Job;跑完主体后 aco_exit()
// **切回控制协程且不返回**(把 co 标记 is_end)。绝不能直接 return —— 那会触发 libaco 的
// funcp protector 而 abort。
void Job::CoEntry()
{
    Job* self = static_cast<Job*>(aco_get_arg());
    self->RunBody();
    aco_exit();   // 不返回
}

// job 主体:跑直线代码 fn_(ctx_)。取消安全(见到 cancelled 时 RAII unwind 返回)。异常
// **兜在协程边界内**:若 job 抛出,fail-soft —— 计 fuzzer.job_aborted + HostLogger error +
// 丢弃 retain(异常收尾视作非正常完成,同不变量 #8),让整个 fuzz 循环存活,而不是像旧线程版
// 那样整进程 std::terminate。被吞的异常**必须可见**(见 ReportAborted),以免掩盖 job 逻辑 bug。
void Job::RunBody()
{
    try {
        fn_(ctx_);
    } catch (const std::exception& e) {
        ReportAborted(e.what());
        pending_retains_.clear();
    } catch (...) {
        ReportAborted("unknown (non-std) exception");
        pending_retains_.clear();
    }
    done_ = true;
}

// [#3] fail-soft 上报:被吞的 job 异常必须可见 —— 计 fuzzer.job_aborted + HostLogger error 事件。
// 无注入(单测)退回 stderr,保证任何情况下都不静默。
void Job::ReportAborted(const char* what)
{
    if (job_aborted_ != nullptr) {
        job_aborted_->Inc();
    }
    if (logger_ != nullptr) {
        logger_->Log("control.job", "job_aborted",
                     {refuzz::logging::Field("job_id", job_id_),
                      refuzz::logging::Field("error", what ? what : "")});
    } else {
        std::fprintf(stderr, "[job %llu] uncaught exception, job aborted: %s\n",
                     static_cast<unsigned long long>(job_id_), what ? what : "");
    }
}

// job 协程侧:登记 pending → yield 回控制协程 → 被 Deliver 恢复后取结果/取消 → 返回。唯一挂起点。
ExecResult Job::Exec(Request req)
{
    // [#2 不变量 #9 硬保证] 取消后再调 exec:立刻返回 cancelled、**不 yield** —— 否则会再挂起,
    // 而取消路径只 resume 一次就 aco_destroy,留下未 unwind 的协程(RAII 不完整)。
    if (abort_) {
        return ExecResult{ .cancelled = true };
    }
    pending_request_ = std::move(req);
    pending_is_emit_ = false;   // 本次是 route-back exec(区别 emit)
    request_ready_   = true;
    aco_yield();   // 切回控制协程(main co);控制 Deliver 后 aco_resume 回到这里

    if (abort_) {
        return ExecResult{ .cancelled = true };
    }
    ExecResult r = std::move(*delivered_);
    delivered_.reset();
    return r;
}

// [Step 5] job 协程侧:登记 emit(fire-and-forget)→ yield → 控制提交后 ResumeAfterEmit
// 恢复本函数(不等结果)→ job 接着发下一个。取消 → 返回 false(job 应 unwind,不得再发)。
bool Job::Emit(Request req, OnSubmitted on_submitted,
               OnCompleted on_completed)
{
    // [#2 不变量 #9 硬保证] 同 Exec:取消后再调 emit 立刻返回 false、不 yield。
    if (abort_) {
        return false;
    }
    pending_request_      = std::move(req);
    pending_on_submitted_ = std::move(on_submitted);
    pending_on_completed_ = std::move(on_completed);
    pending_is_emit_      = true;
    request_ready_        = true;
    aco_yield();

    if (abort_) {
        return false;   // 取消 → job unwind(不得再发 —— 不变量 #9)
    }
    return true;   // emit 无结果可取(ack-only)
}

// control 侧:建协程,跑到首个 yield(首个 pending / 直接 done)。aco_resume 同步执行 job
// 协程直到它 aco_yield(挂起在 Exec/Emit)或 aco_exit(结束),返回时 request_ready_ 或
// done_ 已就位 —— 与旧线程版 Launch 的后置条件一致。
void Job::Launch()
{
    AcoRuntime& rt = JobAcoRuntime();
    co_ = aco_create(rt.main_co, rt.share_stack, /*save_stack_sz=*/0,
                     reinterpret_cast<::aco_cofuncp_t>(&Job::CoEntry), this);
    aco_resume(co_);
}

bool Job::SuspendedWithRequest() const
{
    return request_ready_ && !done_;
}

std::optional<::refuzz::queue::TaskTier> Job::PeekPendingTier() const
{
    if (!request_ready_ || done_) {
        return std::nullopt;
    }
    if (!pending_request_.has_value()) {
        return std::nullopt;
    }
    return pending_request_->tier;
}

Request Job::TakePendingRequest()
{
    Request r = std::move(*pending_request_);
    pending_request_.reset();
    request_ready_ = false;   // 已派发;job 现在在等自己的结果(不再是 ready continuation)
    return r;
}

// [Step 5] control 侧:本次 pending 是否 emit(fire-and-forget)。
bool Job::PendingIsEmit() const
{
    return pending_is_emit_;
}

// [Step 5] control 侧:取走 emit 的 post-submit 回调 + 清 emit 标记(与 TakePendingRequest 配对)。
OnSubmitted Job::TakePendingOnSubmitted()
{
    OnSubmitted cb = std::move(pending_on_submitted_);
    pending_on_submitted_ = nullptr;
    pending_is_emit_      = false;
    return cb;
}

OnCompleted Job::TakePendingOnCompleted()
{
    OnCompleted cb = std::move(pending_on_completed_);
    pending_on_completed_ = nullptr;
    return cb;
}

// control 侧:投结果 + handoff。aco_resume 把 job 从 Exec 的 yield 处推到下一个 yield / done。
void Job::Deliver(ExecResult r)
{
    delivered_ = std::move(r);
    aco_resume(co_);   // 唤醒 job 的 Exec;跑到下一个 yield 或 done
}

// [Step 5] control 侧:emit 无结果 —— 直接恢复 job 到下一 yield / done。
// 与 Deliver 同为 strict-alternation handoff,只是不投 delivered_。
void Job::ResumeAfterEmit()
{
    aco_resume(co_);
}

bool Job::Done() const
{
    return done_;
}

// control 侧:取消 + 回收。若 job 还挂在 exec/emit:置 abort_ 后 aco_resume,让那次调用
// 返回 cancelled/false,job 走 RAII unwind 到结束(is_end);随后 aco_destroy 释放协程
// (save buffer + co)。幂等:co_ 已回收(nullptr)直接返回。
void Job::CancelAndJoin() noexcept
{
    if (co_ == nullptr) {
        return;
    }
    abort_ = true;
    if (co_->is_end == 0) {
        // job 挂在 exec/emit 的 aco_yield 处:恢复它 → 返回取消 → job unwind → aco_exit
        aco_resume(co_);
    }
    aco_destroy(co_);
    co_ = nullptr;
}

// control 侧:job 已 done(is_end)时回收协程资源。幂等(co_ 置空)。
void Job::JoinDone() noexcept
{
    if (co_ != nullptr) {
        aco_destroy(co_);
        co_ = nullptr;
    }
}

// job 协程侧:登记收尾动作。control 在本 job 正常完成后 TakeRetains 执行。
void Job::Retain(std::function<void()> action)
{
    pending_retains_.push_back(std::move(action));
}

// control 侧:取走收尾动作。仅在 JoinDone 之后调(job 协程已结束,无并发)。
std::vector<std::function<void()>> Job::TakeRetains()
{
    return std::move(pending_retains_);
}

} // namespace refuzz::control::job

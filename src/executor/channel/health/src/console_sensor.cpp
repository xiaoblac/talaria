// ConsoleSensor 实现
//
// 设计来源：docs/channel-redesign/v3/50_health.md §4.2 / 40_evidence.md §4
//
// 职责：从 IConsoleSource::ReadLine 消费行流，行级 pattern match，
//       kernel crash / EOF / error 分别 Publish 对应 CrashEvent。
//
// 关键约束：
//   - 所有行读取委托给 IConsoleSource；Sensor 不关心 fd / pipe / connect 细节
//   - Source 的 Open 由装配方负责
//   - step-event snapshot 依赖可选注入的 IStepEventSource
//   - Sensor 在 ReadLine 超时后检查 IsSuspended() → ParkUntilResumed()；
//     源的 Wakeup 由 Poke() 调用负责

#include "refuzz/channel/health/console_sensor.hpp"

#include <chrono>
#include <climits>
#include <cstring>
#include <regex>

namespace refuzz::channel::health {

namespace {

struct CrashPattern {
    const char* prefix;
    CrashKind   kind;
};

// 行级 kernel crash 前缀匹配表（§18.3.4）
constexpr CrashPattern kCrashPatterns[] = {
    // 硬崩溃（原有）。
    {"Kernel panic",       CrashKind::kKernelCrash},
    {"BUG:",               CrashKind::kKernelCrash},  // 含 BUG: KASAN/KCSAN/KMSAN/soft lockup/spinlock...
    {"general protection", CrashKind::kKernelCrash},
    {"KASAN:",             CrashKind::kKernelCrash},
    {"UBSAN:",             CrashKind::kKernelCrash},
    {"WARNING:",           CrashKind::kKernelCrash},  // 含 WARNING: possible circular locking（lockdep 死锁）
    {"unable to handle",   CrashKind::kKernelCrash},  // BUG: unable to handle kernel ...（小写，x86 缺页/空指针）
    // [hung/stall/trap 补齐] 镜像 syzkaller pkg/report/linux.go 的 oops 检测口径。
    // 此前 console sensor 只有上面 7 条硬崩溃，抓不到内核自报的 hung_task / rcu stall /
    // lockdep / 各类 trap —— 而心跳只能抓“整机/worker 卡死”，抓不到“单个 task 在 D 态挂住
    // 但系统仍在跑”的 hung_task。分类统一 kKernelCrash（sensor 层不细分），具体 title
    //（task hung / rcu stall / ...）由下游 kernel_report_parser 从抓取的 console 上下文判定。
    {"blocked for more than",             CrashKind::kKernelCrash},  // INFO: task <x> blocked for more than N seconds（hung task）
    {"blocked in I/O wait for more than", CrashKind::kKernelCrash},  // hung task 的 I/O wait 变体
    {"can't die for more than",           CrashKind::kKernelCrash},  // INFO: task <x> can't die for more than N seconds
    {"detected stall",                    CrashKind::kKernelCrash},  // INFO: rcu_(preempt|sched|bh) [self-]detected stall（RCU stall）
    {"trying to register non-static key", CrashKind::kKernelCrash},  // INFO: trying to register non-static key（lockdep）
    {"kernel BUG at",                     CrashKind::kKernelCrash},  // kernel BUG at file.c:line!（BUG_ON）
    {"invalid opcode:",                   CrashKind::kKernelCrash},  // invalid opcode: 0000（含 BUG()→ud2）
    {"divide error:",                     CrashKind::kKernelCrash},  // divide error: 0000
    {"stack segment:",                    CrashKind::kKernelCrash},  // stack segment: 0000
    {"Unable to handle kernel",           CrashKind::kKernelCrash},  // 大写变体（非 x86 缺页/paging request）
};

bool MatchCrashPattern(const std::string& line, CrashKind& out_kind) {
    for (const auto& p : kCrashPatterns) {
        if (line.find(p.prefix) != std::string::npos) {
            out_kind = p.kind;
            return true;
        }
    }
    return false;
}

// [mand-mount 误判修复] kCrashPatterns 的 "WARNING:" 前缀是纯子串匹配，不区分
// 真崩溃和内核自报的已知无害提示（deprecation / mount 提示 / mitigation 文案等）。
// 命中这类行会把 sensor 状态机推进 COLLECTING_POST，导致两个后果：
//   (1) 若后续 post-context 收满 → ReportCrash(kKernelCrash, kSerialPattern)，
//       corroborated（inferred 默认 false）→ EscalationPolicy 立即 reboot VM，
//       在 mount 密集型程序上造成误报 reboot 风暴；
//   (2) 若在收满前串口 EOF（VM 真死）→ kEof 分支复用这行已收集的 post_context_
//       当作 kVmDead 事件的 fragment.title，把真实死因错误地标成这条无害 WARNING。
// 与 crash/components/symbolizer/kernel_report_parser.cpp 的 kBenignReportRegex
// 同源（该文件镜像 syzkaller pkg/report/linux.go:2168-2180 的 WARNING oops
// suppression 表，11 条完整对应）。console_sensor 所在的 refuzz_channel 不能反向
// 依赖 refuzz_crash（crash 依赖 channel，见 crash/CMakeLists.txt），故在此单独维护
// 一份，两处修改需同步。
const std::regex kBenignWarningPatterns(
    R"((?:)"
    R"(WARNING: /etc/ssh/moduli does not exist)"
    R"(|WARNING: workqueue cpumask: online intersect > possible intersect)"
    R"(|WARNING: [Tt]he mand mount option)"
    R"(|WARNING: Unsupported flag value\(s\) of 0x.* in DT_FLAGS_1)"
    R"(|WARNING: Unprivileged eBPF is enabled with eIBRS)"
    R"(|WARNING: fbcon: Driver .* missed to adjust virtual screen size)"
    R"(|WARNING: See https.* for mitigation options\.)"
    R"(|WARNING: kernel not compiled with CPU_SRSO)"
    R"(|WARNING: .* uses (?:deprecated v2 capabilities|wireless extensions))"
    R"(|EXT4-[Ff][Ss](?: \(.*\))?:)"
    R"(|XFS \(\w+\): WARNING)"
    R"())",
    std::regex::icase);

bool MatchBenignPattern(const std::string& line) {
    return std::regex_search(line, kBenignWarningPatterns);
}

uint64_t NowUs() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

} // namespace

ConsoleSensor::ConsoleSensor(evidence::IConsoleSource*    console_source,
                             evidence::IStepEventSource*  step_source,
                             ConsoleSensorConfig          config,
                             evidence::ConsoleRingBuffer* ring_buffer) noexcept
    : console_source_(console_source)
    , step_source_(step_source)
    , config_(std::move(config))
    , ring_buffer_(ring_buffer) {
}

ConsoleSensor::~ConsoleSensor() {
    Stop();
}

Result<void> ConsoleSensor::Start(HealthPublisher& publisher) {
    if (thread_running_) {
        return Error{ErrorKind::kConnection,
                     "ConsoleSensor::Start() called while already running"};
    }
    if (console_source_ == nullptr) {
        return Error{ErrorKind::kConnection,
                     "ConsoleSensor::Start(): console_source is null"};
    }
    // 注：此处不强制 CurrentState()==kOpen；Sensor 启动后 ThreadMain 会按 Source
    // 当前 state 分派行为（已 kEof/kError 时立即上报相应事件后退出）。
    // 这样 Reboot 场景下，即便 Source 尚未重 Open，Sensor 也能自洽退出而不阻塞。

    publisher_ = &publisher;
    state_     = State::IDLE;
    pre_context_.clear();
    post_context_.clear();
    stop_flag_.store(false, std::memory_order_relaxed);
    thread_        = std::thread(&ConsoleSensor::ThreadMain, this);
    thread_running_ = true;
    return Result<void>::Ok();
}

void ConsoleSensor::Stop() {
    if (!thread_running_) return;
    stop_flag_.store(true, std::memory_order_release);
    if (console_source_) console_source_->Wakeup();
    if (thread_.joinable()) thread_.join();
    thread_running_ = false;
}

void ConsoleSensor::Poke() {
    if (console_source_) console_source_->Wakeup();
}

void ConsoleSensor::ThreadMain() {
    while (true) {
        if (stop_flag_.load(std::memory_order_acquire)) return;

        // 进入 suspend：park 等 resume；Source 由 Wakeup 唤醒 ReadLine 返回 nullopt
        if (publisher_ && publisher_->IsSuspended()) {
            state_ = State::IDLE;
            pre_context_.clear();
            post_context_.clear();
            publisher_->ParkUntilResumed();
            if (stop_flag_.load(std::memory_order_acquire)) return;
            continue;
        }

        auto maybe_line = console_source_->ReadLine(config_.read_line_timeout);
        if (maybe_line.has_value()) {
            // §3.11-B — 旁路写一份到共享 ring buffer，让 HeartbeatSensor /
            // 其它 sensor 在不消费源流的前提下能拿到最近 console 上下文。
            if (ring_buffer_ != nullptr) {
                ring_buffer_->Push(*maybe_line);
            }
            ProcessLine(*maybe_line);
            continue;
        }

        // ReadLine 返回 nullopt：可能是超时 / EOF / error / idle；分状态处理
        auto st = console_source_->CurrentState();
        if (st == evidence::IConsoleSource::State::kIdle) {
            // Source 未 Open（或已 Close）：按"永久 park"语义通知并退出线程，
            // 避免在 Reboot 场景下 Sensor 空循环 ReadLine。
            if (publisher_) publisher_->NotifyThreadExiting();
            return;
        }
        if (st == evidence::IConsoleSource::State::kEof) {
            // VM 退出：Publish kVmDead 然后退出线程
            if (publisher_) ReportCrash(CrashKind::kVmDead, CrashEventOrigin::kSerialEof);
            if (publisher_) publisher_->NotifyThreadExiting();
            return;
        }
        if (st == evidence::IConsoleSource::State::kError) {
            // 不可恢复错误：Publish kHealthInternalFault 后退出线程
            if (publisher_) {
                CrashFragment frag;
                frag.kind             = CrashKind::kHealthInternalFault;
                frag.source_worker_id = UINT32_MAX;
                frag.title            = "ConsoleSensor: console source error";

                CrashEvent ev;
                ev.event_id       = 0;
                ev.origin         = CrashEventOrigin::kHealthInternal;
                ev.vm_epoch       = 0;
                ev.detected_ts_us = NowUs();
                ev.fragment       = std::move(frag);
                ev.checker_name   = "console";
                ev.errno_value    = 0;
                publisher_->Publish(std::move(ev));
                publisher_->NotifyThreadExiting();
            }
            return;
        }
        // 超时：回到 while(!stop_flag_) 检查 Suspend 状态再读
    }
}

void ConsoleSensor::ProcessLine(const std::string& line) {
    switch (state_) {
    case State::IDLE: {
        pre_context_.push_back(line);
        if (pre_context_.size() > config_.pre_context_lines) {
            pre_context_.pop_front();
        }
        CrashKind kind;
        if (MatchCrashPattern(line, kind) && !MatchBenignPattern(line)) {
            state_        = State::COLLECTING_POST;
            pending_kind_ = kind;
            post_context_.clear();
            post_context_.push_back(line);
        }
        break;
    }
    case State::COLLECTING_POST: {
        post_context_.push_back(line);
        if (post_context_.size() >= static_cast<size_t>(config_.post_context_lines) + 1) {
            ReportCrash(pending_kind_, CrashEventOrigin::kSerialPattern);
            state_ = State::IDLE;
        }
        break;
    }
    }
}

void ConsoleSensor::ReportCrash(CrashKind kind, CrashEventOrigin origin) {
    if (publisher_ == nullptr) return;

    CrashFragment fragment;
    fragment.kind             = kind;
    fragment.source_worker_id = UINT32_MAX;

    switch (kind) {
    case CrashKind::kKernelCrash:
        fragment.type = refuzz::channel::CrashType::kPanic; break;
    case CrashKind::kVmDead:
    case CrashKind::kWorkerDead:
    case CrashKind::kHealthInternalFault:
    case CrashKind::kNoOutput:
        fragment.type = refuzz::channel::CrashType::kUnknown; break;
    }

    fragment.serial_lines.reserve(pre_context_.size() + post_context_.size());
    for (const auto& l : pre_context_)   fragment.serial_lines.push_back(l);
    for (const auto& l : post_context_)  fragment.serial_lines.push_back(l);

    fragment.title = post_context_.empty() ? std::string{} : post_context_.front();
    for (const auto& l : fragment.serial_lines) {
        fragment.console_output.append(l);
        fragment.console_output.push_back('\n');
    }

    if (config_.capture_step_events && step_source_ != nullptr
        && step_source_->IsAvailable()) {
        fragment.step_event_snapshot = step_source_->Snapshot();
    }

    CrashEvent ev;
    ev.event_id       = 0;
    ev.origin         = origin;
    ev.vm_epoch       = 0;
    ev.detected_ts_us = NowUs();
    ev.fragment       = std::move(fragment);
    ev.checker_name.clear();
    ev.errno_value    = 0;
    publisher_->Publish(std::move(ev));
}

} // namespace refuzz::channel::health

#include "refuzz/channel/control/control_plane.hpp"
#include "refuzz/channel/control/ivshmem_control_plane.hpp"
#include "refuzz/channel/control/registration_hook.hpp"
#include "refuzz/channel/data/ivshmem_data_plane.hpp"
#include "refuzz/channel/infra/shm_infra.hpp"
#include "refuzz/proto_wire/ivshmem_protocol.h"

#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace data = refuzz::channel::data;
namespace infra = refuzz::channel::infra;
namespace control = refuzz::channel::control;

namespace {

#define CHECK(cond)                                                                  \
    do {                                                                             \
        if (!(cond)) {                                                               \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__);   \
            return 1;                                                                \
        }                                                                            \
    } while (0)

#define RUN_TEST(fn)                                                                 \
    do {                                                                             \
        std::fprintf(stderr, "  [RUN] %s\n", #fn);                                  \
        const int rc = fn();                                                         \
        if (rc != 0) {                                                               \
            std::fprintf(stderr, "  [FAIL] %s\n", #fn);                             \
            return rc;                                                               \
        }                                                                            \
        std::fprintf(stderr, "  [PASS] %s\n", #fn);                                 \
    } while (0)

std::string TempPath(const char* suffix)
{
    static std::atomic<uint32_t> counter{0};
    return "/tmp/refuzz_ivshmem_v3_" + std::to_string(static_cast<long long>(::getpid())) +
           "_" + std::to_string(counter.fetch_add(1)) + "_" + suffix;
}

std::shared_ptr<infra::ShmInfra> MakeShm(const std::string& path, uint32_t n_workers = 1)
{
    infra::InfraConfig cfg;
    cfg.shm_path = path;
    cfg.n_workers = n_workers;
    cfg.step_event_ring_capacity = 8;

    auto shm = std::make_shared<infra::ShmInfra>(std::move(cfg));
    auto r = shm->Init();
    if (!r.ok()) {
        std::fprintf(stderr, "ShmInfra::Init failed: %s\n", r.error().message.c_str());
        return nullptr;
    }
    return shm;
}

data::IvshmemDataPlane MakeDataPlane(const std::shared_ptr<infra::ShmInfra>& shm)
{
    auto worker = shm->worker(0);
    if (worker.valid()) {
        __atomic_store_n(&worker.ctrl()->host_state,
                         static_cast<uint32_t>(HOST_REG_GRANTED),
                         __ATOMIC_RELEASE);
        __atomic_store_n(&worker.ctrl()->guest_state,
                         static_cast<uint32_t>(GUEST_REG_READY),
                         __ATOMIC_RELEASE);
    }
    refuzz::channel::control::SendabilityView sendability;
    sendability.is_registered = [](uint32_t) { return true; };
    sendability.registered_worker_count = [] { return 1u; };

    data::IvshmemDataPlaneOptions options;
    options.shm_path = shm->Backbone()->ShmPath();
    options.use_doorbell = false;
    options.poll_sleep_us = std::chrono::microseconds{100};

    return data::IvshmemDataPlane(
        shm->Backbone(),
        shm.get(),
        std::move(sendability),
        refuzz::channel::control::RegistrationControlHook{},
        std::move(options));
}

int test_submit_requires_domain_ready()
{
    const std::string path = TempPath("domain_ready");
    auto shm = MakeShm(path);
    CHECK(shm != nullptr);
    auto dp = MakeDataPlane(shm);
    auto worker = shm->worker(0);
    CHECK(worker.valid());

    const uint8_t payload = 0x5a;
    data::IDataPlane::SubmitInput req;
    req.worker_id = 0;
    req.executor_id = 1;
    req.dispatch_gen = 1;
    req.payload_data = &payload;
    req.payload_size = sizeof(payload);

    __atomic_store_n(&worker.ctrl()->guest_state,
                     static_cast<uint32_t>(GUEST_REG_CLAIMED),
                     __ATOMIC_RELEASE);
    CHECK(dp.Submit(req) == data::SubmitOutcome::kWorkerDown);
    CHECK(__atomic_load_n(&worker.task_slot()->state, __ATOMIC_ACQUIRE) ==
          static_cast<uint32_t>(TASK_EMPTY));

    __atomic_store_n(&worker.ctrl()->guest_state,
                     static_cast<uint32_t>(GUEST_REG_READY),
                     __ATOMIC_RELEASE);
    CHECK(dp.Submit(req) == data::SubmitOutcome::kSent);

    ::unlink(path.c_str());
    return 0;
}

void StoreTaskState(TaskSlot* slot, TaskSlotState state)
{
    __atomic_store_n(&slot->state, static_cast<uint32_t>(state), __ATOMIC_RELEASE);
}

void StoreCompletionState(CompletionSlot* slot, CompletionSlotState state)
{
    __atomic_store_n(&slot->state, static_cast<uint32_t>(state), __ATOMIC_RELEASE);
}

int test_v3_header_explicit_layout()
{
    const std::string path = TempPath("layout");
    auto shm = MakeShm(path, 2);
    CHECK(shm != nullptr);

    const auto* hdr = shm->Backbone()->Header();
    CHECK(hdr->magic == IVSHMEM_MAGIC);
    CHECK(hdr->version == PROTOCOL_VERSION);
    CHECK(shm->ReadCorpusTriaged() == 0);
    shm->WriteCorpusTriaged(1);
    CHECK(shm->ReadCorpusTriaged() == 1);
    CHECK(shm_header_has_v3_layout(hdr));
    CHECK(hdr->control_region_offset == get_control_region_offset_v3());
    CHECK(hdr->control_region_size == get_control_region_size_v3(2));
    CHECK(hdr->data_region_offset == get_data_region_offset_v3(2));
    CHECK(hdr->data_region_size == get_data_region_size_v3(2));
    CHECK(hdr->step_ring_offset == get_step_event_ring_offset_v3(2));
    CHECK(hdr->step_ring_size == get_step_event_ring_size_v3(8));
    CHECK(hdr->per_worker_control_stride == get_worker_control_stride_v3());
    CHECK(hdr->per_worker_data_stride == get_worker_data_stride_v3());
    CHECK(hdr->data_input_offset == offsetof(WorkerDataWindowV3, input_pool));
    CHECK(hdr->data_output_offset == offsetof(WorkerDataWindowV3, output_pool));
    CHECK(hdr->data_result_offset == offsetof(WorkerDataWindowV3, result_page));

    auto base = reinterpret_cast<uintptr_t>(shm->Backbone()->Base());
    auto w0 = shm->worker(0);
    auto w1 = shm->worker(1);
    CHECK(w0.valid());
    CHECK(w1.valid());
    CHECK(reinterpret_cast<uintptr_t>(w0.ctrl()) ==
          base + hdr->control_region_offset);
    CHECK(reinterpret_cast<uintptr_t>(w1.ctrl()) ==
          base + hdr->control_region_offset + hdr->per_worker_control_stride);
    CHECK(reinterpret_cast<uintptr_t>(w0.input_pool()) ==
          base + hdr->data_region_offset + hdr->data_input_offset);
    CHECK(reinterpret_cast<uintptr_t>(w1.output_pool()) ==
          base + hdr->data_region_offset + hdr->per_worker_data_stride +
              hdr->data_output_offset);
    CHECK(reinterpret_cast<uintptr_t>(w1.result_page()) ==
          base + hdr->data_region_offset + hdr->per_worker_data_stride +
              hdr->data_result_offset);
    CHECK(reinterpret_cast<uintptr_t>(shm->StepEventHeader()) ==
          base + hdr->step_ring_offset);
    // V3 显式 region 字段写下的 step_ring_offset 必须等于公开 helper 算出来的值。
    // 这里同时校验 helper 与 header 不漂移。
    CHECK(hdr->step_ring_offset == get_step_event_ring_offset_v3(2));

    ::unlink(path.c_str());
    return 0;
}

int test_control_reset_preserves_proc_state()
{
    const std::string path = TempPath("proc-state-reset");
    auto shm = MakeShm(path);
    CHECK(shm != nullptr);

    control::IvshmemControlPlane cp(
        shm->Backbone(), shm.get(), control::SessionTiming{});
    WorkerCtrl* ctrl = shm->worker(0).ctrl();
    ctrl->active_proc_id = 7;
    ctrl->proc_epoch = 9;
    ctrl->proc_state_magic = PROC_ID_STATE_MAGIC;
    ctrl->dirty_proc_mask = (1u << 7);
    ctrl->cancel_requested = 1;
    CHECK(cp.ResetWorkerSession(0).ok());
    CHECK(ctrl->active_proc_id == 7);
    CHECK(ctrl->proc_epoch == 9);
    CHECK(ctrl->proc_state_magic == PROC_ID_STATE_MAGIC);
    CHECK(ctrl->dirty_proc_mask == (1u << 7));
    CHECK(ctrl->cancel_requested == 0);

    ctrl->active_proc_id = 11;
    ctrl->proc_epoch = 13;
    CHECK(cp.ResetSession().ok());
    CHECK(ctrl->active_proc_id == 11);
    CHECK(ctrl->proc_epoch == 13);
    CHECK(ctrl->proc_state_magic == PROC_ID_STATE_MAGIC);
    CHECK(ctrl->dirty_proc_mask == (1u << 7));

    CHECK(cp.ClearProcIsolationState().ok());
    CHECK(ctrl->active_proc_id == PROC_ID_ANY);
    CHECK(ctrl->proc_epoch == 0);
    CHECK(ctrl->proc_state_magic == 0);
    CHECK(ctrl->dirty_proc_mask == 0);

    __atomic_store_n(&ctrl->error_latch,
                     ERR_DOMAIN_REPLACEMENT_START_FAILED,
                     __ATOMIC_RELEASE);
    CHECK(cp.ConsumeWorkerError(0) ==
          ERR_DOMAIN_REPLACEMENT_START_FAILED);
    CHECK(cp.ConsumeWorkerError(0) == ERR_OK);

    ::unlink(path.c_str());
    return 0;
}

int test_reset_does_not_clobber_concurrent_dirty_publish()
{
    const std::string path = TempPath("reset-dirty-race");
    auto shm = MakeShm(path);
    CHECK(shm != nullptr);

    control::IvshmemControlPlane cp(
        shm->Backbone(), shm.get(), control::SessionTiming{});
    WorkerCtrl* ctrl = shm->worker(0).ctrl();
    __atomic_store_n(&ctrl->dirty_proc_mask, (1u << 3), __ATOMIC_RELEASE);

    // 模拟旧 guest 在 ResetSession 期间继续发布新的 dirty mask。host 不得
    // 回写该字段（旧的“整块 memset + 快照回写”会覆盖快照后的新发布）。
    std::atomic<bool> stop{false};
    std::atomic<uint32_t> last_published{0};
    std::thread publisher([&] {
        uint32_t mask = 1u << 3;
        uint32_t i = 0;
        while (!stop.load(std::memory_order_acquire)) {
            mask |= (1u << (4u + (i % 20u)));
            __atomic_store_n(&ctrl->dirty_proc_mask, mask, __ATOMIC_RELEASE);
            last_published.store(mask, std::memory_order_release);
            ++i;
        }
    });

    // 确保发布线程已经跑起来并至少写了一次，再开始 ResetSession。
    while (last_published.load(std::memory_order_acquire) == 0) {
        std::this_thread::yield();
    }
    CHECK(cp.ResetSession().ok());
    stop.store(true, std::memory_order_release);
    publisher.join();

    const uint32_t expected = last_published.load(std::memory_order_acquire);
    CHECK(expected != 0);
    // 最终值必须等于 guest 最后一次发布，而不是 ResetSession 的旧快照。
    CHECK(__atomic_load_n(&ctrl->dirty_proc_mask, __ATOMIC_ACQUIRE) == expected);

    // 会话字段仍被清掉。
    CHECK(__atomic_load_n(&ctrl->cancel_requested, __ATOMIC_ACQUIRE) == 0);

    ::unlink(path.c_str());
    return 0;
}

int test_control_starts_domains_one_worker_at_a_time()
{
    const std::string path = TempPath("serialized-domain-ready");
    auto shm = MakeShm(path, 2);
    CHECK(shm != nullptr);

    control::SessionTiming timing{};
    timing.wait_ready_poll_us = std::chrono::microseconds{100};
    control::IvshmemControlPlane cp(shm->Backbone(), shm.get(), timing);
    CHECK(cp.BeginSession().ok());

    std::atomic<int> wait_result{-1};
    std::thread waiter([&]() {
        const auto result = cp.WaitAllWorkersReady(std::chrono::milliseconds(500));
        wait_result.store(result.ok() ? 0 : 1, std::memory_order_release);
    });

    for (uint32_t worker_id = 0; worker_id < 2; ++worker_id) {
        WorkerCtrl* ctrl = shm->worker(worker_id).ctrl();
        __atomic_store_n(&ctrl->guest_state,
                         static_cast<uint32_t>(GUEST_REG_CLAIMED),
                         __ATOMIC_RELEASE);
    }

    const auto first_grant_deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(250);
    WorkerCtrl* first = shm->worker(0).ctrl();
    WorkerCtrl* second = shm->worker(1).ctrl();
    bool first_granted = false;
    while (std::chrono::steady_clock::now() < first_grant_deadline) {
        first_granted =
            __atomic_load_n(&first->host_state, __ATOMIC_ACQUIRE) ==
            static_cast<uint32_t>(HOST_REG_GRANTED);
        if (first_granted) break;
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    }

    const bool second_withheld =
        __atomic_load_n(&second->host_state, __ATOMIC_ACQUIRE) !=
        static_cast<uint32_t>(HOST_REG_GRANTED);
    const uint32_t registered_before_first_ready = cp.RegisteredWorkerCount();
    __atomic_store_n(&first->guest_state,
                     static_cast<uint32_t>(GUEST_REG_READY),
                     __ATOMIC_RELEASE);

    const auto second_grant_deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(250);
    bool second_granted = false;
    while (std::chrono::steady_clock::now() < second_grant_deadline) {
        second_granted =
            __atomic_load_n(&second->host_state, __ATOMIC_ACQUIRE) ==
            static_cast<uint32_t>(HOST_REG_GRANTED);
        if (second_granted) break;
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    }
    const uint32_t registered_before_second_ready = cp.RegisteredWorkerCount();
    __atomic_store_n(&second->guest_state,
                     static_cast<uint32_t>(GUEST_REG_READY),
                     __ATOMIC_RELEASE);
    waiter.join();

    CHECK(first_granted);
    CHECK(second_withheld);
    CHECK(registered_before_first_ready == 1);
    CHECK(second_granted);
    CHECK(registered_before_second_ready == 2);
    CHECK(wait_result.load(std::memory_order_acquire) == 0);

    ::unlink(path.c_str());
    return 0;
}

int test_wait_worker_ready_completes_session_after_last_worker()
{
    const std::string path = TempPath("per-worker-domain-ready");
    auto shm = MakeShm(path, 2);
    CHECK(shm != nullptr);

    control::SessionTiming timing{};
    timing.wait_ready_poll_us = std::chrono::microseconds{100};
    control::IvshmemControlPlane cp(shm->Backbone(), shm.get(), timing);
    CHECK(cp.BeginSession().ok());

    for (uint32_t worker_id = 0; worker_id < 2; ++worker_id) {
        WorkerCtrl* ctrl = shm->worker(worker_id).ctrl();
        __atomic_store_n(&ctrl->guest_state,
                         static_cast<uint32_t>(GUEST_REG_READY),
                         __ATOMIC_RELEASE);
        CHECK(cp.WaitWorkerReady(worker_id, std::chrono::milliseconds{100}).ok());
        const auto expected = worker_id == 0
            ? control::SessionState::kHandshaking
            : control::SessionState::kReady;
        CHECK(cp.CurrentState() == expected);
    }

    ::unlink(path.c_str());
    return 0;
}

int test_heartbeat_sample_requires_registration()
{
    const std::string path = TempPath("heartbeat-registration");
    auto shm = MakeShm(path);
    CHECK(shm != nullptr);

    control::SessionTiming timing{};
    timing.wait_ready_poll_us = std::chrono::microseconds{100};
    control::IvshmemControlPlane cp(shm->Backbone(), shm.get(), timing);
    WorkerCtrl* ctrl = shm->worker(0).ctrl();

    CHECK(!cp.SampleHeartbeat(0).valid);
    CHECK(cp.BeginSession().ok());
    __atomic_store_n(&ctrl->guest_state,
                     static_cast<uint32_t>(GUEST_REG_READY),
                     __ATOMIC_RELEASE);
    CHECK(cp.WaitWorkerReady(0, std::chrono::milliseconds{100}).ok());

    const auto registered = cp.SampleHeartbeat(0);
    CHECK(registered.valid);

    cp.RevokeWorker(0);
    CHECK(!cp.SampleHeartbeat(0).valid);

    ::unlink(path.c_str());
    return 0;
}

// [心跳重定义] counter 不再是 ctrl->heartbeat_counter 的透传,而是执行状态机的**进度令牌**:
//   daemon 每推进一步就变。语义从"存在性"换成"进度",host 不再向 guest 索要存活证明。
//   本例锁住两条性质:(1) 无人推进 → 令牌恒定(否则健康的空闲 worker 会被判死);
//   (2) 任一状态机分量推进 → 令牌必变(否则真卡住的 worker 抓不到)。
int test_heartbeat_counter_is_progress_token()
{
    const std::string path = TempPath("heartbeat-progress-token");
    auto shm = MakeShm(path);
    CHECK(shm != nullptr);

    control::SessionTiming timing{};
    timing.wait_ready_poll_us = std::chrono::microseconds{100};
    control::IvshmemControlPlane cp(shm->Backbone(), shm.get(), timing);
    WorkerCtrl* ctrl = shm->worker(0).ctrl();

    CHECK(cp.BeginSession().ok());
    __atomic_store_n(&ctrl->guest_state,
                     static_cast<uint32_t>(GUEST_REG_READY),
                     __ATOMIC_RELEASE);
    CHECK(cp.WaitWorkerReady(0, std::chrono::milliseconds{100}).ok());

    // 没有任何推进 → 令牌必须恒定。旧心跳靠一个独立 RT 线程自增,"不动"就意味着死;
    //   新令牌由执行路径写,"不动"是空闲的正常状态,只有累够 miss_threshold 才判死。
    const uint64_t baseline = cp.SampleHeartbeat(0).counter;
    CHECK(cp.SampleHeartbeat(0).counter == baseline);

    // 每个分量单独推进都必须改变令牌 —— 它们分别对应 DomainSupervisor 的一次状态迁移:
    //   start_ts_us 进 kExecuting / exec_seq 出 kExecuting /
    //   proc_epoch 进 kStarting(daemon 在自救)/ guest_state 进出 {kReady,kExecuting}
    CompletionSlot* comp = shm->worker(0).completion_slot();
    uint64_t prev = baseline;

    __atomic_store_n(&comp->start_ts_us, 12345ULL, __ATOMIC_RELEASE);  // 取到任务
    const uint64_t after_start = cp.SampleHeartbeat(0).counter;
    CHECK(after_start != prev);
    prev = after_start;

    __atomic_store_n(&comp->exec_seq, 1ULL, __ATOMIC_RELEASE);         // 发布结果
    const uint64_t after_seq = cp.SampleHeartbeat(0).counter;
    CHECK(after_seq != prev);
    prev = after_seq;

    __atomic_store_n(&ctrl->proc_epoch, 7U, __ATOMIC_RELEASE);         // daemon 轮换 domain 自救
    const auto after_epoch = cp.SampleHeartbeat(0);
    CHECK(after_epoch.counter != prev);
    prev = after_epoch.counter;
    // 分量要能被单独读出来:判死日志靠 proc_epoch 区分"卡的是 daemon 还是被测程序"。
    CHECK(after_epoch.proc_epoch == 7U);
    CHECK(after_epoch.guest_state == static_cast<uint32_t>(GUEST_REG_READY));

    task_slot_store_state_v3(shm->worker(0).task_slot(), TASK_TAKEN);  // 槽状态迁移
    const auto after_task = cp.SampleHeartbeat(0);
    CHECK(after_task.counter != prev);
    // CP 把 wire 值翻成共享语义(sensor/telemetry/renderer 都不该认识 TASK_* 的编码)
    CHECK(after_task.slot ==
          refuzz::core::channel_contract::WorkerSlotState::kExecuting);

    ::unlink(path.c_str());
    return 0;
}

int test_host_completion_slot_is_commit_edge()
{
    const std::string path = TempPath("commit");
    auto shm = MakeShm(path);
    CHECK(shm != nullptr);
    auto dp = MakeDataPlane(shm);

    const uint8_t payload[4] = {1, 2, 3, 4};
    data::IDataPlane::SubmitInput req;
    req.worker_id = 0;
    req.proc_id = 2;
    req.executor_id = 11;
    req.dispatch_gen = 3;
    req.payload_data = payload;
    req.payload_size = sizeof(payload);
    req.exec_flags = TASK_FLAG_TRACE_SAMPLED;
    CHECK(dp.Submit(req) == data::SubmitOutcome::kSent);

    auto wv = shm->worker(0);
    CHECK(wv.valid());

    const uint8_t output[3] = {9, 8, 7};
    std::memcpy(wv.output_pool(), output, sizeof(output));
    auto* page = wv.result_page();
    page->executor_id = req.executor_id;
    page->dispatch_gen = req.dispatch_gen;
    page->output_len = sizeof(output);
    page->result_kind = 1;
    program_result_store_commit_seq_v3(page, 1);
    program_result_store_state_v3(page, PROGRAM_RESULT_COMMITTED);

    std::vector<data::DispatchOutcome> out;
    dp.Poll(out, std::chrono::microseconds{0});
    CHECK(out.empty());

    auto* task = wv.task_slot();
    CHECK(__atomic_load_n(&task->proc_id, __ATOMIC_ACQUIRE) == req.proc_id);
    StoreTaskState(task, TASK_TAKEN);
    // Guest replaces the requested value with the actual domain identity
    // before publishing completion.
    __atomic_store_n(&task->proc_id, 4u, __ATOMIC_RELEASE);
    auto* completion = wv.completion_slot();
    completion->executor_id = 99;
    completion->dispatch_gen = req.dispatch_gen;
    completion->status = COMP_STATUS_OK;
    completion->error_code = 0;
    completion->crash_signal = 0;
    completion->output_off = 0;
    completion->output_len = sizeof(output);
    completion->exec_seq = 1;
    StoreCompletionState(completion, COMP_READY);

    dp.Poll(out, std::chrono::microseconds{0});
    CHECK(out.empty());
    CHECK(__atomic_load_n(&completion->state, __ATOMIC_ACQUIRE) ==
          static_cast<uint32_t>(COMP_EMPTY));
    CHECK(__atomic_load_n(&task->state, __ATOMIC_ACQUIRE) ==
          static_cast<uint32_t>(TASK_TAKEN));

    completion->executor_id = req.executor_id;
    completion->dispatch_gen = req.dispatch_gen;
    StoreCompletionState(completion, COMP_READY);

    dp.Poll(out, std::chrono::microseconds{0});
    CHECK(out.size() == 1);
    CHECK(out[0].executor_id == req.executor_id);
    CHECK(out[0].dispatch_gen == req.dispatch_gen);
    CHECK(out[0].proc_id == 4u);
    CHECK(out[0].kind == data::DispatchOutcomeKind::kHarnessFatal);
    CHECK(out[0].error_code == ERR_HARNESS_FORK_SERVER_PROTOCOL);
    CHECK(out[0].output.empty());

    data::IDataPlane::SubmitInput req2 = req;
    req2.executor_id = 12;
    req2.dispatch_gen = 4;
    CHECK(dp.Submit(req2) == data::SubmitOutcome::kSent);
    out.clear();
    wv = shm->worker(0);
    task = wv.task_slot();
    StoreTaskState(task, TASK_TAKEN);
    completion = wv.completion_slot();
    completion->executor_id = req2.executor_id;
    completion->dispatch_gen = req2.dispatch_gen;
    completion->status = COMP_STATUS_OK;
    completion->error_code = 0;
    completion->crash_signal = 0;
    completion->output_off = 0;
    completion->output_len = sizeof(output);
    completion->exec_seq = 1;
    StoreCompletionState(completion, COMP_READY);

    dp.Poll(out, std::chrono::microseconds{0});
    CHECK(out.empty());

    completion->exec_seq = 2;
    StoreCompletionState(completion, COMP_READY);
    dp.Poll(out, std::chrono::microseconds{0});
    CHECK(out.size() == 1);
    CHECK(out[0].executor_id == req2.executor_id);
    CHECK(out[0].dispatch_gen == req2.dispatch_gen);
    CHECK(out[0].proc_id == req2.proc_id);
    CHECK(out[0].kind == data::DispatchOutcomeKind::kOk);
    CHECK(out[0].completion_observed_host_ts_us != 0);
    CHECK(out[0].output_copied_host_ts_us >=
          out[0].completion_observed_host_ts_us);

    ::unlink(path.c_str());
    return 0;
}

int test_start_ack_refreshes_for_same_executor_redispatch()
{
    const std::string path = TempPath("start_ack_retry");
    auto shm = MakeShm(path);
    CHECK(shm != nullptr);
    auto dp = MakeDataPlane(shm);

    data::IDataPlane::SubmitInput req;
    req.worker_id = 0;
    req.executor_id = 77;
    req.dispatch_gen = 1;
    req.exec_flags = TASK_FLAG_TRACE_SAMPLED;
    CHECK(dp.Submit(req) == data::SubmitOutcome::kSent);

    auto wv = shm->worker(0);
    auto* task = wv.task_slot();
    auto* completion = wv.completion_slot();
    __atomic_store_n(&task->worker_started_executor_id, req.executor_id, __ATOMIC_RELEASE);
    StoreTaskState(task, TASK_TAKEN);
    completion->executor_id = req.executor_id;
    completion->dispatch_gen = req.dispatch_gen;
    completion->status = COMP_STATUS_OK;
    completion->error_code = 0;
    completion->crash_signal = 0;
    completion->output_off = 0;
    completion->output_len = 0;
    completion->exec_seq = 1;
    StoreCompletionState(completion, COMP_READY);

    std::vector<data::DispatchOutcome> out;
    dp.Poll(out, std::chrono::microseconds{0});
    CHECK(out.size() == 1);
    const uint64_t first_ack_us = out[0].worker_start_ack_host_ts_us;
    CHECK(first_ack_us != 0);
    CHECK(out[0].completion_observed_host_ts_us >= first_ack_us);
    CHECK(out[0].output_copied_host_ts_us >=
          out[0].completion_observed_host_ts_us);

    ::usleep(1000);
    req.dispatch_gen = 2;
    CHECK(dp.Submit(req) == data::SubmitOutcome::kSent);
    CHECK(__atomic_load_n(&task->worker_started_executor_id, __ATOMIC_ACQUIRE) == 0);
    __atomic_store_n(&task->worker_started_executor_id, req.executor_id, __ATOMIC_RELEASE);
    StoreTaskState(task, TASK_TAKEN);
    completion->executor_id = req.executor_id;
    completion->dispatch_gen = req.dispatch_gen;
    completion->exec_seq = 2;
    StoreCompletionState(completion, COMP_READY);

    out.clear();
    dp.Poll(out, std::chrono::microseconds{0});
    CHECK(out.size() == 1);
    CHECK(out[0].worker_start_ack_host_ts_us > first_ack_us);

    ::unlink(path.c_str());
    return 0;
}

// 连跑两条 program，第二条只完成了 result page commit、CompletionSlot 还没
// publish 就被 host 当作 stale 丢弃；接着 host 提交第三条任务（同 worker），
// 验证：
//   1. 第二条 result page 的残留(output_len/result_kind/progress) **不会**
//      从 V3 header 的 commit-edge 漏给 host —— 因为 host 仍然只看
//      CompletionSlot.state=COMP_READY。
//   2. 旧 exec_seq <= last_completion_exec_seq_ 的 completion 被拒。
//   3. 新一轮 (exec_seq 单调) + 匹配 executor_id/dispatch_gen 的 completion
//      正常 sweep，且 output 内容是新一轮的、不是上一轮的。
int test_v3_stale_result_isolation()
{
    const std::string path = TempPath("stale");
    auto shm = MakeShm(path);
    CHECK(shm != nullptr);
    auto dp = MakeDataPlane(shm);

    // ──── 第一条 program ────────────────────────────────────
    const uint8_t payload_a[2] = {0xAA, 0xBB};
    data::IDataPlane::SubmitInput req_a;
    req_a.worker_id = 0;
    req_a.executor_id = 100;
    req_a.dispatch_gen = 7;
    req_a.payload_data = payload_a;
    req_a.payload_size = sizeof(payload_a);
    req_a.exec_flags = 0;
    CHECK(dp.Submit(req_a) == data::SubmitOutcome::kSent);

    auto wv = shm->worker(0);
    CHECK(wv.valid());

    // worker 写入第一条 program 的 output(4 字节模式)+ result page commit。
    const uint8_t out_a[4] = {0x11, 0x22, 0x33, 0x44};
    std::memcpy(wv.output_pool(), out_a, sizeof(out_a));
    auto* page = wv.result_page();
    page->executor_id = req_a.executor_id;
    page->dispatch_gen = req_a.dispatch_gen;
    page->output_len = sizeof(out_a);
    page->result_kind = 1;
    program_result_store_commit_seq_v3(page, 1);
    program_result_store_state_v3(page, PROGRAM_RESULT_COMMITTED);

    // loop child publish CompletionSlot for task A
    auto* task = wv.task_slot();
    StoreTaskState(task, TASK_TAKEN);
    auto* completion = wv.completion_slot();
    completion->executor_id = req_a.executor_id;
    completion->dispatch_gen = req_a.dispatch_gen;
    completion->status = COMP_STATUS_OK;
    completion->error_code = 0;
    completion->crash_signal = 0;
    completion->output_off = 0;
    completion->output_len = sizeof(out_a);
    completion->exec_seq = 1;
    StoreCompletionState(completion, COMP_READY);

    std::vector<data::DispatchOutcome> out;
    dp.Poll(out, std::chrono::microseconds{0});
    CHECK(out.size() == 1);
    CHECK(out[0].executor_id == req_a.executor_id);
    CHECK(out[0].output.size() == sizeof(out_a));
    CHECK(std::memcmp(out[0].output.data(), out_a, sizeof(out_a)) == 0);

    // ──── 第二条 program：result page commit 了，但 CompletionSlot 没 publish
    //                       (模拟 program child commit 完后 loop child 被 kill 来不及发) ────
    data::IDataPlane::SubmitInput req_b = req_a;
    req_b.executor_id = 101;
    req_b.dispatch_gen = 8;
    const uint8_t payload_b[2] = {0xCC, 0xDD};
    req_b.payload_data = payload_b;
    req_b.payload_size = sizeof(payload_b);
    CHECK(dp.Submit(req_b) == data::SubmitOutcome::kSent);

    // worker 写残留 output + result page commit
    wv = shm->worker(0);
    const uint8_t out_b[5] = {0xDE, 0xAD, 0xBE, 0xEF, 0x99};
    std::memcpy(wv.output_pool(), out_b, sizeof(out_b));
    page = wv.result_page();
    page->executor_id = req_b.executor_id;
    page->dispatch_gen = req_b.dispatch_gen;
    page->output_len = sizeof(out_b);
    page->result_kind = 1;
    program_result_store_commit_seq_v3(page, 1);
    program_result_store_state_v3(page, PROGRAM_RESULT_COMMITTED);
    // 关键：CompletionSlot 不 publish —— 第二条被 abort。

    out.clear();
    dp.Poll(out, std::chrono::microseconds{0});
    CHECK(out.empty());  // result page 已 commit 但 host 不读 page，没有泄漏

    // ──── 第三条 program：完全新一轮。host 同 worker 再 submit ────
    // 模拟 worker 内部 Reset / Respawn，TASK_EMPTY + COMP_EMPTY；同时 worker
    // 应在 fork program 前把 result page 重新 Init（这里手工模拟）。
    StoreTaskState(task, TASK_EMPTY);
    StoreCompletionState(completion, COMP_EMPTY);

    data::IDataPlane::SubmitInput req_c = req_a;
    req_c.executor_id = 102;
    req_c.dispatch_gen = 9;
    const uint8_t payload_c[2] = {0xEE, 0xFF};
    req_c.payload_data = payload_c;
    req_c.payload_size = sizeof(payload_c);
    CHECK(dp.Submit(req_c) == data::SubmitOutcome::kSent);

    // 模拟 loop child InitProgramResultPage —— 写本轮 ids，clear progress。
    wv = shm->worker(0);
    page = wv.result_page();
    page->executor_id = req_c.executor_id;
    page->dispatch_gen = req_c.dispatch_gen;
    page->output_len = 0;
    page->result_kind = 0;
    __atomic_store_n(&page->progress_completed_calls, 0u, __ATOMIC_RELEASE);
    __atomic_store_n(&page->progress_output_len, 0u, __ATOMIC_RELEASE);
    program_result_store_commit_seq_v3(page, 0);
    program_result_store_state_v3(page, PROGRAM_RESULT_RUNNING);

    // 验证：旧 exec_seq=1 不会被 sweep 出来。
    completion->executor_id = req_c.executor_id;
    completion->dispatch_gen = req_c.dispatch_gen;
    completion->status = COMP_STATUS_OK;
    completion->error_code = 0;
    completion->crash_signal = 0;
    completion->output_off = 0;
    completion->output_len = 3;
    completion->exec_seq = 1;  // <= last_completion_exec_seq_，应被拒
    StoreCompletionState(completion, COMP_READY);
    out.clear();
    dp.Poll(out, std::chrono::microseconds{0});
    CHECK(out.empty());

    // 写本轮 output（覆盖前两条的残留）+ exec_seq 单调推进。
    const uint8_t out_c[3] = {0x01, 0x02, 0x03};
    std::memcpy(wv.output_pool(), out_c, sizeof(out_c));
    StoreTaskState(task, TASK_TAKEN);
    completion->output_len = sizeof(out_c);
    completion->exec_seq = 2;
    StoreCompletionState(completion, COMP_READY);

    out.clear();
    dp.Poll(out, std::chrono::microseconds{0});
    CHECK(out.size() == 1);
    CHECK(out[0].executor_id == req_c.executor_id);
    CHECK(out[0].dispatch_gen == req_c.dispatch_gen);
    CHECK(out[0].output.size() == sizeof(out_c));
    // 关键：拿到的是 out_c，不是 out_b 也不是 out_a 的残留。
    CHECK(std::memcmp(out[0].output.data(), out_c, sizeof(out_c)) == 0);

    ::unlink(path.c_str());
    return 0;
}

int test_orphan_completion_does_not_advance_exec_seq_watermark()
{
    const std::string path = TempPath("orphan_seq");
    auto shm = MakeShm(path);
    CHECK(shm != nullptr);
    auto dp = MakeDataPlane(shm);
    auto wv = shm->worker(0);
    CHECK(wv.valid());
    auto* completion = wv.completion_slot();

    // 没有在途任务（从未 Submit）时，旧 loop 的孤儿 completion 到达。
    completion->executor_id = 999;
    completion->dispatch_gen = 99;
    completion->status = COMP_STATUS_OK;
    completion->error_code = 0;
    completion->crash_signal = 0;
    completion->output_off = 0;
    completion->output_len = 3;
    completion->exec_seq = 7;
    StoreCompletionState(completion, COMP_READY);

    std::vector<data::DispatchOutcome> out;
    dp.Poll(out, std::chrono::microseconds{0});
    // 数据面是无状态传输层：孤儿照常交付（channel 按 executor_id 丢弃），
    // 但不得推进 exec_seq 水位线。
    CHECK(out.size() == 1);
    CHECK(out[0].executor_id == 999);
    CHECK(out[0].dispatch_gen == 99);
    CHECK(__atomic_load_n(&completion->state, __ATOMIC_ACQUIRE) ==
          static_cast<uint32_t>(COMP_EMPTY));

    // 新 daemon 实例从 exec_seq=1 重新开始；若上一步的孤儿推进了水位线
    // （7），这条 seq=1 的合法完成会被 non-monotonic 误杀。
    const uint8_t payload = 0x01;
    data::IDataPlane::SubmitInput req;
    req.worker_id = 0;
    req.executor_id = 1234;
    req.dispatch_gen = 5;
    req.payload_data = &payload;
    req.payload_size = sizeof(payload);
    CHECK(dp.Submit(req) == data::SubmitOutcome::kSent);

    auto* task = wv.task_slot();
    StoreTaskState(task, TASK_TAKEN);
    completion->executor_id = req.executor_id;
    completion->dispatch_gen = req.dispatch_gen;
    completion->status = COMP_STATUS_OK;
    completion->error_code = 0;
    completion->crash_signal = 0;
    completion->output_off = 0;
    completion->output_len = 0;
    completion->exec_seq = 1;
    StoreCompletionState(completion, COMP_READY);

    out.clear();
    dp.Poll(out, std::chrono::microseconds{0});
    CHECK(out.size() == 1);
    CHECK(out[0].executor_id == req.executor_id);
    CHECK(out[0].dispatch_gen == req.dispatch_gen);

    ::unlink(path.c_str());
    return 0;
}

} // namespace

int main()
{
    std::fprintf(stderr, "Running ivshmem_v3_layout_commit_test...\n");
    RUN_TEST(test_v3_header_explicit_layout);
    RUN_TEST(test_control_reset_preserves_proc_state);
    RUN_TEST(test_reset_does_not_clobber_concurrent_dirty_publish);
    RUN_TEST(test_control_starts_domains_one_worker_at_a_time);
    RUN_TEST(test_wait_worker_ready_completes_session_after_last_worker);
    RUN_TEST(test_heartbeat_sample_requires_registration);
    RUN_TEST(test_heartbeat_counter_is_progress_token);
    RUN_TEST(test_submit_requires_domain_ready);
    RUN_TEST(test_host_completion_slot_is_commit_edge);
    RUN_TEST(test_start_ack_refreshes_for_same_executor_redispatch);
    RUN_TEST(test_v3_stale_result_isolation);
    RUN_TEST(test_orphan_completion_does_not_advance_exec_seq_watermark);
    std::fprintf(stderr, "OK\n");
    return 0;
}

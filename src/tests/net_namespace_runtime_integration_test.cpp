// Runtime integration coverage for the netfilter checkpoint/reset call sites.
// Host-mutating setup calls are link-wrapped, while the production continuous
// and snapshot engine functions execute unchanged.

#include "worker/adapter/worker_task_channel.hpp"
#include "worker/backend/exec_backend.hpp"
#include "worker/engine/execution_domain_registry.hpp"
#include "worker/engine/loop_runtime.hpp"
#include "worker/engine/loop_worker_boot_config.hpp"
#include "worker/engine/program_runtime.hpp"
#include "worker/engine/snapshot_engine.hpp"
#include "worker/observation/observation_bus.hpp"
#include "worker/sandbox.hpp"

#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <optional>
#include <poll.h>
#include <string>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

volatile sig_atomic_t g_running = 1;

namespace worker = ::refuzz::worker;
namespace engine = ::refuzz::worker::engine;

namespace {

#define CHECK(expr)                                                       \
    do {                                                                  \
        if (!(expr)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,  \
                         #expr);                                          \
            std::abort();                                                 \
        }                                                                 \
    } while (0)

#define RUN_TEST(fn)                                                      \
    do {                                                                  \
        std::fprintf(stderr, "RUN  %s\n", #fn);                           \
        fn();                                                             \
        std::fprintf(stderr, "OK   %s\n", #fn);                           \
    } while (0)

struct HarnessState {
    std::uint32_t sequence;
    std::uint32_t apply_count;
    std::uint32_t cgroup_count;
    std::uint32_t checkpoint_count;
    std::uint32_t reset_count;
    std::uint32_t execute_count;
    std::uint32_t ready_count;
    std::uint32_t apply_order;
    std::uint32_t cgroup_order;
    std::uint32_t checkpoint_order;
    std::uint32_t reset_first_order;
    std::uint32_t reset_second_order;
    std::uint32_t execute_order;
    std::uint32_t ready_order;
    int apply_result;
    int checkpoint_result;
    int checkpoint_errno;
    int reset_result;
    int reset_errno;
};

HarnessState* g_state = nullptr;

std::uint32_t Load(const std::uint32_t* value)
{
    return __atomic_load_n(value, __ATOMIC_ACQUIRE);
}

std::uint32_t NextOrder()
{
    return __atomic_add_fetch(&g_state->sequence, 1u, __ATOMIC_ACQ_REL);
}

void Record(std::uint32_t* count, std::uint32_t* first_order)
{
    const std::uint32_t order = NextOrder();
    const std::uint32_t call =
        __atomic_add_fetch(count, 1u, __ATOMIC_ACQ_REL);
    if (call == 1 && first_order != nullptr) {
        __atomic_store_n(first_order, order, __ATOMIC_RELEASE);
    }
}

void ResetHarnessState()
{
    std::memset(g_state, 0, sizeof(*g_state));
    g_state->checkpoint_result = 1;
    g_state->checkpoint_errno = EIO;
    g_state->reset_result = 1;
    g_state->reset_errno = EIO;
}

bool WaitForCount(const std::uint32_t* value, std::uint32_t target)
{
    for (int i = 0; i < 3000; ++i) {
        if (Load(value) >= target) {
            return true;
        }
        ::usleep(1000);
    }
    return false;
}

bool ReadExact(int fd, void* output, std::size_t size)
{
    auto* bytes = static_cast<unsigned char*>(output);
    std::size_t offset = 0;
    while (offset < size) {
        struct ::pollfd pfd {fd, POLLIN | POLLHUP, 0};
        int ready;
        do {
            ready = ::poll(&pfd, 1, 3000);
        } while (ready < 0 && errno == EINTR);
        if (ready <= 0) {
            return false;
        }
        ssize_t n;
        do {
            n = ::read(fd, bytes + offset, size - offset);
        } while (n < 0 && errno == EINTR);
        if (n <= 0) {
            return false;
        }
        offset += static_cast<std::size_t>(n);
    }
    return true;
}

bool WriteExact(int fd, const void* input, std::size_t size)
{
    const auto* bytes = static_cast<const unsigned char*>(input);
    std::size_t offset = 0;
    while (offset < size) {
        ssize_t n;
        do {
            n = ::write(fd, bytes + offset, size - offset);
        } while (n < 0 && errno == EINTR);
        if (n <= 0) {
            return false;
        }
        offset += static_cast<std::size_t>(n);
    }
    return true;
}

int WaitForChild(pid_t pid)
{
    int status = 0;
    for (int i = 0; i < 3000; ++i) {
        const pid_t waited = ::waitpid(pid, &status, WNOHANG);
        if (waited == pid) {
            return status;
        }
        CHECK(waited == 0 || (waited < 0 && errno == EINTR));
        ::usleep(1000);
    }
    (void)::kill(pid, SIGKILL);
    CHECK(::waitpid(pid, &status, 0) == pid);
    std::fprintf(stderr, "FAIL: child %d did not exit before timeout\n", pid);
    std::abort();
}

class FakeBackend final : public worker::IExecBackend {
public:
    int Execute(const std::uint8_t*, std::uint32_t, std::uint8_t*,
                std::uint32_t, std::uint32_t*, worker::ExecMode) override
    {
        std::abort();
    }

    const char* Name() const override { return "net-runtime-test"; }
};

class FakeBus final : public worker::IObservationBus {
public:
    void AddSink(std::unique_ptr<worker::IObservationSink>) override {}
    bool InitAll() override { return true; }
    void Publish(worker::ObservationEvent,
                 const worker::ObservationContext&) override {}
    void PackAllFeedback(std::uint8_t*, std::uint32_t,
                         std::uint32_t*) override {}
    std::uint32_t SnapshotAllForCrash(std::uint8_t*,
                                      std::uint32_t) const override
    {
        return 0;
    }
    std::size_t TotalBufferBytes() const override { return 0; }
    bool RemapInternalFds(int*, std::vector<int>*) override { return true; }
    std::size_t SinkCount() const override { return 0; }
    worker::IExtraKcovControl* FindExtraKcovControl() override
    {
        return nullptr;
    }
    worker::RuntimeFailure RuntimeFailureState() const override
    {
        return worker::RuntimeFailure::kNone;
    }
};

class FakeProgramExecutor final : public engine::IProgramExecutor {
public:
    void ExecuteProgram(const engine::ProgramRuntimeInput&,
                        engine::DoneMsg* done) override
    {
        Record(&g_state->execute_count, &g_state->execute_order);
        *done = {};
        done->status = 0;
        done->result_kind = engine::RuntimeResultKind::kNormal;
    }
};

class SnapshotChannel final : public worker::IWorkerTaskChannel {
public:
    std::optional<worker::WorkerIO> WaitTask(
        std::chrono::milliseconds) override
    {
        ++wait_count;
        g_running = 0;
        return std::nullopt;
    }

    void ReportDone(const worker::TaskResult&) override { std::abort(); }
    bool CancelRequested() const override { return false; }
    void SetDomainReady(bool ready) override
    {
        CHECK(ready);
        Record(&g_state->ready_count, &g_state->ready_order);
    }
    void ResetOutputLen() override {}
    std::uint32_t GetCrashOutputLen() const override { return 0; }

    std::uint32_t wait_count = 0;
};

class SnapshotRegistry final : public worker::IExecutionDomainRegistry {
public:
    std::uint32_t WorkerCount() const override { return 1; }
    bool PublishProcState(std::uint32_t proc_id,
                          std::uint32_t epoch) override
    {
        published_proc_id = proc_id;
        published_epoch = epoch;
        return true;
    }

    std::uint32_t published_proc_id = PROC_ID_ANY;
    std::uint32_t published_epoch = 0;
};

struct LoopChild {
    pid_t pid = -1;
    int request_write = -1;
    int done_read = -1;
    int startup_read = -1;
    std::string workdir;
};

LoopChild StartLoopChild(worker::SandboxMode sandbox_mode)
{
    int request_pipe[2];
    int done_pipe[2];
    int startup_pipe[2];
    CHECK(::pipe(request_pipe) == 0);
    CHECK(::pipe(done_pipe) == 0);
    CHECK(::pipe(startup_pipe) == 0);

    char workdir_template[] = "/tmp/refuzz-net-runtime-XXXXXX";
    char* workdir = ::mkdtemp(workdir_template);
    CHECK(workdir != nullptr);

    const pid_t pid = ::fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        (void)::close(request_pipe[1]);
        (void)::close(done_pipe[0]);
        (void)::close(startup_pipe[0]);
        CHECK(::chdir(workdir) == 0);

        FakeBackend backend;
        FakeBus bus;
        FakeProgramExecutor executor;
        std::array<std::uint8_t, 8192> storage{};
        worker::ProgramBufferMapping mapping{};
        mapping.source = worker::ProgramBufferSource::kLinearSharedMemory;
        mapping.worker_id = 0;
        mapping.local_base = storage.data();
        mapping.resource_offset = 0;
        mapping.mapped_size = storage.size();
        mapping.input_offset = 0;
        mapping.input_size = 4096;
        mapping.output_offset = 4096;
        mapping.output_size = 4096;

        engine::LoopRuntimeRun(
            request_pipe[0], done_pipe[1], 0, 0, backend, bus,
            sandbox_mode, true, 0, nullptr, 0, mapping,
            startup_pipe[1], executor);
    }

    (void)::close(request_pipe[0]);
    (void)::close(done_pipe[1]);
    (void)::close(startup_pipe[1]);
    return LoopChild{pid, request_pipe[1], done_pipe[0], startup_pipe[0],
                     workdir};
}

engine::LoopStartupStatus ReadStartup(LoopChild* child)
{
    engine::LoopStartupStatus status{};
    CHECK(ReadExact(child->startup_read, &status, sizeof(status)));
    (void)::close(child->startup_read);
    child->startup_read = -1;
    return status;
}

engine::ReadyMsg MakeRequest()
{
    engine::ReadyMsg message{};
    message.input_len = 4;
    message.output_cap = 16;
    message.dispatch_gen = 7;
    message.executor_id = 42;
    message.buffers.source =
        worker::ProgramBufferSource::kLinearSharedMemory;
    message.buffers.worker_id = 0;
    message.buffers.input_offset = 0;
    message.buffers.output_offset = 4096;
    return message;
}

void FinishLoopChild(LoopChild* child, int expected_exit_code)
{
    if (child->request_write >= 0) {
        (void)::close(child->request_write);
        child->request_write = -1;
    }
    if (child->startup_read >= 0) {
        (void)::close(child->startup_read);
        child->startup_read = -1;
    }
    if (child->done_read >= 0) {
        (void)::close(child->done_read);
        child->done_read = -1;
    }
    const int status = WaitForChild(child->pid);
    CHECK(WIFEXITED(status));
    CHECK(WEXITSTATUS(status) == expected_exit_code);
    const std::string iteration_workdir = child->workdir + "/0";
    if (::rmdir(iteration_workdir.c_str()) != 0) {
        CHECK(errno == ENOENT);
    }
    CHECK(::rmdir(child->workdir.c_str()) == 0);
}

void TestContinuousCheckpointAndPerIterationReset()
{
    ResetHarnessState();
    LoopChild child = StartLoopChild(worker::SandboxMode::kNone);
    const engine::LoopStartupStatus startup = ReadStartup(&child);
    CHECK(startup.ready == 1);
    CHECK(startup.stage == engine::LoopStartupStage::kReady);
    CHECK(Load(&g_state->checkpoint_count) == 1);
    CHECK(WaitForCount(&g_state->reset_count, 1));
    CHECK(Load(&g_state->apply_order) < Load(&g_state->cgroup_order));
    CHECK(Load(&g_state->cgroup_order) < Load(&g_state->checkpoint_order));
    CHECK(Load(&g_state->checkpoint_order) <
          Load(&g_state->reset_first_order));

    const engine::ReadyMsg request = MakeRequest();
    CHECK(WriteExact(child.request_write, &request, sizeof(request)));
    engine::DoneMsg done{};
    CHECK(ReadExact(child.done_read, &done, sizeof(done)));
    CHECK(done.status == 0);
    CHECK(done.result_kind == engine::RuntimeResultKind::kNormal);
    CHECK(WaitForCount(&g_state->reset_count, 2));
    CHECK(Load(&g_state->reset_first_order) < Load(&g_state->execute_order));
    CHECK(Load(&g_state->execute_order) < Load(&g_state->reset_second_order));

    FinishLoopChild(&child, 0);
    CHECK(Load(&g_state->checkpoint_count) == 1);
    CHECK(Load(&g_state->reset_count) == 2);
    CHECK(Load(&g_state->execute_count) == 1);
}

void TestContinuousSetuidSkipsCheckpointAndReset()
{
    ResetHarnessState();
    LoopChild child = StartLoopChild(worker::SandboxMode::kSetuid);
    const engine::LoopStartupStatus startup = ReadStartup(&child);
    CHECK(startup.ready == 1);
    CHECK(Load(&g_state->checkpoint_count) == 0);
    CHECK(Load(&g_state->reset_count) == 0);

    const engine::ReadyMsg request = MakeRequest();
    CHECK(WriteExact(child.request_write, &request, sizeof(request)));
    engine::DoneMsg done{};
    CHECK(ReadExact(child.done_read, &done, sizeof(done)));
    CHECK(done.result_kind == engine::RuntimeResultKind::kNormal);
    FinishLoopChild(&child, 0);
    CHECK(Load(&g_state->checkpoint_count) == 0);
    CHECK(Load(&g_state->reset_count) == 0);
    CHECK(Load(&g_state->execute_count) == 1);
}

void TestContinuousCheckpointFailureStopsBeforeReady()
{
    ResetHarnessState();
    g_state->checkpoint_result = 0;
    g_state->checkpoint_errno = EBUSY;
    LoopChild child = StartLoopChild(worker::SandboxMode::kNone);
    const engine::LoopStartupStatus startup = ReadStartup(&child);
    CHECK(startup.ready == 0);
    CHECK(startup.stage == engine::LoopStartupStage::kSandbox);
    CHECK(startup.error_number == EBUSY);
    FinishLoopChild(&child, 2);
    CHECK(Load(&g_state->checkpoint_count) == 1);
    CHECK(Load(&g_state->reset_count) == 0);
    CHECK(Load(&g_state->execute_count) == 0);
}

void TestContinuousResetFailureStopsDomain()
{
    ResetHarnessState();
    g_state->reset_result = 0;
    g_state->reset_errno = EBUSY;
    LoopChild child = StartLoopChild(worker::SandboxMode::kNone);
    const engine::LoopStartupStatus startup = ReadStartup(&child);
    CHECK(startup.ready == 1);
    FinishLoopChild(&child, 10);
    CHECK(Load(&g_state->checkpoint_count) == 1);
    CHECK(Load(&g_state->reset_count) == 1);
    CHECK(Load(&g_state->execute_count) == 0);
}

int RunSnapshot(worker::SandboxMode sandbox_mode,
                SnapshotChannel* channel)
{
    SnapshotRegistry registry;
    FakeBackend backend;
    FakeBus bus;
    worker::EngineConfig config{};
    config.worker_id = 0;
    config.sandbox_mode = sandbox_mode;
    g_running = 1;
    const int result = worker::RunSnapshotEngine(
        *channel, registry, backend, bus, config);
    CHECK(registry.published_proc_id == 0);
    return result;
}

void TestSnapshotCheckpointPrecedesReady()
{
    ResetHarnessState();
    SnapshotChannel channel;
    CHECK(RunSnapshot(worker::SandboxMode::kNone, &channel) == 0);
    CHECK(channel.wait_count == 1);
    CHECK(Load(&g_state->checkpoint_count) == 1);
    CHECK(Load(&g_state->reset_count) == 0);
    CHECK(Load(&g_state->checkpoint_order) < Load(&g_state->ready_order));
}

void TestSnapshotSetuidSkipsCheckpoint()
{
    ResetHarnessState();
    SnapshotChannel channel;
    CHECK(RunSnapshot(worker::SandboxMode::kSetuid, &channel) == 0);
    CHECK(channel.wait_count == 1);
    CHECK(Load(&g_state->checkpoint_count) == 0);
    CHECK(Load(&g_state->reset_count) == 0);
    CHECK(Load(&g_state->ready_count) == 1);
}

void TestSnapshotCheckpointFailureDoesNotPublishReady()
{
    ResetHarnessState();
    g_state->checkpoint_result = 0;
    g_state->checkpoint_errno = EBUSY;
    SnapshotChannel channel;
    CHECK(RunSnapshot(worker::SandboxMode::kNone, &channel) == 4);
    CHECK(channel.wait_count == 0);
    CHECK(Load(&g_state->checkpoint_count) == 1);
    CHECK(Load(&g_state->reset_count) == 0);
    CHECK(Load(&g_state->ready_count) == 0);
}

} // namespace

extern "C" int
__wrap__ZN6refuzz6worker12ApplySandboxENS0_11SandboxModeERKNS0_13SandboxSizingE(
    worker::SandboxMode, const worker::SandboxSizing&)
{
    Record(&g_state->apply_count, &g_state->apply_order);
    return g_state->apply_result;
}

extern "C" bool
__wrap__ZN6refuzz6worker25PreallocateSyzExecScratchEv()
{
    return true;
}

extern "C" void
__wrap__ZN6refuzz6worker6engine34ProgramRuntimeInstallCrashHandlersEPNS0_15IObservationBusE(
    worker::IObservationBus*)
{}

extern "C" void
__wrap__ZN6refuzz6worker7sandbox11device_init16SetupCgroupsLoopEm(
    std::uint64_t)
{
    Record(&g_state->cgroup_count, &g_state->cgroup_order);
}

extern "C" bool
__wrap__ZN6refuzz6worker7sandbox11device_init22CheckpointNetNamespaceEv()
{
    Record(&g_state->checkpoint_count, &g_state->checkpoint_order);
    errno = g_state->checkpoint_errno;
    return g_state->checkpoint_result != 0;
}

extern "C" bool
__wrap__ZN6refuzz6worker7sandbox11device_init17ResetNetNamespaceEv()
{
    const std::uint32_t order = NextOrder();
    const std::uint32_t call =
        __atomic_add_fetch(&g_state->reset_count, 1u, __ATOMIC_ACQ_REL);
    if (call == 1) {
        __atomic_store_n(&g_state->reset_first_order, order, __ATOMIC_RELEASE);
    } else if (call == 2) {
        __atomic_store_n(&g_state->reset_second_order, order, __ATOMIC_RELEASE);
    }
    errno = g_state->reset_errno;
    return g_state->reset_result != 0;
}

extern "C" int __llvm_profile_write_file() __attribute__((weak));
extern "C" [[noreturn]] void __real__exit(int status);

extern "C" [[noreturn]] void __wrap__exit(int status)
{
    if (__llvm_profile_write_file != nullptr) {
        (void)__llvm_profile_write_file();
    }
    __real__exit(status);
}

int main()
{
    void* mapping = ::mmap(nullptr, sizeof(HarnessState),
                           PROT_READ | PROT_WRITE,
                           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(mapping != MAP_FAILED);
    g_state = static_cast<HarnessState*>(mapping);

    RUN_TEST(TestContinuousCheckpointAndPerIterationReset);
    RUN_TEST(TestContinuousSetuidSkipsCheckpointAndReset);
    RUN_TEST(TestContinuousCheckpointFailureStopsBeforeReady);
    RUN_TEST(TestContinuousResetFailureStopsDomain);
    RUN_TEST(TestSnapshotCheckpointPrecedesReady);
    RUN_TEST(TestSnapshotSetuidSkipsCheckpoint);
    RUN_TEST(TestSnapshotCheckpointFailureDoesNotPublishReady);

    CHECK(::munmap(g_state, sizeof(*g_state)) == 0);
    return 0;
}

#include "refuzz/channel/runtime/runtime_instance.hpp"
#include "refuzz/channel/substrate/substrate.hpp"

#include <cassert>
#include <chrono>
#include <string>
#include <utility>
#include <vector>

namespace ch = refuzz::channel;
namespace runtime = refuzz::channel::runtime;
namespace worker = refuzz::channel::worker;

namespace {

struct OpsRecorder {
    std::vector<std::string> events;
    bool fail_chmod = false;
};

runtime::SubstrateInstanceOps MakeMockOps(OpsRecorder* recorder)
{
    runtime::SubstrateInstanceOps ops;
    ops.start = []() { return ch::Result<void>::Ok(); };
    ops.stop = []() {};
    ops.is_alive = []() { return true; };
    ops.run_command = [recorder](const std::string& command,
                                 std::chrono::milliseconds) {
        recorder->events.push_back("command:" + command);
        if (recorder->fail_chmod) {
            return ch::Result<std::string>(
                ch::Error{ch::ErrorKind::kCommand, "chmod denied"});
        }
        return ch::Result<std::string>::Ok(std::string{});
    };
    ops.copy_file_to = [recorder](const std::string& local_path,
                                  const std::string& remote_path,
                                  std::chrono::milliseconds) {
        recorder->events.push_back("copy:" + local_path + "->" + remote_path);
        return ch::Result<void>::Ok();
    };
    ops.serial_endpoint = []() { return std::string{}; };
    ops.monitor_endpoint = []() { return std::string{}; };
    ops.diagnose = []() { return std::string{}; };
    return ops;
}

worker::WorkerConfig MakeWorkerConfig()
{
    worker::WorkerConfig config;
    config.n_workers = 1;
    return config;
}

void TestDeployAppliesEachArtifactMode()
{
    OpsRecorder recorder;
    runtime::RuntimeInstance instance(MakeMockOps(&recorder), MakeWorkerConfig());
    runtime::DeployBundle bundle;
    bundle.artifacts = {
        runtime::DeployArtifact{"host/refuzz_executor", "/tmp/refuzz_executor", 0755},
        runtime::DeployArtifact{"host/config", "/tmp/refuzz config", 0640},
    };

    const auto result = instance.DeployArtifacts(bundle);
    assert(result.ok());
    const std::vector<std::string> expected = {
        "copy:host/refuzz_executor->/tmp/refuzz_executor",
        "command:chmod 0755 -- '/tmp/refuzz_executor'",
        "copy:host/config->/tmp/refuzz config",
        "command:chmod 0640 -- '/tmp/refuzz config'",
    };
    assert(recorder.events == expected);
}

void TestDeployPropagatesChmodFailure()
{
    OpsRecorder recorder;
    recorder.fail_chmod = true;
    runtime::RuntimeInstance instance(MakeMockOps(&recorder), MakeWorkerConfig());
    runtime::DeployBundle bundle;
    bundle.artifacts.push_back(
        runtime::DeployArtifact{"host/refuzz_executor", "/tmp/refuzz_executor", 0755});

    const auto result = instance.DeployArtifacts(bundle);
    assert(!result.ok());
    assert(result.error().kind == ch::ErrorKind::kCommand);
    assert(result.error().message.find("chmod failed") != std::string::npos);
    assert(recorder.events.size() == 2);
}

} // namespace

int main()
{
    TestDeployAppliesEachArtifactMode();
    TestDeployPropagatesChmodFailure();
    return 0;
}

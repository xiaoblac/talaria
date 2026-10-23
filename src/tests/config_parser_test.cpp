// Copyright 2026 reFuzz project author -------youngkk.
//
// Config parser contract tests:
//   - ChannelConfig defaults stay aligned with parser defaults.
//   - Explicit channel.*_ms and executor.event_forward_strategy fields take effect.
//   - Legacy timeout fields remain compatible.
//   - Unsupported keys fail fast instead of being silently ignored.

#include "refuzz/config_parser/parse_config_from_json.hpp"

#include "refuzz/channel/factory/qemu_ivshmem_linux_profile.hpp"
#include "refuzz/channel/factory/xiuos_uart_profile.hpp"
#include "util/json.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <system_error>

namespace {

namespace fs = std::filesystem;

int tests_run = 0;
int tests_passed = 0;

#define CHECK(cond) do {                                                        \
    if (!(cond)) {                                                              \
        std::fprintf(stderr,                                                    \
                     "    CHECK failed: %s [line %d]\n",                        \
                     #cond, __LINE__);                                          \
        return false;                                                           \
    }                                                                           \
} while (0)

#define CHECK_EQ(actual, expected) do {                                         \
    const auto actual_value = (actual);                                         \
    const auto expected_value = (expected);                                     \
    if (!(actual_value == expected_value)) {                                    \
        std::fprintf(stderr,                                                    \
                     "    CHECK_EQ failed: %s == %s [line %d]\n",               \
                     #actual, #expected, __LINE__);                             \
        return false;                                                           \
    }                                                                           \
} while (0)

#define RUN_TEST(fn, failed) do {                                               \
    ++tests_run;                                                                \
    std::fprintf(stdout, "  %-60s ", #fn);                                      \
    std::fflush(stdout);                                                        \
    if (fn()) {                                                                 \
        ++tests_passed;                                                         \
        std::fprintf(stdout, "PASS\n");                                         \
    } else {                                                                    \
        std::fprintf(stdout, "FAIL\n");                                         \
        ++(failed);                                                             \
    }                                                                           \
} while (0)

class TmpWorkDir {
public:
    TmpWorkDir()
    {
        char tmpl[] = "/tmp/refuzz_config_parser_XXXXXX";
        char* dir = mkdtemp(tmpl);
        if (dir != nullptr) {
            path_ = dir;
        }
    }

    ~TmpWorkDir()
    {
        if (!path_.empty()) {
            std::error_code ec;
            fs::remove_all(path_, ec);
        }
    }

    TmpWorkDir(const TmpWorkDir&) = delete;
    TmpWorkDir& operator=(const TmpWorkDir&) = delete;

    bool ok() const { return !path_.empty(); }
    const std::string& path() const { return path_; }

private:
    std::string path_;
};

nlohmann::json MinimalConfig(const std::string& work_dir)
{
    return nlohmann::json{
        {"work_dir", work_dir},
        {"retention", false},
        {"channel",
         {{"vm",
           {{"arch", "amd64"},
            {"image", "/nonexistent/image.img"},
            {"kernel", "/nonexistent/bzImage"},
            {"ssh_key", "/nonexistent/id_rsa"},
            {"ssh_user", "root"},
            {"qemu", nlohmann::json::object()}}},
          {"transport",
           {{"n_workers", 2},
            {"ivshmem_path", "/tmp/refuzz_config_parser_shm"},
            {"ivshmem_mode", "plain"}}}}},
        {"target",
         {{"execution_mode", "kernel_syscall"},
          {"coverage_mode", "kcov"},
          {"sanitizer_mode", "none"},
          {"sandbox_mode", "none"}}},
    };
}

bool TestDefaultsUseChannelConfigValues()
{
    TmpWorkDir tmp;
    CHECK(tmp.ok());

    refuzz::orchestrator::OrchestratorConfig cfg;
    CHECK(refuzz::orchestrator::ParseConfigFromJson(MinimalConfig(tmp.path()), cfg));

    CHECK_EQ(cfg.channel_common.wait_ready_timeout.count(), 60000);
    CHECK_EQ(cfg.channel_common.loop_interval.count(), 100);
    CHECK_EQ(cfg.channel_common.health_check_interval.count(), 500);
    CHECK_EQ(cfg.channel_common.pre_reboot_drain.count(), 5500);
    CHECK_EQ(cfg.channel_common.input_queue_capacity, static_cast<std::size_t>(6));
    CHECK_EQ(cfg.fuzz_channel_count, 1U);
    CHECK_EQ(cfg.executor.idle_sleep_us, 1000000ULL);
    CHECK_EQ(cfg.executor.event_blocking_timeout_us, 1000ULL);
    CHECK_EQ(cfg.executor.submit_strategy, std::string{"round_robin"});
    CHECK_EQ(cfg.target.thread_count, 1U);
    CHECK_EQ(cfg.coverage_kcov_entries, 512U << 10);
    CHECK(cfg.target.intra_task_mode ==
          refuzz::orchestrator::TargetRuntimeConfig::IntraTaskMode::kSerial);
    CHECK_EQ(cfg.executor.default_intra_threaded, false);
    return true;
}

bool TestExplicitChannelAndExecutorValues()
{
    TmpWorkDir tmp;
    CHECK(tmp.ok());

    auto root = MinimalConfig(tmp.path());
    root["channel"]["wait_ready_timeout_ms"] = 1234;
    root["channel"]["loop_interval_ms"] = 12;
    root["channel"]["health_check_interval_ms"] = 34;
    root["channel"]["pre_reboot_drain_ms"] = 56;
    root["channel"]["input_queue_capacity"] = 78;
    root["executor"] = {
        {"idle_sleep_us", 2222},
        {"submit_wait_for_slot_ms", 0},
        {"submit_strategy", {{"name", "round_robin"}}},
        {"event_forward_strategy", {{"blocking_timeout_ms", 7}}},
        {"timeouts_ms", {{"pop", 9}, {"poll", 3}}},
    };

    refuzz::orchestrator::OrchestratorConfig cfg;
    CHECK(refuzz::orchestrator::ParseConfigFromJson(root, cfg));

    CHECK_EQ(cfg.channel_common.wait_ready_timeout.count(), 1234);
    CHECK_EQ(cfg.channel_common.loop_interval.count(), 12);
    CHECK_EQ(cfg.channel_common.health_check_interval.count(), 34);
    CHECK_EQ(cfg.channel_common.pre_reboot_drain.count(), 56);
    CHECK_EQ(cfg.channel_common.input_queue_capacity, static_cast<std::size_t>(78));
    CHECK_EQ(cfg.executor.idle_sleep_us, 2222ULL);
    CHECK_EQ(cfg.executor.event_blocking_timeout_us, 7000ULL);
    CHECK_EQ(cfg.pop_timeout.count(), 9);
    CHECK_EQ(cfg.poll_timeout.count(), 3000);

    const std::string dump = refuzz::orchestrator::DumpConfigSummary(cfg);
    CHECK(dump.find("\"wait_ready_timeout_ms\": 1234") != std::string::npos);
    CHECK(dump.find("\"blocking_timeout_us\": 7000") != std::string::npos);
    return true;
}

bool TestFuzzChannelCountScalesDefaultHighWatermark()
{
    TmpWorkDir tmp;
    CHECK(tmp.ok());

    auto root = MinimalConfig(tmp.path());
    root["channel"]["fuzz_channel_count"] = 3;

    refuzz::orchestrator::OrchestratorConfig cfg;
    CHECK(refuzz::orchestrator::ParseConfigFromJson(root, cfg));

    CHECK_EQ(cfg.fuzz_channel_count, 3U);
    CHECK_EQ(cfg.channel_common.input_queue_capacity, static_cast<std::size_t>(6));

    const std::string dump = refuzz::orchestrator::DumpConfigSummary(cfg);
    CHECK(dump.find("\"fuzz_channel_count\": 3") != std::string::npos);
    return true;
}

bool TestFuzzChannelCountRejectsInvalidValues()
{
    TmpWorkDir tmp;
    CHECK(tmp.ok());

    auto zero = MinimalConfig(tmp.path());
    zero["channel"]["fuzz_channel_count"] = 0;
    refuzz::orchestrator::OrchestratorConfig cfg_zero;
    CHECK(!refuzz::orchestrator::ParseConfigFromJson(zero, cfg_zero));

    auto string_value = MinimalConfig(tmp.path());
    string_value["channel"]["fuzz_channel_count"] = "3";
    refuzz::orchestrator::OrchestratorConfig cfg_string;
    CHECK(!refuzz::orchestrator::ParseConfigFromJson(string_value, cfg_string));
    return true;
}

bool TestLegacyTimeoutFieldsStillParse()
{
    TmpWorkDir tmp;
    CHECK(tmp.ok());

    auto root = MinimalConfig(tmp.path());
    root["channel"]["transport"]["wait_ready_timeout_us"] = 12345678;
    root["executor"] = {
        {"event_blocking_timeout_us", 4321},
    };

    refuzz::orchestrator::OrchestratorConfig cfg;
    CHECK(refuzz::orchestrator::ParseConfigFromJson(root, cfg));

    CHECK_EQ(cfg.channel_common.wait_ready_timeout.count(), 12345);
    CHECK_EQ(cfg.executor.event_blocking_timeout_us, 4321ULL);
    return true;
}

bool TestUnsupportedKeysFail()
{
    TmpWorkDir tmp;
    CHECK(tmp.ok());

    auto root = MinimalConfig(tmp.path());
    root["executor"] = {
        {"submit_strategy",
         {{"name", "round_robin"},
          {"max_retries", 3}}},
    };

    refuzz::orchestrator::OrchestratorConfig cfg;
    CHECK(!refuzz::orchestrator::ParseConfigFromJson(root, cfg));
    return true;
}

bool TestThreadedModePlumbsWorkerCommandAndExecutorDefault()
{
    TmpWorkDir tmp;
    CHECK(tmp.ok());

    auto root = MinimalConfig(tmp.path());
    root["target"]["thread_count"] = 4;
    root["target"]["intra_task_mode"] = "threaded";

    refuzz::orchestrator::OrchestratorConfig cfg;
    CHECK(refuzz::orchestrator::ParseConfigFromJson(root, cfg));
    CHECK_EQ(cfg.target.thread_count, 4U);
    CHECK(cfg.target.intra_task_mode ==
          refuzz::orchestrator::TargetRuntimeConfig::IntraTaskMode::kThreaded);
    CHECK_EQ(cfg.executor.default_intra_threaded, true);
    CHECK(cfg.channel_backend != nullptr);
    const auto* concrete =
        dynamic_cast<const refuzz::channel::factory::QemuIvshmemLinuxProfile*>(
            cfg.channel_backend.get());
    CHECK(concrete != nullptr);
    CHECK(concrete->worker.worker_start_cmd.find(
              "--thread-count 4") != std::string::npos);
    return true;
}

bool TestWorkerPerfPlumbsWorkerCommand()
{
    TmpWorkDir tmp;
    CHECK(tmp.ok());

    auto root = MinimalConfig(tmp.path());
    root["fuzzer"]["worker_perf"] = {
        {"enable", true},
        {"sample_rate", 4},
        {"report_every", 64},
    };

    refuzz::orchestrator::OrchestratorConfig cfg;
    CHECK(refuzz::orchestrator::ParseConfigFromJson(root, cfg));
    CHECK_EQ(cfg.worker_perf_enabled, true);
    CHECK_EQ(cfg.worker_perf_sample_rate, 4U);
    CHECK_EQ(cfg.worker_perf_report_every, 64U);
    CHECK(cfg.channel_backend != nullptr);
    const auto* concrete =
        dynamic_cast<const refuzz::channel::factory::QemuIvshmemLinuxProfile*>(
            cfg.channel_backend.get());
    CHECK(concrete != nullptr);
    const auto& cmd = concrete->worker.worker_start_cmd;
    CHECK(cmd.find("--worker-perf") != std::string::npos);
    CHECK(cmd.find("--worker-perf-sample 4") != std::string::npos);
    CHECK(cmd.find("--worker-perf-report-every 64") != std::string::npos);
    return true;
}

bool TestKcovEntriesPlumbsWorkerCommand()
{
    TmpWorkDir tmp;
    CHECK(tmp.ok());

    auto root = MinimalConfig(tmp.path());
    root["coverage"] = {
        {"kcov",
         {{"entries", 64U << 10},
          {"raw_pc", true},
          {"max_pcs_per_exec", 8192},
          {"sample_rate", 1.0}}},
    };

    refuzz::orchestrator::OrchestratorConfig cfg;
    CHECK(refuzz::orchestrator::ParseConfigFromJson(root, cfg));
    CHECK_EQ(cfg.coverage_kcov_entries, 64U << 10);
    CHECK(cfg.channel_backend != nullptr);
    const auto* concrete =
        dynamic_cast<const refuzz::channel::factory::QemuIvshmemLinuxProfile*>(
            cfg.channel_backend.get());
    CHECK(concrete != nullptr);
    const auto& cmd = concrete->worker.worker_start_cmd;
    CHECK(cmd.find("--kcov-entries 65536") != std::string::npos);
    return true;
}

bool TestKcovEntriesRejectsInvalidValues()
{
    TmpWorkDir tmp;
    CHECK(tmp.ok());

    auto too_small = MinimalConfig(tmp.path());
    too_small["coverage"] = {{"kcov", {{"entries", 512}}}};
    refuzz::orchestrator::OrchestratorConfig cfg_small;
    CHECK(!refuzz::orchestrator::ParseConfigFromJson(too_small, cfg_small));

    auto too_large = MinimalConfig(tmp.path());
    too_large["coverage"] = {{"kcov", {{"entries", (512U << 10) + 1U}}}};
    refuzz::orchestrator::OrchestratorConfig cfg_large;
    CHECK(!refuzz::orchestrator::ParseConfigFromJson(too_large, cfg_large));

    auto string_value = MinimalConfig(tmp.path());
    string_value["coverage"] = {{"kcov", {{"entries", "65536"}}}};
    refuzz::orchestrator::OrchestratorConfig cfg_string;
    CHECK(!refuzz::orchestrator::ParseConfigFromJson(string_value, cfg_string));
    return true;
}

bool TestThreadedModeRejectsThreadCountOne()
{
    TmpWorkDir tmp;
    CHECK(tmp.ok());

    auto root = MinimalConfig(tmp.path());
    root["target"]["thread_count"] = 1;
    root["target"]["intra_task_mode"] = "threaded";

    refuzz::orchestrator::OrchestratorConfig cfg;
    CHECK(!refuzz::orchestrator::ParseConfigFromJson(root, cfg));
    return true;
}

bool TestThreadedModeAllowsCoverageNone()
{
    TmpWorkDir tmp;
    CHECK(tmp.ok());

    auto root = MinimalConfig(tmp.path());
    root["target"]["coverage_mode"] = "none";
    root["target"]["thread_count"] = 2;
    root["target"]["intra_task_mode"] = "threaded";

    refuzz::orchestrator::OrchestratorConfig cfg;
    CHECK(refuzz::orchestrator::ParseConfigFromJson(root, cfg));
    CHECK_EQ(cfg.target.coverage_mode, refuzz::orchestrator::CoverageMode::kNone);
    CHECK_EQ(cfg.target.thread_count, 2U);
    CHECK(cfg.target.intra_task_mode ==
          refuzz::orchestrator::TargetRuntimeConfig::IntraTaskMode::kThreaded);
    CHECK_EQ(cfg.executor.default_intra_threaded, true);
    CHECK(cfg.channel_backend != nullptr);
    const auto* concrete =
        dynamic_cast<const refuzz::channel::factory::QemuIvshmemLinuxProfile*>(
            cfg.channel_backend.get());
    CHECK(concrete != nullptr);
    const auto& cmd = concrete->worker.worker_start_cmd;
    CHECK(cmd.find("--coverage-mode none") != std::string::npos);
    CHECK(cmd.find("--thread-count 2") != std::string::npos);
    return true;
}

bool TestThreadedModeAllowsSyzLikeKcovCollectorCap()
{
    TmpWorkDir tmp;
    CHECK(tmp.ok());

    auto root = MinimalConfig(tmp.path());
    root["target"]["thread_count"] = 16;
    root["target"]["intra_task_mode"] = "threaded";
    root["target"]["kcov_collector_count"] = 8;

    refuzz::orchestrator::OrchestratorConfig cfg;
    CHECK(refuzz::orchestrator::ParseConfigFromJson(root, cfg));
    CHECK_EQ(cfg.target.thread_count, 16U);
    CHECK_EQ(cfg.target.kcov_collector_count, 8U);
    CHECK(cfg.channel_backend != nullptr);
    const auto* concrete =
        dynamic_cast<const refuzz::channel::factory::QemuIvshmemLinuxProfile*>(
            cfg.channel_backend.get());
    CHECK(concrete != nullptr);
    const auto& cmd = concrete->worker.worker_start_cmd;
    CHECK(cmd.find("--thread-count 16") != std::string::npos);
    return true;
}

// [心跳重定义] 阈值链路:heartbeat_timeout_ms → 地板 → miss_threshold。
//
// 判死延迟 = miss_threshold × poll_interval。心跳的 counter 已从"RT 线程自增"换成
// "执行状态机进度令牌",两者静止特性相反:旧心跳在程序执行期间照样 tick,新令牌不动。
// 于是阈值必须覆盖 daemon **一次完整自救**的静止期,否则会把正在正确履职的 daemon 判死:
//     3×exec_timeout(watchdog) + stop 预算(5s) + startup 预算(60s)
// 这条地板是整个判据成立的根据,而它极易被静默破坏(截断、clamp),所以在此锁死。
bool TestHeartbeatTimeoutFloorAndMissThreshold()
{
    // ① 默认值:不写 heartbeat_timeout_ms → 300s。
    //    依据是内核自报窗口:CONFIG_DEFAULT_HUNG_TASK_TIMEOUT=140 → 实际 140-280s 才报得出
    //    hung task(syzkaller targets.go:863-871 由此反推 NoOutput=300s)。判死早于它,就是
    //    抢在内核开口前动手,拿不到带栈的报告。
    {
        TmpWorkDir tmp;
        CHECK(tmp.ok());
        auto root = MinimalConfig(tmp.path());
        root["channel"]["health"]["sample_interval_ms"] = 250;

        refuzz::orchestrator::OrchestratorConfig cfg;
        CHECK(refuzz::orchestrator::ParseConfigFromJson(root, cfg));
        const auto* p = dynamic_cast<const refuzz::channel::factory::QemuIvshmemLinuxProfile*>(
            cfg.channel_backend.get());
        CHECK(p != nullptr);
        // 300000 / 250 = 1200 轮 × 250ms = 300s
        CHECK_EQ(p->health_monitor.heartbeat.miss_threshold, 1200U);
    }

    // ② 地板:旧语义下写的小值(1500)必须被抬到 3×exec(15s)+stop(5s)+startup(60s)=80s。
    //    这些值原本是给"执行期间照样 tick"的心跳定的,在新语义下会把每个正常跑 5s 程序的
    //    worker 判死。
    {
        TmpWorkDir tmp;
        CHECK(tmp.ok());
        auto root = MinimalConfig(tmp.path());
        root["channel"]["health"]["sample_interval_ms"] = 200;
        root["channel"]["health"]["heartbeat_timeout_ms"] = 1500;
        root["fuzzer"]["exec_timeout_ms"] = 5000;

        refuzz::orchestrator::OrchestratorConfig cfg;
        CHECK(refuzz::orchestrator::ParseConfigFromJson(root, cfg));
        const auto* p = dynamic_cast<const refuzz::channel::factory::QemuIvshmemLinuxProfile*>(
            cfg.channel_backend.get());
        CHECK(p != nullptr);
        // 抬到 80000 → 80000/200 = 400 轮 × 200ms = 80s(而非配置字面的 1500ms)
        CHECK_EQ(p->health_monitor.heartbeat.miss_threshold, 400U);
    }

    // ③ 地板随 exec_timeout 缩放,不是写死的常数(slowdown 环境下 exec_timeout 会变大)。
    {
        TmpWorkDir tmp;
        CHECK(tmp.ok());
        auto root = MinimalConfig(tmp.path());
        root["channel"]["health"]["sample_interval_ms"] = 200;
        root["channel"]["health"]["heartbeat_timeout_ms"] = 1500;
        root["fuzzer"]["exec_timeout_ms"] = 15000;  // 3×15000 + 5000 + 60000 = 110000

        refuzz::orchestrator::OrchestratorConfig cfg;
        CHECK(refuzz::orchestrator::ParseConfigFromJson(root, cfg));
        const auto* p = dynamic_cast<const refuzz::channel::factory::QemuIvshmemLinuxProfile*>(
            cfg.channel_backend.get());
        CHECK(p != nullptr);
        CHECK_EQ(p->health_monitor.heartbeat.miss_threshold, 550U);  // 110000/200
    }

    // ④ miss_threshold 必须**向上**取整,否则 sample_interval 大时整数截断会把地板悄悄截漏:
    //    sample=60000 / 地板 80000 → 截断得 1 → 实际只有 60s < 地板 → 误判正在自救的 daemon。
    //    ceil 后得 2 → 120s ≥ 地板。方向永远偏保守(宁可晚判,不可早判)。
    {
        TmpWorkDir tmp;
        CHECK(tmp.ok());
        auto root = MinimalConfig(tmp.path());
        root["channel"]["health"]["sample_interval_ms"] = 60000;
        root["channel"]["health"]["heartbeat_timeout_ms"] = 60000;
        root["fuzzer"]["exec_timeout_ms"] = 5000;

        refuzz::orchestrator::OrchestratorConfig cfg;
        CHECK(refuzz::orchestrator::ParseConfigFromJson(root, cfg));
        const auto* p = dynamic_cast<const refuzz::channel::factory::QemuIvshmemLinuxProfile*>(
            cfg.channel_backend.get());
        CHECK(p != nullptr);
        CHECK_EQ(p->health_monitor.heartbeat.miss_threshold, 2U);
        // 生效判死时长 ≥ 地板 —— 这条才是真正要守的不变量
        CHECK(p->health_monitor.heartbeat.miss_threshold *
                  p->health_monitor.heartbeat.poll_interval.count() >= 80000);
    }

    // ⑤ 显式 heartbeat_miss_threshold 覆盖路径优先级最高(调试/实验用),不受地板管辖。
    {
        TmpWorkDir tmp;
        CHECK(tmp.ok());
        auto root = MinimalConfig(tmp.path());
        root["channel"]["health"]["sample_interval_ms"] = 250;
        root["channel"]["health"]["heartbeat_miss_threshold"] = 7;

        refuzz::orchestrator::OrchestratorConfig cfg;
        CHECK(refuzz::orchestrator::ParseConfigFromJson(root, cfg));
        const auto* p = dynamic_cast<const refuzz::channel::factory::QemuIvshmemLinuxProfile*>(
            cfg.channel_backend.get());
        CHECK(p != nullptr);
        CHECK_EQ(p->health_monitor.heartbeat.miss_threshold, 7U);
    }

    return true;
}

bool TestTopologyProbePlumbsWorkerCommand()
{
    TmpWorkDir tmp;
    CHECK(tmp.ok());

    auto root = MinimalConfig(tmp.path());
    root["target"]["debug_topology_probe"] = true;

    refuzz::orchestrator::OrchestratorConfig cfg;
    CHECK(refuzz::orchestrator::ParseConfigFromJson(root, cfg));
    CHECK_EQ(cfg.target.debug_topology_probe, true);
    CHECK(cfg.channel_backend != nullptr);
    const auto* concrete =
        dynamic_cast<const refuzz::channel::factory::QemuIvshmemLinuxProfile*>(
            cfg.channel_backend.get());
    CHECK(concrete != nullptr);
    const auto& cmd = concrete->worker.worker_start_cmd;
    CHECK(cmd.find("--debug-topology-probe") != std::string::npos);
    return true;
}

bool TestThreadCountRejectsWrongTypes()
{
    TmpWorkDir tmp;
    CHECK(tmp.ok());

    auto negative = MinimalConfig(tmp.path());
    negative["target"]["thread_count"] = -1;
    refuzz::orchestrator::OrchestratorConfig cfg_negative;
    CHECK(!refuzz::orchestrator::ParseConfigFromJson(negative, cfg_negative));

    auto string_value = MinimalConfig(tmp.path());
    string_value["target"]["thread_count"] = "4";
    refuzz::orchestrator::OrchestratorConfig cfg_string;
    CHECK(!refuzz::orchestrator::ParseConfigFromJson(string_value, cfg_string));
    return true;
}

bool TestIntraTaskModeRejectsWrongType()
{
    TmpWorkDir tmp;
    CHECK(tmp.ok());

    auto root = MinimalConfig(tmp.path());
    root["target"]["intra_task_mode"] = true;

    refuzz::orchestrator::OrchestratorConfig cfg;
    CHECK(!refuzz::orchestrator::ParseConfigFromJson(root, cfg));
    return true;
}

bool TestXiuosConfigParsesBackendProfile()
{
    TmpWorkDir tmp;
    CHECK(tmp.ok());

    const std::string corpus_dir = tmp.path() + "/wire_corpus";
    auto root = nlohmann::json{
        {"profile", "xiuos"},
        {"work_dir", tmp.path()},
        {"retention", false},
        {"channel",
         {{"backend_id", "qemu_uart_xiuos"},
          {"n_workers", 7},
          {"wait_ready_timeout_ms", 12345},
          {"loop_interval_ms", 67},
          {"xiuos",
           {{"qemu_bin", "qemu-system-riscv32"},
            {"elf_path", "/tmp/xiuos.elf"},
            {"serial_host", "127.0.0.1"},
            {"serial_port", 33001},
            {"connect_timeout_ms", 111},
            {"frame_timeout_ms", 222},
            {"heartbeat_timeout_ms", 333},
            {"poll_slice_ms", 4},
            {"program_timeout_ms", 5555},
            {"shutdown_grace_ms", 666}}}}},
        {"executor",
         {{"submit_strategy", {{"name", "round_robin"}}},
          {"event_forward_strategy", {{"blocking_timeout_ms", 1}}},
          {"timeouts_ms", {{"poll", 2}, {"pop", 3}}}}},
        {"fuzzer",
         {{"high_watermark", 9},
          {"exec_timeout_ms", 4444},
          {"corpus", {{"capacity", 100}, {"max_drain", 5}}}}},
        {"target",
         {{"execution_mode", "kernel_syscall"},
          {"coverage_mode", "kcov"},
          {"sanitizer_mode", "none"},
          {"sandbox_mode", "none"}}},
        {"coverage", {{"kcov", {{"raw_pc", true}}}}},
        {"persistence",
         {{"corpus",
           {{"enable", true}, {"load_on_start", true}, {"dir", corpus_dir}}},
          {"coverage", {{"enable", false}, {"load_on_start", false}}},
          {"crash_repros_as_seeds", false}}},
        {"phase1_run_limit_mode", "runtime"},
        {"phase1_runtime_seconds", 12},
        {"phase1_total_tasks", 34},
    };

    refuzz::orchestrator::OrchestratorConfig cfg;
    CHECK(refuzz::orchestrator::ParseConfigFromJson(root, cfg));
    CHECK_EQ(cfg.profile, std::string{"xiuos"});
    CHECK_EQ(cfg.channel_backend_id, std::string{"qemu_uart_xiuos"});
    CHECK_EQ(cfg.channel_common.n_workers, 1U);
    CHECK_EQ(cfg.channel_common.wait_ready_timeout.count(), 12345);
    CHECK_EQ(cfg.channel_common.loop_interval.count(), 67);
    CHECK_EQ(cfg.fuzzer.exec_timeout_ms, 4444U);
    CHECK_EQ(cfg.corpus_persist_dir, corpus_dir);
    CHECK_EQ(cfg.run_limit_mode, refuzz::orchestrator::RunLimitMode::kRuntime);
    CHECK_EQ(cfg.runtime.count(), 12);
    CHECK_EQ(cfg.total_tasks, 34ULL);

    CHECK(cfg.channel_backend != nullptr);
    const auto* concrete =
        dynamic_cast<const refuzz::channel::factory::XiuosUartProfile*>(
            cfg.channel_backend.get());
    CHECK(concrete != nullptr);
    CHECK_EQ(concrete->qemu_bin, std::string{"qemu-system-riscv32"});
    CHECK_EQ(concrete->elf_path, std::string{"/tmp/xiuos.elf"});
    CHECK_EQ(concrete->serial_host, std::string{"127.0.0.1"});
    CHECK_EQ(concrete->serial_port, static_cast<std::uint16_t>(33001));
    CHECK_EQ(concrete->connect_timeout.count(), 111);
    CHECK_EQ(concrete->frame_timeout.count(), 222);
    CHECK_EQ(concrete->heartbeat_timeout.count(), 333);
    CHECK_EQ(concrete->poll_slice.count(), 4);
    CHECK_EQ(concrete->program_timeout.count(), 5555);
    CHECK_EQ(concrete->shutdown_grace.count(), 666);
    return true;
}

// [SyzVegas baseline] mab tuning knobs must be BOTH whitelisted (CheckKnownConfigKeys)
// and parsed. Baseline knobs = mab_task_enabled + mab_time_cap_s (the patch knobs
// mab_lineage_*/explore_floor/optimistic_init/scale_quantile/rate_window were removed).
// Use exactly-representable doubles so CHECK_EQ is bit-exact.
bool TestMabKnobsAcceptedAndParsed()
{
    TmpWorkDir tmp;
    CHECK(tmp.ok());

    auto root = MinimalConfig(tmp.path());
    root["fuzzer"]["scheduling_policy"] = "mab_exp3ix";
    root["fuzzer"]["mab_time_cap_s"]    = 0.5;

    refuzz::orchestrator::OrchestratorConfig cfg;
    CHECK(refuzz::orchestrator::ParseConfigFromJson(root, cfg));  // not rejected by whitelist

    CHECK_EQ(cfg.fuzzer.scheduling_policy, std::string{"mab_exp3ix"});
    CHECK_EQ(cfg.fuzzer.mab_time_cap_s, 0.5);
    return true;
}

// [request-stream capture] The key has to survive the strict unknown-key
// whitelist AND reach FuzzerLoopConfig, in every parser branch. It is spelled in
// three places (whitelist + three parse sites), which is exactly the shape of
// mistake a test catches and a config file does not: a missing whitelist entry
// rejects the run at startup, a missing parse site accepts it and then captures
// nothing, wasting a whole fuzz run before anyone notices the empty file.
bool TestRequestStreamCapturePathParses()
{
    TmpWorkDir tmp;
    CHECK(tmp.ok());

    auto root = MinimalConfig(tmp.path());
    root["fuzzer"]["request_stream_capture_path"] = "/tmp/dispatched.jsonl";

    refuzz::orchestrator::OrchestratorConfig cfg;
    CHECK(refuzz::orchestrator::ParseConfigFromJson(root, cfg));

    CHECK_EQ(cfg.fuzzer.request_stream_capture_path, std::string{"/tmp/dispatched.jsonl"});
    return true;
}

// Absent key means capture off, not an empty file created on every production run.
bool TestRequestStreamCaptureDefaultsOff()
{
    TmpWorkDir tmp;
    CHECK(tmp.ok());

    auto root = MinimalConfig(tmp.path());
    refuzz::orchestrator::OrchestratorConfig cfg;
    CHECK(refuzz::orchestrator::ParseConfigFromJson(root, cfg));

    CHECK(cfg.fuzzer.request_stream_capture_path.empty());
    return true;
}

} // namespace

int main()
{
    std::fprintf(stdout, "Running config_parser_test...\n");
    int failed = 0;
    RUN_TEST(TestDefaultsUseChannelConfigValues, failed);
    RUN_TEST(TestExplicitChannelAndExecutorValues, failed);
    RUN_TEST(TestFuzzChannelCountScalesDefaultHighWatermark, failed);
    RUN_TEST(TestFuzzChannelCountRejectsInvalidValues, failed);
    RUN_TEST(TestLegacyTimeoutFieldsStillParse, failed);
    RUN_TEST(TestUnsupportedKeysFail, failed);
    RUN_TEST(TestThreadedModePlumbsWorkerCommandAndExecutorDefault, failed);
    RUN_TEST(TestWorkerPerfPlumbsWorkerCommand, failed);
    RUN_TEST(TestKcovEntriesPlumbsWorkerCommand, failed);
    RUN_TEST(TestKcovEntriesRejectsInvalidValues, failed);
    RUN_TEST(TestThreadedModeRejectsThreadCountOne, failed);
    RUN_TEST(TestThreadedModeAllowsCoverageNone, failed);
    RUN_TEST(TestThreadedModeAllowsSyzLikeKcovCollectorCap, failed);
    RUN_TEST(TestTopologyProbePlumbsWorkerCommand, failed);
    RUN_TEST(TestThreadCountRejectsWrongTypes, failed);
    RUN_TEST(TestIntraTaskModeRejectsWrongType, failed);
    RUN_TEST(TestHeartbeatTimeoutFloorAndMissThreshold, failed);
    RUN_TEST(TestXiuosConfigParsesBackendProfile, failed);
    RUN_TEST(TestMabKnobsAcceptedAndParsed, failed);
    RUN_TEST(TestRequestStreamCapturePathParses, failed);
    RUN_TEST(TestRequestStreamCaptureDefaultsOff, failed);

    std::fprintf(stdout, "%d/%d tests passed\n", tests_passed, tests_run);
    return failed == 0 ? 0 : 1;
}

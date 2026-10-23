#pragma once

#include <cstdint>
#include <filesystem>
#include <string>

namespace refuzz::telemetry {

class RunStateStore;

struct RunSummaryJsonSinkConfig {
    std::filesystem::path logs_dir;  // 通常 = SessionLayout::logs_dir
    std::string filename = "run_summary.json";
};

enum class JsonWriteStatus : uint8_t {
    kOk,              // 写成功且 invariants.status ∈ {kOk, kDisabled}
    kInvariantFailed, // 写成功但 invariants.status == kViolated
    kIoError,         // rename / 写 tmp 失败
    kSkipped,         // store.LatestRunSummary() == nullopt 或 invariants.status == kSkipped
};

// Final json 写盘器。无线程、无 mutex、无 Registry。
// 只接 RunStateStore const ref,在调用线程渲染 LatestRunSummary() 为 json 并原子 rename。
// 预期调用时机:orchestrator Stop() 里,projector.Stop() 之后(此时 store 内是
// is_final=true 的 summary)、service_registry.Stop() 之前。
class RunSummaryJsonSink {
public:
    RunSummaryJsonSink(RunSummaryJsonSinkConfig cfg, const RunStateStore& store);

    JsonWriteStatus WriteFinal();

    // 便于测试:只渲染 json 字符串,不落盘。
    std::string RenderJson() const;

private:
    RunSummaryJsonSinkConfig cfg_;
    const RunStateStore& store_;
};

const char* JsonWriteStatusName(JsonWriteStatus s);

} // namespace refuzz::telemetry

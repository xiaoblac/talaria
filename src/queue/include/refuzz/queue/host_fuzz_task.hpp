// HostFuzzTask — host-side task carrier between control/stage push
// sites and the executor's submit boundary.
//
// 角色：retypes `InMemoryTaskQueue` 的 carrier（D7），让 host 管道携带
// typed `ProgramArtifact`，同时把 wire-shape `proto::Task` 留为 executor
// 边界内部细节，仅在 channel-dispatch 处构造。
//
// Bytes 与 typed 双轨：
//   - `artifact`：v2 typed authority，syz_v2 路径填，typed 消费者直接读
//   - `payload`：v1 profile fallback（如 `kernel_full`），bytes-only 路径
//     用；通过 `IMutatorEngine::Mutate(seed)` 产生。两条字段并存到 v1
//     cutover 之后再删。channel + worker 边界永远是 bytes-only（D2/D8
//     contract）—— `Executor::Submit` 是唯一 exec-wire 物化点。

#pragma once

#include "refuzz/program/artifact.hpp"
#include "refuzz/proto_domain/types.hpp"

#include <cstdint>
#include <vector>

namespace refuzz::queue {

struct HostFuzzTask {
    // v2 typed authority — syz_v2 路径填，typed 消费者直接读。
    ::refuzz::program::ProgramArtifact artifact;

    // v1 profile fallback — bytes-only 路径填（IMutatorEngine::Mutate
    // 产出）；channel/worker 边界 D2/D8 永远 bytes-only。两字段并存到
    // v1 cutover 之后再删。
    std::vector<std::uint8_t> payload;

    ::refuzz::proto::ExecOpts  opts;
    ::refuzz::proto::TaskTrace trace;

    uint64_t executor_id    = 0;
    uint64_t seed_id        = 0;
    uint64_t origin_seed_id = 0;
    bool     important      = false;
};

} // namespace refuzz::queue

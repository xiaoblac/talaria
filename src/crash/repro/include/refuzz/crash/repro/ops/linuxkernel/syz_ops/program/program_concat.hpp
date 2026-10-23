#pragma once

// 程序拼接工具 — 用于 repro 的 bisect/concat 策略。

#include <cstdint>
#include <memory>
#include <vector>

namespace refuzz::program { class ProgramArtifact; }
namespace refuzz::program::syz { class Prog; }

namespace refuzz::crash {

// Byte-level stubs (legacy V1; the V2 exec-wire varint stream cannot be naively
// byte-concatenated — these return empty/0). Superseded by ConcatTypedPrograms.
std::vector<uint8_t> ConcatPrograms(const std::vector<std::vector<uint8_t>>& payloads);
std::vector<uint8_t> TruncateProgram(const std::vector<uint8_t>& payload, uint32_t count);
uint32_t CountCalls(const std::vector<uint8_t>& payload);

// [async-crash-reproduction Phase 1.5] V2-IR typed concat — the "separate item"
// the byte-level stub deferred. Merges the given typed programs (DeepClone each,
// append calls) into one Prog and lowers it: `payload` (exec-wire, for execution)
// + `artifact` (typed view, for StageMinimize / C-repro) + `call_count`. Returns
// false if `progs` is empty / any input is null / serialize_for_exec fails. Each
// program's resources are self-contained, so concatenation preserves ResultArg
// references; serialize_for_exec re-assigns copyout indices globally.
// See docs/plans/async-crash-reproduction.md.
struct ConcatTypedResult {
    std::vector<uint8_t>                                       payload;
    std::shared_ptr<const ::refuzz::program::ProgramArtifact>  artifact;
    uint32_t                                                   call_count = 0;
};

bool ConcatTypedPrograms(
    const std::vector<std::shared_ptr<const ::refuzz::program::syz::Prog>>& progs,
    ConcatTypedResult& out);

} // namespace refuzz::crash


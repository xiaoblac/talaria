// program_concat — repro pipeline's bisect/concat extraction helper.
//
// Historical V1 implementation operated on `SyscallProgHeader` flat wire
// or `SyzProgCodec`-encoded typed wire. After V1 IR retirement (L5/L6)
// both formats are gone; the V2 exec wire is a self-describing varint
// stream that cannot be naively concatenated without re-running
// `serialize_for_exec` over a merged typed Prog. Re-implementing
// concat/truncate on the V2 IR is a separate item.
//
// For now these helpers return empty / 0 — the bisect/concat fast
// paths in `ReproManager::StageExtract` simply skip when the result is
// empty, falling through to the typed minimize path which is the
// primary reproduction route after §3.10/§3.11.

#include "refuzz/crash/repro/ops/linuxkernel/syz_ops/program/program_concat.hpp"

#include "refuzz/program/artifact.hpp"
#include "refuzz/program/syz/artifact_materializer.hpp"
#include "refuzz/program/syz/clone.hpp"
#include "refuzz/program/syz/exec_wire.hpp"
#include "refuzz/program/syz/prog.hpp"

#include <memory>
#include <utility>

namespace refuzz::crash {

std::vector<uint8_t> ConcatPrograms(const std::vector<std::vector<uint8_t>>& /*payloads*/)
{
    return {};
}

std::vector<uint8_t> TruncateProgram(const std::vector<uint8_t>& /*payload*/, uint32_t /*count*/)
{
    return {};
}

uint32_t CountCalls(const std::vector<uint8_t>& /*payload*/)
{
    return 0;
}

// [async-crash-reproduction Phase 1.5] typed V2-IR concat — see header.
bool ConcatTypedPrograms(
    const std::vector<std::shared_ptr<const ::refuzz::program::syz::Prog>>& progs,
    ConcatTypedResult& out)
{
    namespace syzv2 = ::refuzz::program::syz;
    if (progs.empty()) return false;

    std::unique_ptr<syzv2::Prog> merged;
    for (const auto& p : progs) {
        if (!p) return false;
        auto cloned = syzv2::DeepClone(*p);  // deep copy, ResultArg refs remapped
        if (!cloned) return false;
        if (!merged) {
            merged = std::move(cloned);
        } else {
            // Append this program's cloned calls after the merged list. Each
            // program's resources are self-contained, so the ResultArg pointers
            // stay valid; serialize_for_exec re-assigns copyout indices globally.
            for (auto& call : cloned->mutable_calls()) {
                merged->mutable_calls().push_back(std::move(call));
            }
        }
    }
    if (!merged || merged->calls().empty()) return false;

    auto payload_or = syzv2::serialize_for_exec(*merged);
    if (!payload_or.has_value() || payload_or->empty()) return false;
    out.payload     = std::move(*payload_or);
    out.call_count  = static_cast<uint32_t>(merged->calls().size());

    std::shared_ptr<const syzv2::Prog> merged_sp(merged.release());
    auto art = syzv2::MakeArtifactFromTypedProg(merged_sp);
    if (art.valid()) {
        out.artifact =
            std::make_shared<const ::refuzz::program::ProgramArtifact>(std::move(art));
    }
    return true;
}

} // namespace refuzz::crash

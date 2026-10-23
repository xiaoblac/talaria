// §3.10 follow-up — format-neutral dispatch for ProgramArtifact
// materialization. Replaces the original syz_v2-hardcoded
// `MakeArtifactFromCanonicalPayload` / `MaterializeExecWire` bodies
// with registry-driven dispatch. Adapters are owned by their format's
// source tree and registered via `RegisterBuiltinArtifactMaterializers`.

#include "refuzz/program/artifact_materializer.hpp"

#include "refuzz/program/raw_bytes_artifact.hpp"           // post-V1-retirement B-6 — CreateRawBytesMaterializer
#include "refuzz/program/syz/artifact_materializer.hpp"   // CreateSyzV2Materializer

#include <memory>
#include <mutex>
#include <utility>

namespace refuzz::program {

// ----- ArtifactMaterializerRegistry -----

ArtifactMaterializerRegistry& ArtifactMaterializerRegistry::Instance() {
    static ArtifactMaterializerRegistry inst;
    return inst;
}

void ArtifactMaterializerRegistry::Register(std::unique_ptr<IArtifactMaterializer> adapter) {
    if (adapter == nullptr) return;
    const auto fmt = adapter->format();
    by_format_[static_cast<int>(fmt)] = std::move(adapter);
}

IArtifactMaterializer*
ArtifactMaterializerRegistry::Find(refuzz::fuzzer::ProgFormat format) const {
    auto it = by_format_.find(static_cast<int>(format));
    return it == by_format_.end() ? nullptr : it->second.get();
}

void ArtifactMaterializerRegistry::ResetForTest() {
    by_format_.clear();
}

// ----- Builtin registration -----
//
// Idempotent: under a process-wide call_once we register every adapter
// linked into this binary. Tests that need a clean slate call
// `Instance().ResetForTest()` first.

namespace {
std::once_flag g_register_once;
} // namespace

void RegisterBuiltinArtifactMaterializers() {
    std::call_once(g_register_once, []() {
        auto& reg = ArtifactMaterializerRegistry::Instance();
        // syz_v2 (kSyzProg). Future: libafl bridge, additional arches under syz, etc.
        reg.Register(syz::CreateSyzV2Materializer());
        // post-V1-retirement B-6: raw-bytes target (kAflRaw).
        //   target-agnostic adapter, identity LowerToExecWire；让 non-typed
        //   targets（AFL / userspace fuzz / RPC / VM-snapshot delta）能挂
        //   ProgramArtifact，跨模块 contract 不再 syz-only。
        reg.Register(CreateRawBytesMaterializer());
    });
}

// ----- Top-level dispatch -----

std::expected<ProgramArtifact, MaterializeError>
MakeArtifactFromCanonicalPayload(refuzz::fuzzer::ProgFormat format,
                                 ProgramTargetKey           target,
                                 std::vector<std::uint8_t>  canonical_bytes)
{
    auto* mat = ArtifactMaterializerRegistry::Instance().Find(format);
    if (mat == nullptr) {
        return std::unexpected(MaterializeError{
            "MakeArtifactFromCanonicalPayload: no materializer registered "
            "for format=" + std::to_string(static_cast<int>(format))
            + " (call RegisterBuiltinArtifactMaterializers at init)"});
    }
    return mat->BuildFromCanonicalPayload(std::move(target),
                                          std::move(canonical_bytes));
}

std::expected<std::shared_ptr<const std::vector<std::uint8_t>>, MaterializeError>
MaterializeCanonicalText(const ProgramArtifact& artifact)
{
    if (!artifact.valid()) {
        return std::unexpected(MaterializeError{
            "MaterializeCanonicalText: invalid artifact"});
    }
    auto bytes = artifact.canonical_payload();
    if (bytes == nullptr) {
        return std::unexpected(MaterializeError{
            "MaterializeCanonicalText: canonical_payload unavailable "
            "(no preload, no provider)"});
    }
    return bytes;
}

std::expected<std::vector<std::uint8_t>, MaterializeError>
MaterializeExecWire(const ProgramArtifact& artifact)
{
    if (!artifact.valid()) {
        return std::unexpected(MaterializeError{
            "MaterializeExecWire: invalid artifact"});
    }
    auto* mat = ArtifactMaterializerRegistry::Instance().Find(artifact.format());
    if (mat == nullptr) {
        return std::unexpected(MaterializeError{
            "MaterializeExecWire: no materializer registered for "
            "artifact.format()=" + std::to_string(static_cast<int>(artifact.format()))});
    }
    return mat->LowerToExecWire(artifact);
}

// ----- Convenience: corpus-side callback factory -----

ArtifactMaterializerFn MakeRegistryMaterializer(refuzz::fuzzer::ProgFormat format,
                                                ProgramTargetKey           target)
{
    return [format, target = std::move(target)]
           (const std::vector<std::uint8_t>& bytes)
               -> std::shared_ptr<const ProgramArtifact>
    {
        // post-V1-retirement: 不在 dispatcher 层吃 empty fast-path —— 空 input
        // 对 raw / AFL target 是合法 program（zero-length seed），shortcut 会
        // 让空 raw seed 拿不到 artifact，违反"every Seed has an artifact"。
        // empty 合法性交给 adapter 自己（syz_v2 内部还是会拒绝空 .syz；
        // RawBytesMaterializer 接受）。
        // Copy bytes into the call so per-payload BuildFrom takes
        // ownership; the input vector is shared with seed.payload and
        // must stay intact.
        std::vector<std::uint8_t> bytes_copy = bytes;
        auto art_or = MakeArtifactFromCanonicalPayload(format, target,
                                                       std::move(bytes_copy));
        if (!art_or.has_value()) return nullptr;
        return std::make_shared<const ProgramArtifact>(std::move(*art_or));
    };
}

} // namespace refuzz::program

// RawBytesArtifact 实现 — post-V1-retirement B-6.
// 详见 refuzz/program/raw_bytes_artifact.hpp 头注释。

#include "refuzz/program/raw_bytes_artifact.hpp"

#include "refuzz/program/prog_format.hpp"

#include <cstdint>
#include <memory>
#include <typeinfo>
#include <utility>
#include <vector>

namespace refuzz::program {

ProgramArtifact MakeRawBytesArtifact(ProgramTargetKey          target,
                                     std::vector<std::uint8_t> bytes)
{
    // typed_view = RawBytesProgram{bytes}, canonical_payload = bytes (preloaded).
    auto typed = std::make_shared<RawBytesProgram>();
    typed->bytes = bytes;  // 复制：canonical_payload 与 typed.bytes 都需要持有
    auto canonical = std::make_shared<std::vector<std::uint8_t>>(std::move(bytes));
    return ProgramArtifact::Build(
        refuzz::fuzzer::ProgFormat::kAflRaw,
        std::move(target),
        std::move(typed),
        typeid(RawBytesProgram),
        std::move(canonical),
        /*canonical_provider=*/{});
}

namespace {

class RawBytesMaterializer final : public IArtifactMaterializer {
public:
    refuzz::fuzzer::ProgFormat format() const override {
        return refuzz::fuzzer::ProgFormat::kAflRaw;
    }

    std::expected<ProgramArtifact, MaterializeError>
    BuildFromCanonicalPayload(ProgramTargetKey          target,
                              std::vector<std::uint8_t> canonical_bytes) override
    {
        // 空 input 在 raw / AFL target 是合法 program（zero-length seed），
        // 按"every Seed has an artifact"的不变式必须返回有效 artifact，不
        // fallback 到 nullptr —— 否则空种子会绕过整个 V2 hot path。
        return MakeRawBytesArtifact(std::move(target), std::move(canonical_bytes));
    }

    std::expected<std::vector<std::uint8_t>, MaterializeError>
    LowerToExecWire(const ProgramArtifact& artifact) override
    {
        if (!artifact.valid()) {
            return std::unexpected(MaterializeError{
                "RawBytesMaterializer::LowerToExecWire: invalid artifact"});
        }
        // raw-bytes 的 exec-wire 就是 bytes 本身（identity）。
        // 优先走 typed view；canonical_payload 作为 fallback。
        if (auto typed = artifact.As<RawBytesProgram>(); typed != nullptr) {
            return typed->bytes;
        }
        auto canonical = artifact.canonical_payload();
        if (canonical == nullptr) {
            return std::unexpected(MaterializeError{
                "RawBytesMaterializer::LowerToExecWire: no typed view and "
                "no canonical_payload"});
        }
        return *canonical;
    }
};

} // namespace

std::unique_ptr<IArtifactMaterializer> CreateRawBytesMaterializer()
{
    return std::make_unique<RawBytesMaterializer>();
}

} // namespace refuzz::program

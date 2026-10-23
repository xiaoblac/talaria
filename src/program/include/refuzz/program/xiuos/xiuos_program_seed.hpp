// Copyright 2026 reFuzz project author -------youngkk.
//
// XiuosProgramSeed — host-side representation of a XiUOS seed program.
//
// Phase 2 §B residual #15: bridge between the descriptor-driven JSON corpus
// (generated cache `run/xiuos/corpus/generated/`; hand-authored source seeds
// `tools/xiuos_refuzz/corpus/seed/`) and the C++ program-level encoder
// (`XiuosEncodeProgram`).
//
// Lives under `program/` because it owns *in-memory program representation*
// and the JSON parser that constructs it — the same way other program kinds
// (RawBytesArtifact, syz::Prog) live in this component. The channel layer
// consumes the encoded bytes via `XiuosProgramSeed::Encode()` and is below
// in the dep graph (refuzz_channel links refuzz_program, not the reverse).

#pragma once

#include "refuzz/program/xiuos/xiuos_program.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace refuzz::program::xiuos {

// Lightweight result type local to this module. Errors carry a kind tag +
// message for diagnostic logging; callers that need richer error handling
// can map this onto their own Result<T>.
enum class XiuosSeedErrorKind : std::uint8_t {
    kConfig,
    kIo,
    kParse,
};

struct XiuosSeedError {
    XiuosSeedErrorKind kind = XiuosSeedErrorKind::kConfig;
    std::string        message;
};

template <typename T>
class XiuosSeedResult {
public:
    static XiuosSeedResult Ok(T value) {
        XiuosSeedResult r;
        r.value_ = std::move(value);
        return r;
    }
    XiuosSeedResult(XiuosSeedError err) : error_(std::move(err)) {}

    bool ok() const noexcept { return !error_.has_value(); }
    T&       value()       { return *value_; }
    const T& value() const { return *value_; }
    const XiuosSeedError& error() const { return *error_; }

private:
    XiuosSeedResult() = default;
    std::optional<T>              value_;
    std::optional<XiuosSeedError> error_;
};

struct XiuosProgramSeed {
    std::string                    name;
    XiuosSuiteId                   suite_id{XiuosSuiteId::CommonKernel};
    std::vector<XiuosProgramCall>  calls;

    // Metadata copied from the JSON when present; otherwise defaulted.
    std::optional<std::string>     source_rule;
    std::optional<std::uint16_t>   expected_min_calls;

    // Encode as XiUOS PROGRAM payload (the bytes that go straight into
    // `ChannelDispatchRequest.payload`). Mirrors XiuosEncodeProgram exactly.
    std::vector<std::uint8_t> Encode() const;
};

// Parse a single seed JSON file. Schema must include at minimum:
//
//   {
//     "name": "...",
//     "suite": "COMMON_KERNEL",
//     "calls": [
//       {"api": "SEM_CREATE", "args": [0, 1]},
//       {"api": "SEM_DELETE", "args": [0]}
//     ]
//   }
//
// Optional fields: `source_rule`, `expected_min_calls`, `source`,
// `purpose`, `expected_status` (last three are ignored by this loader;
// they're orchestrator-level metadata).
XiuosSeedResult<XiuosProgramSeed>
LoadXiuosProgramSeed(const std::filesystem::path& path);

XiuosSeedResult<XiuosProgramSeed>
ParseXiuosProgramSeedJson(std::string_view text,
                          std::string_view source_name = "<memory>");

// Walk a `corpus/generated/...` tree (recursive); yield seed JSON file
// paths sorted lexicographically. `manifest.json` and any non-.json files
// are skipped. Bootstrap seed dirs (`corpus/seed/`) work too — they just
// don't have subdirectories.
std::vector<std::filesystem::path>
DiscoverXiuosProgramSeedFiles(const std::filesystem::path& root);

}  // namespace refuzz::program::xiuos

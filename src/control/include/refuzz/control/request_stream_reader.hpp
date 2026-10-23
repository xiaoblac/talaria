#pragma once

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace refuzz::request_stream {

// Request-stream v2 is deliberately independent from the flatrpc wire format.
// It carries only the inputs needed to submit the same programs to another
// execution system; it is not a communication or result trace.
//
// v2 carries `prog_text` -- the canonical syzlang program text (Syzkaller's
// Prog.Serialize()) -- where v1 carried SerializeForExec() bytes. The exec form
// is lowered and one-way: its flattened copyin/copyout stream keeps no type
// structure, so a consumer can only ever hold bytes and has to bypass its own
// normal request path. Text round-trips (TextDecoder mirrors Syzkaller's
// Deserialize grammar), so reFuzz rebuilds a typed syz::Prog + ProgramArtifact
// and lowers it with its own encoder -- i.e. replay runs the SAME code path as
// fuzzing, which is the whole point of a fixed-workload comparison.
inline constexpr std::string_view kMagic = "RFZREQS2";
inline constexpr std::string_view kFooterMagic = "RFZEND01";
inline constexpr uint32_t kVersion = 2;
inline constexpr uint32_t kHeaderSize = 32;
inline constexpr uint32_t kFooterSize = 36; // marker + 32-byte footer body
inline constexpr uint32_t kRecordFixedSize = 60;
inline constexpr uint32_t kFooterMarker = 0xffffffffU;
inline constexpr uint8_t kRecordKindProgram = 1;
inline constexpr uint64_t kRequestTypeProgram = 0;
inline constexpr uint32_t kMaxRecordSize = 64U * 1024U * 1024U;
inline constexpr uint32_t kMaxProgTextSize = 16U * 1024U * 1024U;
inline constexpr uint32_t kMaxAllSignalCount = 1U * 1024U * 1024U;

struct RequestRecord {
    uint64_t sequence = 0;
    uint64_t request_type = kRequestTypeProgram;
    uint64_t exec_env_flags = 0;
    uint64_t exec_flags = 0;
    int64_t sandbox_arg = 0;
    uint64_t request_flags = 0;
    std::vector<int32_t> all_signal;
    // Canonical syzlang text; see the v2 note above.
    std::vector<uint8_t> prog_text;
};

struct RequestStream {
    std::vector<RequestRecord> records;
};

using ParseResult = std::expected<RequestStream, std::string>;

ParseResult Read(std::span<const uint8_t> bytes);
ParseResult ReadFile(std::string_view path);

} // namespace refuzz::request_stream

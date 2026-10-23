// reFuzz syzkaller-equivalent IR — text codec (.syz)
//
// Decoder mirrors syzkaller pkg/prog encoding.go Deserialize() grammar
// recursively, dispatching on Type kind. Encoder mirrors Serialize().
//
// Together they form a parity oracle: round-tripping a .syz program
// through reFuzz v2 should match syzkaller Go-side Deserialize→Serialize
// byte-for-byte (for the supported subset).

#pragma once

#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

#include <expected>
#include <memory>
#include <string>
#include <string_view>

namespace refuzz::program::syz {

// Failure detail returned on parse error.
struct DecodeError {
    int         line    = 0;   // 1-based; 0 if unknown
    int         column  = 0;   // 0-based offset within line; 0 if unknown
    std::string message;
};

// Mirror of prog.DeserializeMode (Strict vs NonStrict). reFuzz only
// supports the two basic modes for now; Unsafe variants are deferred.
enum class DecodeMode : uint8_t {
    kStrict    = 0,
    kNonStrict = 1,
};

class TextDecoder {
public:
    explicit TextDecoder(const Target& target, DecodeMode mode = DecodeMode::kNonStrict);
    ~TextDecoder();

    TextDecoder(const TextDecoder&)            = delete;
    TextDecoder& operator=(const TextDecoder&) = delete;

    std::expected<std::unique_ptr<Prog>, DecodeError> decode(std::string_view text);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

class TextEncoder {
public:
    explicit TextEncoder(const Target& target);
    ~TextEncoder();

    TextEncoder(const TextEncoder&)            = delete;
    TextEncoder& operator=(const TextEncoder&) = delete;

    std::string encode(const Prog& prog);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace refuzz::program::syz
